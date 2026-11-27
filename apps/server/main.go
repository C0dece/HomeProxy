package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS
var bundledAdmin fs.FS

const apiVersion = 1
const schemaVersion = 5

var releaseVersion = "0.1.2"

type settings struct {
	ManageAutomaticUpdates bool         `json:"manageAutomaticUpdates"`
	DestinationDNS         *dnsResolver `json:"destinationDns"`

	Listen         string  `json:"listen"`
	PublicListen   string  `json:"publicListen"`
	LocalAdmin     string  `json:"localAdminListen"`
	PublicURL      string  `json:"publicUrl"`
	Database       string  `json:"database"`
	KeyFile        string  `json:"keyFile"`
	CertFile       string  `json:"certFile"`
	TLSKeyFile     string  `json:"tlsKeyFile"`
	AdminDir       *string `json:"adminDir"`
	AdminTokenFile string  `json:"adminTokenFile"`
	SingBox        string  `json:"singBox"`
	TunnelListen   string  `json:"tunnelListen"`
	TunnelHost     string  `json:"tunnelHost"`
	TunnelPort     int     `json:"tunnelPort"`
	RealityKeyFile string  `json:"realityKeyFile"`
	HandshakeHost  string  `json:"handshakeHost"`
	HandshakePort  int     `json:"handshakePort"`
	ServerName     string  `json:"serverName"`
	ProbeURL       string  `json:"probeUrl"`
	LoopbackDev    bool    `json:"loopbackDev"`
}

type dnsResolver struct {
	Address    string `json:"address"`
	ServerName string `json:"serverName"`
}

type server struct {
	cfg       settings
	db        *sql.DB
	secrets   cipher.AEAD
	adminHash [32]byte
	key       *ecdh.PrivateKey
	shortID   string
	core      engine
	write     sync.Mutex
}

func randomToken() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

func randomBytes(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func uuid() string {
	data := randomBytes(16)
	data[6] = (data[6] & 15) | 64
	data[8] = (data[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[:4], data[4:6], data[6:8], data[8:10], data[10:])
}

func digest(s string) []byte {
	value := sha256.Sum256([]byte(s))
	return value[:]
}

var tokenFormat = regexp.MustCompile(`^[a-zA-Z0-9_-]{43}$`)
var hostname = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validHost(s string) bool {
	return net.ParseIP(s) != nil || len(s) <= 253 && hostname.MatchString(s)
}

func isLoopback(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}

func validPort(p int) bool { return p > 0 && p <= 65535 }

func (c settings) validate() error {
	listenHost, listenPort, listenErr := net.SplitHostPort(c.Listen)
	tunnelHost, tunnelPort, tunnelErr := net.SplitHostPort(c.TunnelListen)
	apiPort, _ := strconv.Atoi(listenPort)
	dataPort, _ := strconv.Atoi(tunnelPort)
	base, baseErr := url.Parse(c.PublicURL)
	probe, probeErr := url.Parse(c.ProbeURL)
	if listenErr != nil || tunnelErr != nil || !validPort(apiPort) || !validPort(dataPort) ||
		baseErr != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		(base.Path != "" && base.Path != "/") || probeErr != nil || probe.Host == "" || probe.User != nil ||
		!validHost(c.TunnelHost) || !validPort(c.TunnelPort) || !validHost(c.HandshakeHost) ||
		!validHost(c.ServerName) || !validPort(c.HandshakePort) ||
		c.SingBox == "" || c.KeyFile == "" || c.Database == "" || c.RealityKeyFile == "" {
		return errors.New("invalid server addresses, probe, or file paths")
	}
	if c.LoopbackDev {
		if !isLoopback(listenHost) || !isLoopback(tunnelHost) || !isLoopback(base.Hostname()) ||
			!isLoopback(c.TunnelHost) || !isLoopback(c.HandshakeHost) {
			return errors.New("development listeners and handshake must use loopback IPs")
		}
	} else if c.CertFile == "" || c.TLSKeyFile == "" {
		return errors.New("TLS certificate and key are required")
	}
	if c.PublicListen != "" {
		host, port, err := net.SplitHostPort(c.PublicListen)
		publicPort, _ := strconv.Atoi(port)
		ip := net.ParseIP(host)
		if err != nil || !validPort(publicPort) || ip == nil || ip.IsUnspecified() ||
			ip.IsMulticast() || !isLoopback(listenHost) ||
			(apiPort == publicPort && ip.Equal(net.ParseIP(listenHost))) {
			return errors.New("publicListen requires a separate IP listener and a loopback listen")
		}
		if c.LoopbackDev && !ip.IsLoopback() {
			return errors.New("development publicListen must use a loopback IP")
		}
		if base.Scheme != "https" || c.CertFile == "" || c.TLSKeyFile == "" {
			return errors.New("publicListen requires an HTTPS publicUrl, TLS certificate and key")
		}
	}
	if c.LocalAdmin != "" {
		host, port, err := net.SplitHostPort(c.LocalAdmin)
		n, _ := strconv.Atoi(port)
		if c.PublicListen == "" || err != nil || !validPort(n) || n == apiPort ||
			(host != "127.0.0.1" && host != "::1") || port != strconv.Itoa(n) {
			return errors.New("localAdminListen requires publicListen and a separate loopback port")
		}
	}
	if dns := c.DestinationDNS; dns != nil {
		ip := net.ParseIP(dns.Address)
		if c.LoopbackDev || ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() ||
			!validHost(dns.ServerName) {
			return errors.New("destinationDns requires a public resolver IP and TLS name")
		}
	}
	if base.Scheme != "https" && !(c.LoopbackDev && base.Scheme == "http") ||
		probe.Scheme != "https" && !(c.LoopbackDev && probe.Scheme == "http" && isLoopback(probe.Hostname())) {
		return errors.New("HTTPS is required for the public API and probe")
	}
	return nil
}

func (c *settings) resolvePaths(root string) {
	for _, p := range []*string{&c.Database, &c.KeyFile, &c.CertFile, &c.TLSKeyFile, c.AdminDir, &c.AdminTokenFile, &c.SingBox, &c.RealityKeyFile} {
		if p != nil && *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(root, *p)
		}
	}
}

func secureFile(path string, n int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		data = randomBytes(n)
		if _, err := f.Write(data); err != nil {
			f.Close()
			return nil, err
		}
		return data, f.Close()
	}
	if err != nil || len(data) != n {
		return nil, fmt.Errorf("cannot load key file %s", filepath.Base(path))
	}
	return data, nil
}

func openStore(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	err = migrate(db)
	if err != nil {
		db.Close()
	}
	return db, err
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000"); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion {
		return errors.New("database was created by a newer version")
	}
	for next := version + 1; next <= schemaVersion; next++ {
		migration, err := migrations.ReadFile(fmt.Sprintf("migrations/%03d.sql", next))
		if err != nil {
			return err
		}
		if _, err = tx.Exec(string(migration) + fmt.Sprintf("PRAGMA user_version=%d;", next)); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(createDeviceReports); err != nil {
		return err
	}
	if _, err = tx.Exec(createClientUpdatePolicy); err != nil {
		return err
	}
	return tx.Commit()
}

func start(cfg settings, adminToken string) (*server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if !tokenFormat.MatchString(adminToken) {
		return nil, errors.New("set HOMEPROXY_ADMIN_TOKEN to a generated 32-byte base64url token")
	}
	key, err := secureFile(cfg.KeyFile, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	box, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	raw, err := secureFile(cfg.RealityKeyFile, 40)
	if err != nil {
		return nil, err
	}
	private, err := ecdh.X25519().NewPrivateKey(raw[8:])
	if err != nil {
		return nil, err
	}
	db, err := openStore(cfg.Database)
	if err != nil {
		return nil, err
	}
	s := &server{cfg: cfg, db: db, secrets: box, key: private, shortID: hex.EncodeToString(raw[:8]), adminHash: sha256.Sum256([]byte(adminToken))}
	s.core = engine{binary: cfg.SingBox}
	s.core.control, err = loopbackAddress()
	if err != nil {
		db.Close()
		return nil, err
	}
	s.core.token = randomToken()
	cfgBytes, err := s.coreConfig(db)
	if err == nil {
		err = s.core.replace(cfgBytes)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *server) clientRoutes(r *http.ServeMux) {
	r.HandleFunc("GET /api/sub/singbox", s.subSingbox)
	r.HandleFunc("POST /api/v1/connect", s.connect)
	r.HandleFunc("GET /api/v1/config", s.config)
	r.HandleFunc("POST /api/v1/ack", s.ack)
	r.HandleFunc("PUT /api/v1/personal-rules", s.personalRule)
	r.HandleFunc("DELETE /api/v1/personal-rules/{id}", s.deletePersonalRule)
	r.HandleFunc("PUT /api/v1/shared-groups", s.clientSaveGroup)
	r.HandleFunc("DELETE /api/v1/shared-groups/{id}", s.clientDeleteGroup)
	r.HandleFunc("GET /connect", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "Скопируйте ссылку целиком и вставьте в HomeProxy.")
	})
}

func (s *server) publicHandler() http.Handler {
	r := http.NewServeMux()
	s.clientRoutes(r)
	return secureHeaders(r)
}

func (s *server) handler() http.Handler {
	r := http.NewServeMux()
	s.clientRoutes(r)
	s.adminRoutes(r)
	return secureHeaders(r)
}

func (s *server) localAdminHandler() http.Handler {
	r := http.NewServeMux()
	s.adminRoutes(r)
	origin := "http://" + s.cfg.LocalAdmin
	return secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host != s.cfg.LocalAdmin {
			http.Error(w, "Invalid host", http.StatusMisdirectedRequest)
			return
		}
		if requestOrigin := req.Header.Get("Origin"); requestOrigin != "" && requestOrigin != origin {
			http.Error(w, "Invalid origin", http.StatusForbidden)
			return
		}
		r.ServeHTTP(w, req)
	}))
}

func (s *server) adminRoutes(r *http.ServeMux) {
	r.HandleFunc("GET /healthz", s.health)
	r.HandleFunc("GET /api/v1/admin/state", s.admin(s.state))
	r.HandleFunc("GET /api/v1/admin/updates/check", s.admin(s.checkServerUpdate))
	r.HandleFunc("POST /api/v1/admin/updates/apply", s.admin(s.applyServerUpdate))
	r.HandleFunc("GET /api/v1/admin/update-history", s.admin(s.updateHistory))
	r.HandleFunc("GET /api/v1/admin/update-policy", s.admin(s.updatePolicy))
	r.HandleFunc("PUT /api/v1/admin/update-policy", s.admin(s.updatePolicy))
	r.HandleFunc("GET /api/v1/admin/client-update-policy", s.admin(s.clientUpdatePolicy))
	r.HandleFunc("PUT /api/v1/admin/client-update-policy", s.admin(s.clientUpdatePolicy))
	r.HandleFunc("POST /api/v1/admin/users", s.admin(s.user))
	r.HandleFunc("PUT /api/v1/admin/users/{id}", s.admin(s.user))
	r.HandleFunc("PUT /api/v1/admin/users/{id}/permissions", s.admin(s.userPermissions))
	r.HandleFunc("DELETE /api/v1/admin/users/{id}", s.admin(s.deleteUser))
	r.HandleFunc("PUT /api/v1/admin/proxies", s.admin(s.proxy))
	r.HandleFunc("DELETE /api/v1/admin/proxies/{id}", s.admin(s.deleteProxy))
	r.HandleFunc("PUT /api/v1/admin/routes", s.admin(s.routes))
	r.HandleFunc("POST /api/v1/admin/invites", s.admin(s.invite))
	r.HandleFunc("POST /api/v1/admin/devices/{id}/sub-link", s.admin(s.ensureDeviceSubLink))
	r.HandleFunc("PUT /api/v1/admin/devices/{id}/access", s.admin(s.deviceAccess))
	r.HandleFunc("DELETE /api/v1/admin/devices/history", s.admin(s.clearDeviceHistory))
	r.HandleFunc("DELETE /api/v1/admin/devices/{id}", s.admin(s.revoke))
	r.HandleFunc("PUT /api/v1/admin/rules", s.admin(s.adminRule))
	r.HandleFunc("DELETE /api/v1/admin/rules/{id}", s.admin(s.deleteRule))
	r.HandleFunc("PUT /api/v1/admin/groups", s.admin(s.saveGroup))
	r.HandleFunc("DELETE /api/v1/admin/groups/{id}", s.admin(s.deleteGroup))
	r.HandleFunc("POST /api/v1/admin/probes/{id}", s.admin(s.probe))
	r.HandleFunc("POST /api/v1/admin/backups", s.admin(s.backup))
	if s.cfg.AdminDir == nil {
		if bundledAdmin != nil {
			r.Handle("GET /", http.FileServerFS(bundledAdmin))
		}
	} else if *s.cfg.AdminDir != "" {
		r.Handle("GET /", http.FileServer(http.Dir(*s.cfg.AdminDir)))
	}
}

func secureHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; style-src 'self' 'unsafe-inline'")
		if req.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		handler.ServeHTTP(w, req)
	})
}

func (s *server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if subtle.ConstantTimeCompare(s.adminHash[:], digest(bearer(req))) != 1 {
			fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, req)
	}
}

func bearer(req *http.Request) string {
	value, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || !tokenFormat.MatchString(value) {
		return ""
	}
	return value
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		fail(w, 400, "invalid_json")
		return false
	}
	return true
}

func send(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, status int, code string) {
	send(w, status, map[string]string{"error": code})
}

func internal(w http.ResponseWriter, err error) {
	// Driver and connection errors can include values from secret-bearing requests.
	log.Printf("operation failed (%T)", err)
	fail(w, 500, "operation_failed")
}

func (s *server) health(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), time.Second)
	defer cancel()
	status := 200
	if s.db.PingContext(ctx) != nil || !s.core.ready(ctx) {
		status = 503
	}
	send(w, status, map[string]any{
		"ready": status == 200, "api": apiVersion, "dbSchema": schemaVersion,
		"version": releaseVersion, "pid": os.Getpid(),
	})
}

func resolveConfigPath(path string) (string, error) {
	if path == "server.json" {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if exe, exeErr := os.Executable(); exeErr == nil {
				candidate := filepath.Join(filepath.Dir(exe), "server.json")
				if _, statErr := os.Stat(candidate); statErr == nil {
					path = candidate
				}
			}
		}
	}
	return filepath.Abs(path)
}

func run(ctx context.Context) error {
	config := flag.String("config", "server.json", "server settings file")
	gen := flag.Bool("generate-token", false, "print an administrative token and exit")
	restore := flag.String("restore", "", "restore a local SQLite backup with the service stopped")
	backup := flag.String("backup", "", "write a new SQLite backup with the service stopped")
	flag.Parse()
	if *restore != "" && *backup != "" {
		return errors.New("choose backup or restore")
	}
	if *gen {
		fmt.Println(randomToken())
		return nil
	}
	path, err := resolveConfigPath(*config)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg settings
	parser := json.NewDecoder(strings.NewReader(string(data)))
	parser.DisallowUnknownFields()
	if err = parser.Decode(&cfg); err != nil {
		return err
	}
	cfg.resolvePaths(filepath.Dir(path))
	if err := cfg.validate(); err != nil {
		return err
	}
	lock, err := lockStore(cfg.Database)
	if err != nil {
		return err
	}
	defer lock.Close()
	if *restore != "" {
		return restoreStore(cfg, *restore)
	}
	if *backup != "" {
		return backupStore(cfg.Database, *backup)
	}
	admin := os.Getenv("HOMEPROXY_ADMIN_TOKEN")
	if cfg.AdminTokenFile != "" {
		raw, err := os.ReadFile(cfg.AdminTokenFile)
		if err != nil {
			return errors.New("cannot read administrative token file")
		}
		admin = strings.TrimSpace(string(raw))
	}
	s, err := start(cfg, admin)
	if err != nil {
		return err
	}
	defer s.db.Close()
	defer func() {
		s.write.Lock()
		defer s.write.Unlock()
		s.core.stop()
	}()
	return s.serveAPI(ctx)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) > 1 && os.Args[1] == "ctl" {
		if err := runCLI(ctx, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := runPlatform(ctx); err != nil {
		log.Fatal(err)
	}
}
