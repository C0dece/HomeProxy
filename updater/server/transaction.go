package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type serviceControl interface {
	pid() (int, error)
	stop(context.Context) error
	start(health) error
}

type health struct {
	Ready    bool   `json:"ready"`
	PID      int    `json:"pid"`
	Version  string `json:"version"`
	API      int    `json:"api"`
	DBSchema int    `json:"dbSchema"`
}

type installation struct {
	service      serviceControl
	image        string
	config       string
	stateDir     string
	probe        func(context.Context, int) (health, error)
	startTimeout time.Duration
}

type updateRecord struct {
	Directory   string `json:"directory"`
	Previous    health `json:"previous"`
	PreviousSHA string `json:"previousSHA"`
	NextSHA     string `json:"nextSHA"`
}

var releaseDirectory = regexp.MustCompile(`^release-[0-9]+$`)

func (i installation) lock() (*os.File, error) {
	if err := os.MkdirAll(i.stateDir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(i.stateDir, "update.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockUpdate(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot lock local installation: %w", err)
	}
	return f, nil
}

func (i installation) pending() string { return filepath.Join(i.stateDir, "pending.json") }

func (i installation) current(ctx context.Context) (health, error) {
	pid, err := i.service.pid()
	if err != nil {
		return health{}, err
	}
	if pid <= 0 {
		return health{}, errors.New("service is not running")
	}
	status, err := i.probe(ctx, pid)
	if err != nil {
		return health{}, err
	}
	if _, err := parseVersion(status.Version); err != nil || status.API <= 0 || status.DBSchema <= 0 {
		return health{}, errors.New("running server does not report its release and database versions")
	}
	return status, nil
}

func (i installation) apply(manifest, signature, key, local, channel string) error {
	if _, err := os.Lstat(i.pending()); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		return errors.New("an interrupted update is pending. Run with -recover-service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	previous, err := i.current(ctx)
	if err != nil {
		return err
	}
	version, err := parseVersion(previous.Version)
	if err != nil {
		return err
	}
	pkg, err := loadRelease(manifest, signature, key,
		selection{"server", channel, runtime.GOOS, runtime.GOARCH, version, previous.API, previous.DBSchema})
	if err != nil {
		return err
	}
	return i.install(pkg, local, previous)
}

func (i installation) install(pkg artifact, local string, previous health) error {
	dir, err := os.MkdirTemp(i.stateDir, "release-")
	if err != nil {
		return err
	}
	candidate := filepath.Join(dir, "candidate.exe")
	saved := filepath.Join(dir, "previous.exe")
	keepBackup := false
	defer func() {
		os.Remove(candidate)
		if !keepBackup {
			os.Remove(saved)
			os.Remove(dir)
		}
	}()
	if err := stage(pkg, local, candidate); err != nil {
		return err
	}
	if err := os.Chmod(candidate, 0700); err != nil {
		return err
	}
	oldHash, err := copyFile(i.image, saved)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fresh, err := i.current(ctx)
	if err != nil || fresh != previous {
		return errors.New("server changed while the release was being staged")
	}
	record := updateRecord{filepath.Base(dir), previous, oldHash, strings.ToLower(pkg.SHA256)}
	if err := writeRecord(i.pending(), record); err != nil {
		return err
	}
	keepBackup = true

	if err := i.switchRelease(pkg, record, dir); err != nil {
		if rollbackErr := i.recover(); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("automatic rollback failed with the journal retained: %w", rollbackErr))
		}
		return fmt.Errorf("update failed and previous service restored: %w", err)
	}
	fmt.Printf("Installed %s. Recovery copy in %s\n", pkg.Version, dir)
	return nil
}

func (i installation) switchRelease(pkg artifact, record updateRecord, dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := i.service.stop(ctx); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	if got, err := fileHash(i.image); err != nil || got != record.PreviousSHA {
		return errors.New("installed image changed before replacement")
	}
	backupCtx, done := context.WithTimeout(context.Background(), 60*time.Second)
	defer done()
	cmd := exec.CommandContext(backupCtx, i.image, "-config", i.config, "-backup", filepath.Join(dir, "previous.sqlite"))
	hideConsole(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("SQLite backup failed: %w", err)
	}
	candidate := filepath.Join(dir, "candidate.exe")
	if got, err := fileHash(candidate); err != nil || got != record.NextSHA {
		return errors.New("staged executable changed after verification")
	}
	if err := replaceImage(candidate, i.image); err != nil {
		return fmt.Errorf("replace service image: %w", err)
	}
	desired := record.Previous
	desired.Version = pkg.Version
	desired.DBSchema = pkg.DBSchema
	if err := i.service.start(desired); err != nil {
		return fmt.Errorf("start updated service: %w", err)
	}
	if err := i.waitReady(desired); err != nil {
		return err
	}
	return os.Remove(i.pending())
}

func (i installation) recover() error {
	raw, err := read(i.pending(), 4096)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("No interrupted update")
		return nil
	}
	if err != nil {
		return err
	}
	var record updateRecord
	if json.Unmarshal(raw, &record) != nil || !releaseDirectory.MatchString(record.Directory) ||
		!validHash(record.PreviousSHA) || !validHash(record.NextSHA) {
		return errors.New("invalid update journal")
	}
	saved := filepath.Join(i.stateDir, record.Directory, "previous.exe")
	if hash, err := fileHash(saved); err != nil || hash != record.PreviousSHA {
		return errors.New("previous executable is missing or has changed")
	}
	hash, err := fileHash(i.image)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	switch hash {
	case record.PreviousSHA:
		// The old image might still be running if the update failed before swap.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		status, probeErr := i.current(ctx)
		cancel()
		if probeErr == nil && status.matches(record.Previous) {
			return os.Remove(i.pending())
		}
	case record.NextSHA, "":
	default:
		return errors.New("installed executable is unrelated to the pending update")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := i.service.stop(ctx); err != nil {
		return fmt.Errorf("stop service for recovery: %w", err)
	}
	if hash != record.PreviousSHA {
		restore := filepath.Join(i.stateDir, record.Directory, "rollback.exe")
		if err := os.Remove(restore); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clear recovery staging file: %w", err)
		}
		defer os.Remove(restore)
		if got, err := copyFile(saved, restore); err != nil || got != record.PreviousSHA {
			return errors.New("could not copy the verified predecessor")
		}
		if err := replaceImage(restore, i.image); err != nil {
			return fmt.Errorf("restore previous executable: %w", err)
		}
	}
	savedDB := filepath.Join(i.stateDir, record.Directory, "previous.sqlite")
	if _, statErr := os.Stat(savedDB); statErr == nil && i.config != "" {
		if dbPath, err := configuredDatabase(i.config); err == nil && dbPath != "" {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				_ = os.Remove(dbPath + suffix)
			}
			tmpDB := filepath.Join(filepath.Dir(dbPath), ".rollback-db-"+record.Directory)
			_ = os.Remove(tmpDB)
			if _, err := copyFile(savedDB, tmpDB); err != nil {
				_ = os.Remove(tmpDB)
				return fmt.Errorf("stage database rollback: %w", err)
			}
			if err := replaceFile(tmpDB, dbPath); err != nil {
				_ = os.Remove(tmpDB)
				return fmt.Errorf("restore database backup: %w", err)
			}
		}
	}
	if err := i.service.start(record.Previous); err != nil {
		return fmt.Errorf("restart previous service: %w", err)
	}
	if err := i.waitReady(record.Previous); err != nil {
		return err
	}
	if err := os.Remove(i.pending()); err != nil {
		return fmt.Errorf("clear recovered journal: %w", err)
	}
	return nil
}

func (got health) matches(expected health) bool {
	a, aErr := parseVersion(got.Version)
	b, bErr := parseVersion(expected.Version)
	return got.Ready && aErr == nil && bErr == nil && a == b && got.API == expected.API && got.DBSchema == expected.DBSchema
}

func (i installation) waitReady(expected health) error {
	ctx, cancel := context.WithTimeout(context.Background(), i.startTimeout)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := i.current(ctx)
		if err == nil && status.matches(expected) {
			return nil
		}
		select {
		case <-ctx.Done():
			if err == nil {
				err = fmt.Errorf("reported version %s, API %d, schema %d", status.Version, status.API, status.DBSchema)
			}
			return fmt.Errorf("health check for release %s failed: %w", expected.Version, err)
		case <-ticker.C:
		}
	}
}

func copyFile(source, dest string) (string, error) {
	in, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, hash), in)
	return hex.EncodeToString(hash.Sum(nil)), errors.Join(copyErr, out.Sync(), out.Close())
}

func fileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	return hex.EncodeToString(hash.Sum(nil)), err
}

func validHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size
}

func configuredDatabase(configPath string) (string, error) {
	data, err := read(configPath, 64<<10)
	if err != nil {
		return "", err
	}
	var cfg struct {
		Database string `json:"database"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	if strings.TrimSpace(cfg.Database) == "" {
		return "", nil
	}
	if filepath.IsAbs(cfg.Database) {
		return cfg.Database, nil
	}
	return filepath.Join(filepath.Dir(configPath), cfg.Database), nil
}

func writeRecord(path string, record updateRecord) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".journal-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	writeErr := json.NewEncoder(file).Encode(record)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return replaceFile(file.Name(), path)
}

// The HTTP authority supplies the TLS name. The actual TCP connection always
// uses the local listener in the service configuration.
func localProbe(config string) (func(context.Context, int) (health, error), error) {
	type listenerConfig struct {
		Listen      string `json:"listen"`
		PublicURL   string `json:"publicUrl"`
		CertFile    string `json:"certFile"`
		LoopbackDev bool   `json:"loopbackDev"`
	}
	var cfg listenerConfig
	data, err := read(config, 64<<10)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	portNumber, parseErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("invalid configured listener address")
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !localIP(ip) {
		return nil, errors.New("health check requires a numeric local listen address")
	}
	authority, err := url.Parse(cfg.PublicURL)
	if err != nil || authority.Hostname() == "" || authority.User != nil {
		return nil, errors.New("invalid configured HTTPS authority")
	}
	scheme := "https"
	if cfg.CertFile == "" {
		if !cfg.LoopbackDev || !ip.IsLoopback() {
			return nil, errors.New("health check requires TLS outside loopback development")
		}
		scheme = "http"
	}
	endpoint := (&url.URL{Scheme: scheme, Host: authority.Host, Path: "/healthz"}).String()
	address := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: time.Second}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(ctx context.Context, pid int) (health, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return health{}, err
		}
		res, err := client.Do(req)
		if err != nil {
			return health{}, err
		}
		defer res.Body.Close()
		var status health
		if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&status) != nil ||
			!status.Ready || status.PID != pid {
			return health{}, errors.New("health response does not identify the ready service process")
		}
		return status, nil
	}, nil
}

func localIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	addresses, _ := net.InterfaceAddrs()
	for _, addr := range addresses {
		if network, ok := addr.(*net.IPNet); ok && network.IP.Equal(ip) {
			return true
		}
	}
	return false
}
