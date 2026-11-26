package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type processService struct {
	image, config string
	cmd           *exec.Cmd
	done          chan struct{}
}

func (s *processService) pid() (int, error) {
	if s.cmd == nil {
		return 0, nil
	}
	select {
	case <-s.done:
		return 0, nil
	default:
		return s.cmd.Process.Pid, nil
	}
}

func (s *processService) start(_ health) error {
	s.cmd = exec.Command(s.image, "-config", s.config)
	s.cmd.Env = append(os.Environ(), "HOMEPROXY_ADMIN_TOKEN="+strings.Repeat("A", 43))
	hideConsole(s.cmd)
	if err := s.cmd.Start(); err != nil {
		s.cmd = nil
		return err
	}
	s.done = make(chan struct{})
	go func(cmd *exec.Cmd, done chan struct{}) {
		cmd.Wait()
		close(done)
	}(s.cmd, s.done)
	return nil
}

func (s *processService) stop(ctx context.Context) error {
	if s.cmd == nil {
		return nil
	}
	if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		s.cmd = nil
		return nil
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func writeJSON(t *testing.T, file string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateTransactionWithServer(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("uses the Windows sing-box tool")
	}
	singbox := os.Getenv("HOMEPROXY_TEST_SINGBOX")
	if singbox == "" {
		singbox = "../../.tools/sing-box-1.14.4-windows-amd64/sing-box.exe"
	}
	singbox, _ = filepath.Abs(singbox)
	if _, err := os.Stat(singbox); errors.Is(err, os.ErrNotExist) {
		t.Skip("install the project sing-box tool or set HOMEPROXY_TEST_SINGBOX")
	} else if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	goCompiler := filepath.Join(runtime.GOROOT(), "bin", "go.exe")
	image := filepath.Join(root, "homeproxy-server.exe")
	pkg := filepath.Join(root, "next.exe")
	for _, target := range []struct{ Version, Path string }{{"0.1.0", image}, {"0.2.0", pkg}} {
		cmd := exec.Command(goCompiler, "build", "-mod=readonly", "-trimpath", "-ldflags=-X main.releaseVersion="+target.Version,
			"-o", target.Path, "./apps/server")
		cmd.Dir = "../.."
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", target.Version, err, output)
		}
	}
	const host = "127.0.0.1"
	listen := (&net.TCPAddr{IP: net.ParseIP(host), Port: freePort(t)}).String()
	tunnel := freePort(t)
	url := "http://" + listen
	config := filepath.Join(root, "server.json")
	writeJSON(t, config, map[string]any{
		"listen": listen, "publicUrl": url, "database": "server.sqlite", "keyFile": "secret.key", "realityKeyFile": "reality.key",
		"tunnelListen": (&net.TCPAddr{IP: net.ParseIP(host), Port: tunnel}).String(), "tunnelHost": host, "tunnelPort": tunnel,
		"serverName": "localhost", "handshakeHost": host, "handshakePort": freePort(t),
		"probeUrl": url + "/healthz", "singBox": singbox, "loopbackDev": true,
	})
	probe, err := localProbe(config)
	if err != nil {
		t.Fatal(err)
	}
	service := &processService{image: image, config: config}
	i := installation{service: service, image: image, config: config, probe: probe,
		stateDir: filepath.Join(root, ".homeproxy-updates"), startTimeout: 5 * time.Second}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.stop(ctx); err != nil {
			t.Error(err)
		}
	}()
	if err := service.start(health{}); err != nil {
		t.Fatal(err)
	}
	const fixtureSchema = 3
	previous := health{Ready: true, Version: "0.1.0", API: 1, DBSchema: fixtureSchema}
	if err := i.waitReady(previous); err != nil {
		t.Fatal(err)
	}
	id, err := service.pid()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe(context.Background(), id+1); err == nil {
		t.Fatal("health probe accepted the wrong process")
	}
	addUser(t, url)
	lock, err := i.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if duplicate, err := i.lock(); err == nil {
		duplicate.Close()
		t.Fatal("another update acquired the lock")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "public.pem")
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	manifest, sig := filepath.Join(root, "release.json"), filepath.Join(root, "release.sig")
	hash, err := fileHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(pkg)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(v string, schema int) {
		entry := artifact{Component: "server", Channel: "dev", Version: v, Platform: runtime.GOOS, Arch: runtime.GOARCH,
			Size: info.Size(), SHA256: hash, APIMin: 1, APIMax: 1, DBSchema: schema}
		writeJSON(t, manifest, map[string]any{"format": 1, "artifacts": []artifact{entry}})
		raw, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sig, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))), 0600); err != nil {
			t.Fatal(err)
		}
	}

	sign("0.2.0", fixtureSchema+1)
	if err := i.apply(manifest, sig, key, pkg, "dev"); err == nil {
		t.Fatal("incompatible package was accepted")
	}
	if got, err := service.pid(); err != nil || got != id {
		t.Fatal("rejected release affected the running service")
	}

	sign("0.3.0", fixtureSchema)
	if err := i.apply(manifest, sig, key, pkg, "dev"); err == nil || !strings.Contains(err.Error(), "previous service restored") {
		t.Fatalf("expected working rollback after version mismatch, got %v", err)
	}
	if err := i.waitReady(previous); err != nil {
		t.Fatal(err)
	}
	assertUser(t, filepath.Join(root, "server.sqlite"))

	sign("0.2.0", fixtureSchema)
	if err := i.apply(manifest, sig, key, pkg, "dev"); err != nil {
		t.Fatal(err)
	}
	next := health{Ready: true, Version: "0.2.0", API: 1, DBSchema: fixtureSchema}
	if err := i.waitReady(next); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(filepath.Join(i.stateDir, "release-*", "previous.sqlite"))
	if err != nil || len(backups) != 2 {
		t.Fatalf("expected both upgrade backups, got %v, %v", backups, err)
	}
	assertUser(t, backups[0])
	assertUser(t, backups[1])
	assertUser(t, filepath.Join(root, "server.sqlite"))

	// Recreate the durable state immediately after replacing a service image.
	dir, err := os.MkdirTemp(i.stateDir, "release-")
	if err != nil {
		t.Fatal(err)
	}
	nextHash, err := copyFile(image, filepath.Join(dir, "previous.exe"))
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(filepath.Dir(backups[0]), "previous.exe")
	candidate := filepath.Join(dir, "candidate.exe")
	oldHash, err := copyFile(old, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(i.pending(), updateRecord{filepath.Base(dir), next, nextHash, oldHash}); err != nil {
		t.Fatal(err)
	}
	if err := service.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := replaceImage(candidate, image); err != nil {
		t.Fatal(err)
	}
	if err := i.recover(); err != nil {
		t.Fatal(err)
	}
	if err := i.waitReady(next); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(i.pending()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful recovery left a pending update")
	}
}

func addUser(t *testing.T, baseURL string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/users", bytes.NewBufferString(`{"name":"Updater QA"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43))
	request.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create fixture user: %d", res.StatusCode)
	}
}

func assertUser(t *testing.T, file string) {
	t.Helper()
	db, err := sql.Open("sqlite", file)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var user string
	if err := db.QueryRow("SELECT name FROM users").Scan(&user); err != nil || user != "Updater QA" {
		t.Fatalf("fixture user was lost: %q, %v", user, err)
	}
}
