package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeleteUserCascades(t *testing.T) {
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxySrv.Close()
	parsed, _ := url.Parse(proxySrv.URL)

	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	h := s.handler()

	uRec := doJSON(t, h, "POST", "/api/v1/admin/users", adminToken, map[string]any{"name": "TempUser"})
	if uRec.Code != 201 {
		t.Fatalf("create user: %d %s", uRec.Code, uRec.Body.String())
	}
	var uResp struct{ ID string }
	_ = json.Unmarshal(uRec.Body.Bytes(), &uResp)

	pRec := doJSON(t, h, "PUT", "/api/v1/admin/proxies", adminToken, map[string]any{
		"name": "KeepProxy", "host": parsed.Hostname(), "port": mustAtoi(t, parsed.Port()), "tls": false,
	})
	var pResp struct{ ID string }
	_ = json.Unmarshal(pRec.Body.Bytes(), &pResp)

	_ = doJSON(t, h, "PUT", "/api/v1/admin/routes", adminToken, map[string]any{
		"userId": uResp.ID, "proxyIds": []string{pResp.ID},
	})
	invRec := doJSON(t, h, "POST", "/api/v1/admin/invites", adminToken, map[string]any{
		"userId": uResp.ID, "label": "TempDev", "transport": "agent",
	})
	var invResp struct{ Link string }
	_ = json.Unmarshal(invRec.Body.Bytes(), &invResp)
	_ = doJSON(t, h, "POST", "/api/v1/connect", "", map[string]any{
		"token": strings.Split(invResp.Link, "#")[1], "deviceKey": randomToken(), "transport": "agent",
	})
	_ = doJSON(t, h, "PUT", "/api/v1/admin/rules", adminToken, map[string]any{
		"userId": uResp.ID, "kind": "domain", "pattern": "temp.example", "action": "PROXY",
	})
	_ = doJSON(t, h, "PUT", "/api/v1/admin/groups", adminToken, map[string]any{
		"name": "TempGroup", "userId": uResp.ID, "action": "PROXY", "enabled": true,
		"entries": []map[string]string{{"kind": "domain", "pattern": "grp.example"}},
	})

	delRec := doJSON(t, h, "DELETE", "/api/v1/admin/users/"+uResp.ID, adminToken, nil)
	if delRec.Code != 204 {
		t.Fatalf("delete user: %d %s", delRec.Code, delRec.Body.String())
	}
	if delAgain := doJSON(t, h, "DELETE", "/api/v1/admin/users/"+uResp.ID, adminToken, nil); delAgain.Code != 404 {
		t.Fatalf("expected 404 on second delete, got %d", delAgain.Code)
	}

	stRec := doJSON(t, h, "GET", "/api/v1/admin/state", adminToken, nil)
	var st cliState
	_ = json.Unmarshal(stRec.Body.Bytes(), &st)
	if len(st.Users) != 0 || len(st.Devices) != 0 || len(st.Routes) != 0 || len(st.Rules) != 0 || len(st.Groups) != 0 {
		t.Fatalf("expected cascade delete of user resources, got %+v", st)
	}
	if len(st.Proxies) != 1 {
		t.Fatalf("expected proxy to remain, got %+v", st.Proxies)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func TestCLIFullWorkflow(t *testing.T) {
	var seenHdr string
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHdr = r.Header.Get("X-CLI-Hdr")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxySrv.Close()
	parsed, _ := url.Parse(proxySrv.URL)

	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	if cfgBytes, err := s.coreConfig(s.db); err != nil {
		t.Fatal(err)
	} else if err := s.core.replace(cfgBytes); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s.cfg.Database = filepath.Join(dir, "cli-test.sqlite")
	apiSrv := httptest.NewServer(s.handler())
	defer apiSrv.Close()

	run := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		full := append([]string{"-url", apiSrv.URL, "-token", adminToken}, args...)
		if err := runCLIWithIO(context.Background(), full, &stdout, &stderr); err != nil {
			t.Fatalf("ctl %v failed: %v\nstderr: %s", args, err, stderr.String())
		}
		return stdout.String()
	}
	runJSON := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		full := append([]string{"-url", apiSrv.URL, "-token", adminToken, "-json"}, args...)
		if err := runCLIWithIO(context.Background(), full, &stdout, &stderr); err != nil {
			t.Fatalf("ctl -json %v failed: %v\nstderr: %s", args, err, stderr.String())
		}
		return stdout.String()
	}

	// Help & Status
	if out := run("help"); !strings.Contains(out, "HomeProxy Server CLI") {
		t.Fatalf("unexpected help output: %s", out)
	}
	if out := run("status"); !strings.Contains(out, "Version:") || !strings.Contains(out, "Devices:") {
		t.Fatalf("unexpected status output: %s", out)
	}

	// Users
	run("users", "add", "Alice")
	if out := run("users", "list"); !strings.Contains(out, "Alice") {
		t.Fatalf("users list missing Alice: %s", out)
	}
	run("users", "rename", "Alice", "AliceRenamed")
	if out := run("users", "list"); !strings.Contains(out, "AliceRenamed") {
		t.Fatalf("users list missing AliceRenamed: %s", out)
	}

	// Proxies
	run("proxies", "add", "-name", "ExtProxy", "-host", parsed.Hostname(), "-port", parsed.Port(), "-header", "X-CLI-Hdr: v1")
	if seenHdr != "v1" {
		t.Fatalf("expected header v1 on probe, got %q", seenHdr)
	}
	run("proxies", "update", "ExtProxy", "-header", "X-CLI-Hdr: v2")
	if seenHdr != "v2" {
		t.Fatalf("expected updated header v2, got %q", seenHdr)
	}
	if out := run("proxies", "probe", "ExtProxy"); !strings.Contains(out, "reachable") {
		t.Fatalf("unexpected probe output: %s", out)
	}
	if out := run("proxies", "list"); !strings.Contains(out, "ExtProxy") {
		t.Fatalf("proxies list missing ExtProxy: %s", out)
	}
	run("users", "assign-proxies", "AliceRenamed", "ExtProxy")

	// Devices
	invJSON := runJSON("devices", "invite", "-user", "AliceRenamed", "-label", "MyLaptop", "-transport", "agent")
	var inv struct {
		ID   string `json:"id"`
		Link string `json:"link"`
	}
	if err := json.Unmarshal([]byte(invJSON), &inv); err != nil {
		t.Fatal(err)
	}
	devKey := randomToken()
	connRec := doJSON(t, s.handler(), "POST", "/api/v1/connect", "", map[string]any{
		"token": strings.Split(inv.Link, "#")[1], "deviceKey": devKey, "transport": "agent",
	})
	if connRec.Code != 201 {
		t.Fatalf("connect: %d", connRec.Code)
	}
	if out := run("devices", "online"); !strings.Contains(out, "MyLaptop") {
		t.Fatalf("devices online missing newly connected MyLaptop: %s", out)
	}
	if out := run("devices", "list"); !strings.Contains(out, "online") {
		t.Fatalf("devices list missing online status: %s", out)
	}

	// Rules
	rJSON := runJSON("rules", "set", "-kind", "domain", "-pattern", "site.example", "-action", "PROXY", "-user", "AliceRenamed", "-disabled")
	var createdRule rule
	_ = json.Unmarshal([]byte(rJSON), &createdRule)
	if createdRule.Enabled {
		t.Fatalf("expected disabled rule")
	}
	run("rules", "toggle", createdRule.ID)
	if out := run("rules", "list"); !strings.Contains(out, "site.example") || !strings.Contains(out, "true") {
		t.Fatalf("rules list unexpected: %s", out)
	}
	run("rules", "remove", createdRule.ID)

	// Groups
	run("groups", "create", "-name", "ChatGPT", "-action", "PROXY", "-entry", "domain:chatgpt.com", "-entry", "ip_cidr:104.18.0.0/16")
	run("groups", "add-entry", "ChatGPT", "-kind", "suffix", "-pattern", "openai.com")
	run("groups", "remove-entry", "ChatGPT", "-kind", "domain", "-pattern", "chatgpt.com")
	run("groups", "set-action", "ChatGPT", "SERVER_DIRECT")
	run("groups", "toggle", "ChatGPT", "-enabled=false")
	gOut := run("groups", "list")
	if !strings.Contains(gOut, "ChatGPT") || !strings.Contains(gOut, "SERVER_DIRECT") || !strings.Contains(gOut, "false") {
		t.Fatalf("unexpected groups list: %s", gOut)
	}
	run("groups", "delete", "ChatGPT")

	// Backup, revoke, cleanup
	bOut := strings.TrimSpace(run("backup"))
	if _, err := os.Stat(filepath.Join(dir, "backups", bOut)); err != nil {
		t.Fatalf("backup file not created: %v", err)
	}
	run("devices", "revoke", "MyLaptop")
	run("proxies", "remove", "ExtProxy")
	run("users", "delete", "AliceRenamed")
}

func TestCLISelfSignedTLSFromConfig(t *testing.T) {
	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	if cfgBytes, err := s.coreConfig(s.db); err != nil {
		t.Fatal(err)
	} else if err := s.core.replace(cfgBytes); err != nil {
		t.Fatal(err)
	}
	tlsSrv := httptest.NewTLSServer(s.handler())
	defer tlsSrv.Close()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	tokPath := filepath.Join(dir, "token.txt")
	if err := os.WriteFile(tokPath, []byte(adminToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(tlsSrv.URL)
	cfgPath := filepath.Join(dir, "server.json")
	cfgJSON, _ := json.Marshal(map[string]any{
		"listen":         parsed.Host,
		"publicUrl":      tlsSrv.URL,
		"certFile":       "cert.pem",
		"adminTokenFile": "token.txt",
	})
	if err := os.WriteFile(cfgPath, cfgJSON, 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := runCLIWithIO(context.Background(), []string{"-config", cfgPath, "status"}, &stdout, &stderr); err != nil {
		t.Fatalf("CLI over TLS from server.json failed: %v\nstderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Ready:") {
		t.Fatalf("unexpected TLS status output: %s", stdout.String())
	}
}
