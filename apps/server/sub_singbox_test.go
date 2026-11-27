package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func singboxCheckConfig(t *testing.T, configBytes []byte) {
	t.Helper()
	singbox := os.Getenv("HOMEPROXY_TEST_SINGBOX")
	if singbox == "" {
		singbox = filepath.Join("..", "..", ".tools", "sing-box-1.14.4-windows-amd64", "sing-box.exe")
	}
	if _, err := os.Stat(singbox); err != nil {
		if runtime.GOOS != "windows" {
			t.Skip("sing-box binary unavailable on non-Windows without HOMEPROXY_TEST_SINGBOX")
		}
		t.Fatalf("sing-box binary not found at %s: %v", singbox, err)
	}
	cfgPath := filepath.Join(t.TempDir(), "sub-check.json")
	if err := os.WriteFile(cfgPath, configBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(singbox, "check", "-c", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check failed: %v\noutput:\n%s\nconfig:\n%s", err, string(out), string(configBytes))
	}
}

func extractSubToken(t *testing.T, subURL string) string {
	t.Helper()
	parsed, err := url.Parse(subURL)
	if err != nil {
		t.Fatalf("parse subUrl %q: %v", subURL, err)
	}
	tok := parsed.Query().Get("token")
	if tok == "" {
		t.Fatalf("empty token in subUrl %q", subURL)
	}
	return tok
}

func TestMigrateV4ToV5PreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v4.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"001.sql", "002.sql", "003.sql", "004.sql"} {
		sqlBytes, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version=4;"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO users(id,name,can_edit_global) VALUES('u1','Alice',0);
		INSERT INTO devices(id,user_id,label,transport,expires,primary_id,direct_id,universal,link_type,access_enabled)
		VALUES('d1','u1','iPhone','agent',0,'p-id','d-id',1,'permanent',1);
	`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	migrated, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()

	var version int
	if err := migrated.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("expected user_version=%d, got %d (err=%v)", schemaVersion, version, err)
	}
	var subActive int
	var subHash, subEnc []byte
	if err := migrated.QueryRow("SELECT sub_active, sub_token_hash, sub_token_enc FROM devices WHERE id='d1'").Scan(&subActive, &subHash, &subEnc); err != nil {
		t.Fatalf("query migrated v5 columns: %v", err)
	}
	if subActive != 0 || len(subHash) != 0 || len(subEnc) != 0 {
		t.Fatalf("unexpected v5 column defaults: subActive=%d hash=%v enc=%v", subActive, subHash, subEnc)
	}
}

func TestSingboxSubscriptionValidConfigAndHeaders(t *testing.T) {
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxySrv.Close()
	proxyParsed, _ := url.Parse(proxySrv.URL)
	proxyPort, _ := strconv.Atoi(proxyParsed.Port())

	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	h := s.handler()

	userRec := doJSON(t, h, "POST", "/api/v1/admin/users", adminToken, map[string]any{"name": "iOS User"})
	if userRec.Code != 201 {
		t.Fatalf("create user: %d %s", userRec.Code, userRec.Body.String())
	}
	var user struct{ ID string }
	_ = json.Unmarshal(userRec.Body.Bytes(), &user)

	for _, name := range []string{"EU-Node", "US-Node"} {
		rec := doJSON(t, h, "PUT", "/api/v1/admin/proxies", adminToken, map[string]any{
			"name": name, "host": proxyParsed.Hostname(), "port": proxyPort, "tls": false, "username": "u", "password": "p",
		})
		if rec.Code != 200 {
			t.Fatalf("create proxy %s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	stateRec := doJSON(t, h, "GET", "/api/v1/admin/state", adminToken, nil)
	var state struct {
		Proxies []struct{ ID, Name string } `json:"proxies"`
	}
	_ = json.Unmarshal(stateRec.Body.Bytes(), &state)
	if len(state.Proxies) < 2 {
		t.Fatalf("expected 2 proxies, got %d", len(state.Proxies))
	}
	routesRec := doJSON(t, h, "PUT", "/api/v1/admin/routes", adminToken, map[string]any{
		"userId": user.ID, "proxyIds": []string{state.Proxies[0].ID, state.Proxies[1].ID},
	})
	if routesRec.Code != 204 {
		t.Fatalf("save routes: %d %s", routesRec.Code, routesRec.Body.String())
	}

	// Enabled shared group (global) and disabled shared group.
	g1 := doJSON(t, h, "PUT", "/api/v1/admin/groups", adminToken, map[string]any{
		"name": "AI", "action": "PROXY", "enabled": true, "locked": false,
		"entries": []map[string]any{
			{"kind": "domain", "pattern": "chatgpt.com", "enabled": true},
			{"kind": "suffix", "pattern": "openai.com", "enabled": true},
			{"kind": "domain", "pattern": "disabled-entry.com", "enabled": false},
		},
	})
	if g1.Code != 200 {
		t.Fatalf("save active group: %d %s", g1.Code, g1.Body.String())
	}
	g2 := doJSON(t, h, "PUT", "/api/v1/admin/groups", adminToken, map[string]any{
		"name": "DisabledGroup", "action": "PROXY", "enabled": false, "locked": false,
		"entries": []map[string]any{
			{"kind": "domain", "pattern": "disabled-group.com", "enabled": true},
		},
	})
	if g2.Code != 200 {
		t.Fatalf("save disabled group: %d %s", g2.Code, g2.Body.String())
	}

	// User-scoped shared group with ip_cidr -> LOCAL_DIRECT.
	gUser := doJSON(t, h, "PUT", "/api/v1/admin/groups", adminToken, map[string]any{
		"userId": user.ID, "name": "DirectCIDR", "action": "LOCAL_DIRECT", "enabled": true, "locked": false,
		"entries": []map[string]any{
			{"kind": "ip_cidr", "pattern": "203.0.113.0/24", "enabled": true},
		},
	})
	if gUser.Code != 200 {
		t.Fatalf("save user group: %d %s", gUser.Code, gUser.Body.String())
	}

	// User-scoped and process rules.
	for _, r := range []map[string]any{
		{"userId": user.ID, "kind": "domain", "pattern": "home-only.example.com", "action": "SERVER_DIRECT", "enabled": true},
		{"userId": "", "kind": "suffix", "pattern": "ads.example.net", "action": "BLOCK", "enabled": true},
		{"userId": user.ID, "kind": "process", "pattern": "slack.exe", "action": "PROXY", "enabled": true},
	} {
		rec := doJSON(t, h, "PUT", "/api/v1/admin/rules", adminToken, r)
		if rec.Code != 200 {
			t.Fatalf("save rule %v: %d %s", r, rec.Code, rec.Body.String())
		}
	}

	invRec := doJSON(t, h, "POST", "/api/v1/admin/invites", adminToken, map[string]any{
		"userId": user.ID, "label": "iPhone 16", "universal": true, "linkType": "permanent",
	})
	if invRec.Code != 201 {
		t.Fatalf("create invite: %d %s", invRec.Code, invRec.Body.String())
	}
	var inv struct {
		ID     string `json:"id"`
		SubURL string `json:"subUrl"`
	}
	_ = json.Unmarshal(invRec.Body.Bytes(), &inv)
	subToken := extractSubToken(t, inv.SubURL)

	// Fetch subscription config with default final=direct.
	req := httptest.NewRequest("GET", "/api/sub/singbox?token="+url.QueryEscape(subToken), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET /api/sub/singbox failed: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("unexpected Content-Type: %q", ct)
	}
	if interval := rec.Header().Get("Profile-Update-Interval"); interval != "1" {
		t.Fatalf("unexpected Profile-Update-Interval: %q", interval)
	}
	if disp := rec.Header().Get("Content-Disposition"); disp != `attachment; filename="HomeProxy.json"` {
		t.Fatalf("unexpected Content-Disposition: %q", disp)
	}

	singboxCheckConfig(t, rec.Body.Bytes())

	var cfg struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		DNS       struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
			Final   string           `json:"final"`
		} `json:"dns"`
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("unmarshal singbox config: %v", err)
	}
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0]["type"] != "tun" ||
		cfg.Inbounds[0]["auto_route"] != true || cfg.Inbounds[0]["strict_route"] != true || cfg.Inbounds[0]["stack"] != "system" {
		t.Fatalf("unexpected tun inbound: %#v", cfg.Inbounds)
	}
	if cfg.Route.Final != "direct" {
		t.Fatalf("expected default route.final=direct, got %q", cfg.Route.Final)
	}

	tags := map[string]string{}
	var selectorOutbounds []any
	for _, out := range cfg.Outbounds {
		tag, _ := out["tag"].(string)
		typ, _ := out["type"].(string)
		tags[tag] = typ
		if typ == "selector" {
			selectorOutbounds, _ = out["outbounds"].([]any)
		}
	}
	for _, want := range []string{"EU-Node", "US-Node", "HomeProxy Server", "homeproxy-server-direct", "proxy", "direct", "block"} {
		if _, ok := tags[want]; !ok {
			t.Fatalf("missing outbound %q in %v", want, tags)
		}
	}
	if len(selectorOutbounds) != 3 {
		t.Fatalf("expected 3 selector outbounds (2 proxies + HomeProxy Server), got %v", selectorOutbounds)
	}

	bodyStr := rec.Body.String()
	for _, mustHave := range []string{"chatgpt.com", "openai.com", "home-only.example.com", "203.0.113.0/24", "ads.example.net", "fakeip", "hijack-dns"} {
		if !strings.Contains(bodyStr, mustHave) {
			t.Fatalf("expected %q in generated config", mustHave)
		}
	}
	for _, mustNotHave := range []string{"disabled-entry.com", "disabled-group.com", "slack.exe"} {
		if strings.Contains(bodyStr, mustNotHave) {
			t.Fatalf("unexpected %q in generated config", mustNotHave)
		}
	}

	// Verify state reflects subActive=true, platform=ios, status=connected and no encrypted blob leak.
	afterState := doJSON(t, h, "GET", "/api/v1/admin/state", adminToken, nil)
	if afterState.Code != 200 || strings.Contains(afterState.Body.String(), "subTokenEnc") {
		t.Fatalf("unexpected admin state: %d %s", afterState.Code, afterState.Body.String())
	}
	var parsedAfter struct {
		Devices []map[string]any `json:"devices"`
	}
	_ = json.Unmarshal(afterState.Body.Bytes(), &parsedAfter)
	if len(parsedAfter.Devices) != 1 || parsedAfter.Devices[0]["subActive"] != true ||
		parsedAfter.Devices[0]["platform"] != "ios" || parsedAfter.Devices[0]["status"] != "connected" ||
		parsedAfter.Devices[0]["subUrl"] != inv.SubURL {
		t.Fatalf("unexpected device state after subscription fetch: %#v", parsedAfter.Devices)
	}

	// Verify final=proxy query option.
	reqProxy := httptest.NewRequest("GET", "/api/sub/singbox?final=proxy&token="+url.QueryEscape(subToken), nil)
	recProxy := httptest.NewRecorder()
	h.ServeHTTP(recProxy, reqProxy)
	if recProxy.Code != 200 {
		t.Fatalf("GET /api/sub/singbox?final=proxy failed: %d", recProxy.Code)
	}
	singboxCheckConfig(t, recProxy.Body.Bytes())
	var cfgProxy struct {
		Route struct{ Final string `json:"final"` } `json:"route"`
	}
	_ = json.Unmarshal(recProxy.Body.Bytes(), &cfgProxy)
	if cfgProxy.Route.Final != "proxy" {
		t.Fatalf("expected route.final=proxy, got %q", cfgProxy.Route.Final)
	}
}

func TestSingboxSubscriptionRejectsRevokedSuspendedExpiredAndInvalidTokens(t *testing.T) {
	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	h := s.handler()

	// Missing and unknown tokens must return 403.
	for _, target := range []string{
		"/api/sub/singbox",
		"/api/sub/singbox?token=not-valid",
		"/api/sub/singbox?token=" + randomToken(),
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
		if rec.Code != 403 {
			t.Fatalf("GET %s: expected 403, got %d", target, rec.Code)
		}
	}

	invRec := doJSON(t, h, "POST", "/api/v1/admin/invites", adminToken, map[string]any{
		"label": "iPhone", "universal": true, "linkType": "permanent",
	})
	var inv struct {
		ID     string `json:"id"`
		SubURL string `json:"subUrl"`
	}
	_ = json.Unmarshal(invRec.Body.Bytes(), &inv)
	subToken := extractSubToken(t, inv.SubURL)

	// Suspend access -> 403.
	if rec := doJSON(t, h, "PUT", "/api/v1/admin/devices/"+inv.ID+"/access", adminToken, map[string]any{"accessEnabled": false}); rec.Code != 204 {
		t.Fatalf("suspend device: %d", rec.Code)
	}
	subRec := httptest.NewRecorder()
	h.ServeHTTP(subRec, httptest.NewRequest("GET", "/api/sub/singbox?token="+url.QueryEscape(subToken), nil))
	if subRec.Code != 403 {
		t.Fatalf("suspended device sub: expected 403, got %d", subRec.Code)
	}

	// Re-enable -> 200.
	if rec := doJSON(t, h, "PUT", "/api/v1/admin/devices/"+inv.ID+"/access", adminToken, map[string]any{"accessEnabled": true}); rec.Code != 204 {
		t.Fatalf("enable device: %d", rec.Code)
	}
	subRec = httptest.NewRecorder()
	h.ServeHTTP(subRec, httptest.NewRequest("GET", "/api/sub/singbox?token="+url.QueryEscape(subToken), nil))
	if subRec.Code != 200 {
		t.Fatalf("re-enabled device sub: expected 200, got %d", subRec.Code)
	}

	// Expire access -> 403.
	if _, err := s.db.Exec("UPDATE devices SET access_expires=? WHERE id=?", time.Now().Unix()-60, inv.ID); err != nil {
		t.Fatal(err)
	}
	subRec = httptest.NewRecorder()
	h.ServeHTTP(subRec, httptest.NewRequest("GET", "/api/sub/singbox?token="+url.QueryEscape(subToken), nil))
	if subRec.Code != 403 {
		t.Fatalf("expired device sub: expected 403, got %d", subRec.Code)
	}

	// Restore expiry, then revoke -> 403 on subscription, 409 on sub-link issue.
	if _, err := s.db.Exec("UPDATE devices SET access_expires=0 WHERE id=?", inv.ID); err != nil {
		t.Fatal(err)
	}
	if rec := doJSON(t, h, "DELETE", "/api/v1/admin/devices/"+inv.ID, adminToken, nil); rec.Code != 204 {
		t.Fatalf("revoke device: %d", rec.Code)
	}
	subRec = httptest.NewRecorder()
	h.ServeHTTP(subRec, httptest.NewRequest("GET", "/api/sub/singbox?token="+url.QueryEscape(subToken), nil))
	if subRec.Code != 403 {
		t.Fatalf("revoked device sub: expected 403, got %d", subRec.Code)
	}
	ensureRec := doJSON(t, h, "POST", "/api/v1/admin/devices/"+inv.ID+"/sub-link", adminToken, nil)
	if ensureRec.Code != 409 {
		t.Fatalf("ensure sub-link for revoked device: expected 409, got %d", ensureRec.Code)
	}
}

func TestEnsureDeviceSubLinkBackfillsLegacyDevice(t *testing.T) {
	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	h := s.handler()

	if _, err := s.db.Exec(`
		INSERT INTO users(id,name,can_edit_global) VALUES('u1','Legacy',0);
		INSERT INTO devices(id,user_id,label,transport,expires,primary_id,direct_id,universal,link_type,access_enabled)
		VALUES('d-legacy','u1','LegacyPhone','agent',0,'p-leg','d-leg',1,'permanent',1);
	`); err != nil {
		t.Fatal(err)
	}

	rec1 := doJSON(t, h, "POST", "/api/v1/admin/devices/d-legacy/sub-link", adminToken, nil)
	if rec1.Code != 200 {
		t.Fatalf("backfill sub-link: %d %s", rec1.Code, rec1.Body.String())
	}
	var resp1 struct{ SubURL string `json:"subUrl"` }
	_ = json.Unmarshal(rec1.Body.Bytes(), &resp1)

	rec2 := doJSON(t, h, "POST", "/api/v1/admin/devices/d-legacy/sub-link", adminToken, nil)
	var resp2 struct{ SubURL string `json:"subUrl"` }
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	if resp1.SubURL == "" || resp1.SubURL != resp2.SubURL {
		t.Fatalf("expected stable subUrl across repeated calls, got %q then %q", resp1.SubURL, resp2.SubURL)
	}

	subToken := extractSubToken(t, resp1.SubURL)
	subRec := httptest.NewRecorder()
	h.ServeHTTP(subRec, httptest.NewRequest("GET", "/api/sub/singbox?token="+url.QueryEscape(subToken), nil))
	if subRec.Code != 200 {
		t.Fatalf("GET backfilled sub: %d %s", subRec.Code, subRec.Body.String())
	}
}
