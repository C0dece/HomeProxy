package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T, probeURL string) (*server, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := openStore(filepath.Join(dir, "store.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	box, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	rawReality := make([]byte, 40)
	if _, err := rand.Read(rawReality); err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(rawReality[8:])
	if err != nil {
		t.Fatal(err)
	}
	singBox := filepath.Join("..", "..", ".tools", "sing-box-1.14.4-windows-amd64", "sing-box.exe")
	if _, err := os.Stat(singBox); err != nil {
		t.Fatalf("sing-box binary not found at %s: %v", singBox, err)
	}
	controlAddr, err := loopbackAddress()
	if err != nil {
		t.Fatal(err)
	}
	tunnelAddr, err := loopbackAddress()
	if err != nil {
		t.Fatal(err)
	}
	_, tunnelPortStr, _ := strings.Cut(tunnelAddr, ":")
	tunnelPort, _ := strconv.Atoi(tunnelPortStr)
	token := randomToken()
	s := &server{
		cfg: settings{
			PublicURL:     "http://127.0.0.1:8443",
			SingBox:       singBox,
			TunnelListen:  tunnelAddr,
			TunnelHost:    "127.0.0.1",
			TunnelPort:    tunnelPort,
			ServerName:    "localhost",
			HandshakeHost: "127.0.0.1",
			HandshakePort: 443,
			ProbeURL:      probeURL,
			LoopbackDev:   true,
		},
		db:        db,
		secrets:   box,
		adminHash: sha256.Sum256([]byte(token)),
		key:       priv,
		shortID:   hex.EncodeToString(rawReality[:8]),
		core: engine{
			binary:  singBox,
			control: controlAddr,
			token:   randomToken(),
		},
	}
	t.Cleanup(func() {
		s.write.Lock()
		defer s.write.Unlock()
		s.core.stop()
	})
	return s, token
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMigrateV2ToV3PreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := migrations.ReadFile("migrations/001.sql")
	if err != nil {
		t.Fatal(err)
	}
	m2, err := migrations.ReadFile("migrations/002.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(m1) + string(m2) + "PRAGMA user_version=2;"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO users(id,name) VALUES('u1','Alice');
		INSERT INTO proxies(id,name,host,port,tls,credentials) VALUES('p1','Upstream','10.0.0.1',8080,0,X'0102');
		INSERT INTO routes(user_id,proxy_id,priority) VALUES('u1','p1',0);
		INSERT INTO devices(id,user_id,label,transport,expires,primary_id,direct_id) VALUES('d1','u1','Laptop','agent',999999,'p-id','d-id');
		INSERT INTO rules(id,user_id,pattern,kind,action,locked,revision) VALUES('r1','u1','example.com','domain','PROXY',0,5);
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
	var headers string
	if err := migrated.QueryRow("SELECT headers FROM proxies WHERE id='p1'").Scan(&headers); err != nil || headers != "{}" {
		t.Fatalf("expected headers='{}', got %q (err=%v)", headers, err)
	}
	var enabled int
	var pattern string
	if err := migrated.QueryRow("SELECT pattern,enabled FROM rules WHERE id='r1'").Scan(&pattern, &enabled); err != nil || pattern != "example.com" || enabled != 1 {
		t.Fatalf("expected preserved rule with enabled=1, got %q %d (err=%v)", pattern, enabled, err)
	}
	var userCount, deviceCount int
	_ = migrated.QueryRow("SELECT count(*) FROM users").Scan(&userCount)
	_ = migrated.QueryRow("SELECT count(*) FROM devices").Scan(&deviceCount)
	if userCount != 1 || deviceCount != 1 {
		t.Fatalf("lost existing rows: users=%d devices=%d", userCount, deviceCount)
	}
	if _, err := migrated.Exec("INSERT INTO service_groups(id,name,action,enabled,locked,revision) VALUES('g1','Test','PROXY',1,0,1)"); err != nil {
		t.Fatalf("service_groups table missing or broken: %v", err)
	}
}

func TestProxyHeadersAndCoreConfig(t *testing.T) {
	var seenHeader string
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get("X-Proxy-Tag")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxySrv.Close()
	parsed, _ := url.Parse(proxySrv.URL)
	host := parsed.Hostname()
	port, _ := strconv.Atoi(parsed.Port())

	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	h := s.handler()

	userRec := doJSON(t, h, "POST", "/api/v1/admin/users", adminToken, map[string]any{"name": "User1"})
	if userRec.Code != 201 {
		t.Fatalf("create user: %d %s", userRec.Code, userRec.Body.String())
	}
	var userResp struct{ ID string }
	_ = json.Unmarshal(userRec.Body.Bytes(), &userResp)

	badRec := doJSON(t, h, "PUT", "/api/v1/admin/proxies", adminToken, map[string]any{
		"name": "Bad", "host": host, "port": port, "tls": false,
		"headers": map[string]string{"Host": "evil.example"},
	})
	if badRec.Code != 400 {
		t.Fatalf("expected 400 for forbidden Host header, got %d", badRec.Code)
	}

	okRec := doJSON(t, h, "PUT", "/api/v1/admin/proxies", adminToken, map[string]any{
		"name": "WithHeaders", "host": host, "port": port, "tls": false,
		"headers": map[string]string{"X-Proxy-Tag": "homeproxy-hdr"},
	})
	if okRec.Code != 200 {
		t.Fatalf("save proxy: %d %s", okRec.Code, okRec.Body.String())
	}
	if seenHeader != "homeproxy-hdr" {
		t.Fatalf("probeProxy did not forward custom header, got %q", seenHeader)
	}
	var proxyResp struct{ ID string }
	_ = json.Unmarshal(okRec.Body.Bytes(), &proxyResp)

	routesRec := doJSON(t, h, "PUT", "/api/v1/admin/routes", adminToken, map[string]any{
		"userId": userResp.ID, "proxyIds": []string{proxyResp.ID},
	})
	if routesRec.Code != 204 {
		t.Fatalf("routes: %d", routesRec.Code)
	}
	invRec := doJSON(t, h, "POST", "/api/v1/admin/invites", adminToken, map[string]any{
		"userId": userResp.ID, "label": "WinPC", "transport": "agent",
	})
	var invResp struct{ Link string }
	_ = json.Unmarshal(invRec.Body.Bytes(), &invResp)
	devKey := randomToken()
	connRec := doJSON(t, h, "POST", "/api/v1/connect", "", map[string]any{
		"token": strings.Split(invResp.Link, "#")[1], "deviceKey": devKey, "transport": "agent",
	})
	if connRec.Code != 201 {
		t.Fatalf("connect: %d %s", connRec.Code, connRec.Body.String())
	}

	rawCfg, err := s.coreConfig(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawCfg), `"X-Proxy-Tag":"homeproxy-hdr"`) {
		t.Fatalf("coreConfig missing proxy headers: %s", string(rawCfg))
	}

	stateRec := doJSON(t, h, "GET", "/api/v1/admin/state", adminToken, nil)
	if stateRec.Code != 200 || !strings.Contains(stateRec.Body.String(), `"X-Proxy-Tag":"homeproxy-hdr"`) {
		t.Fatalf("state missing decoded headers: %d %s", stateRec.Code, stateRec.Body.String())
	}
}

func TestServiceGroupsAndPlatformFiltering(t *testing.T) {
	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	h := s.handler()

	userRec := doJSON(t, h, "POST", "/api/v1/admin/users", adminToken, map[string]any{"name": "Bob"})
	var userResp struct{ ID string }
	_ = json.Unmarshal(userRec.Body.Bytes(), &userResp)

	register := func(label, transport string) string {
		inv := doJSON(t, h, "POST", "/api/v1/admin/invites", adminToken, map[string]any{
			"userId": userResp.ID, "label": label, "transport": transport,
		})
		var invResp struct{ Link string }
		_ = json.Unmarshal(inv.Body.Bytes(), &invResp)
		key := randomToken()
		rec := doJSON(t, h, "POST", "/api/v1/connect", "", map[string]any{
			"token": strings.Split(invResp.Link, "#")[1], "deviceKey": key, "transport": transport,
		})
		if rec.Code != 201 {
			t.Fatalf("connect %s: %d", label, rec.Code)
		}
		return key
	}
	winKey := register("Win", "agent")
	browserKey := register("Ext", "browser")

	grpRec := doJSON(t, h, "PUT", "/api/v1/admin/groups", adminToken, map[string]any{
		"name": "ChatGPT", "action": "PROXY", "enabled": true, "locked": true,
		"entries": []map[string]string{
			{"kind": "domain", "pattern": "chatgpt.com"},
			{"kind": "suffix", "pattern": "openai.com"},
			{"kind": "ip_cidr", "pattern": "104.18.0.1"},
			{"kind": "process", "pattern": "chatgpt.exe"},
			{"kind": "package", "pattern": "com.openai.chatgpt"},
		},
	})
	if grpRec.Code != 200 {
		t.Fatalf("saveGroup: %d %s", grpRec.Code, grpRec.Body.String())
	}
	var grp serviceGroup
	_ = json.Unmarshal(grpRec.Body.Bytes(), &grp)

	disabledRec := doJSON(t, h, "PUT", "/api/v1/admin/groups", adminToken, map[string]any{
		"name": "DisabledSvc", "action": "BLOCK", "enabled": false,
		"entries": []map[string]string{{"kind": "domain", "pattern": "disabled.example"}},
	})
	if disabledRec.Code != 200 {
		t.Fatalf("save disabled group: %d", disabledRec.Code)
	}

	kindsOf := func(token, path string) map[string]bool {
		rec := doJSON(t, h, "GET", path, token, nil)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		var cfg struct {
			Groups []serviceGroup `json:"groups"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &cfg)
		if len(cfg.Groups) != 1 || cfg.Groups[0].Name != "ChatGPT" {
			t.Fatalf("expected only enabled group ChatGPT on %s, got %+v", path, cfg.Groups)
		}
		out := map[string]bool{}
		for _, e := range cfg.Groups[0].Entries {
			out[e.Kind] = true
		}
		return out
	}

	winKinds := kindsOf(winKey, "/api/v1/config")
	if !winKinds["domain"] || !winKinds["suffix"] || !winKinds["ip_cidr"] || !winKinds["process"] || winKinds["package"] {
		t.Fatalf("unexpected Windows kinds: %+v", winKinds)
	}
	androidKinds := kindsOf(winKey, "/api/v1/config?platform=android")
	if !androidKinds["domain"] || !androidKinds["suffix"] || !androidKinds["ip_cidr"] || !androidKinds["package"] || androidKinds["process"] {
		t.Fatalf("unexpected Android kinds: %+v", androidKinds)
	}
	browserKinds := kindsOf(browserKey, "/api/v1/config")
	if !browserKinds["domain"] || !browserKinds["suffix"] || browserKinds["ip_cidr"] || browserKinds["process"] || browserKinds["package"] {
		t.Fatalf("unexpected Browser kinds: %+v", browserKinds)
	}

	// Conflict check
	conflict := doJSON(t, h, "PUT", "/api/v1/admin/groups", adminToken, map[string]any{
		"id": grp.ID, "name": "ChatGPT", "action": "BLOCK", "enabled": true, "revision": grp.Revision - 1,
		"entries": []map[string]string{},
	})
	if conflict.Code != 409 {
		t.Fatalf("expected 409 group_conflict, got %d", conflict.Code)
	}

	delRec := doJSON(t, h, "DELETE", "/api/v1/admin/groups/"+grp.ID, adminToken, nil)
	if delRec.Code != 204 {
		t.Fatalf("delete group: %d", delRec.Code)
	}
}

func TestRuleEnabledDeletePersonalAndOnlineDevices(t *testing.T) {
	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")

	// Mock Clash API /connections for active device tracking
	var devID string
	clash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connections" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{"metadata": map[string]string{"user": devID + "-proxy"}},
				},
			})
			return
		}
		w.WriteHeader(404)
	}))
	defer clash.Close()
	h := s.handler()
	userRec := doJSON(t, h, "POST", "/api/v1/admin/users", adminToken, map[string]any{"name": "Carol"})
	var userResp struct{ ID string }
	_ = json.Unmarshal(userRec.Body.Bytes(), &userResp)
	invRec := doJSON(t, h, "POST", "/api/v1/admin/invites", adminToken, map[string]any{
		"userId": userResp.ID, "label": "Phone", "transport": "agent",
	})
	var invResp struct{ Link string }
	_ = json.Unmarshal(invRec.Body.Bytes(), &invResp)
	devKey := randomToken()
	connRec := doJSON(t, h, "POST", "/api/v1/connect", "", map[string]any{
		"token": strings.Split(invResp.Link, "#")[1], "deviceKey": devKey, "transport": "agent",
	})
	if connRec.Code != 201 {
		t.Fatalf("connect: %d %s", connRec.Code, connRec.Body.String())
	}
	var connResp struct{ DeviceID string }
	_ = json.Unmarshal(connRec.Body.Bytes(), &connResp)
	devID = connResp.DeviceID

	clashURL, _ := url.Parse(clash.URL)
	s.core.control = clashURL.Host

	// Personal rule create, disable, and delete
	pRuleRec := doJSON(t, h, "PUT", "/api/v1/personal-rules", devKey, map[string]any{
		"pattern": "my.example", "kind": "domain", "action": "PROXY", "enabled": false,
	})
	if pRuleRec.Code != 200 {
		t.Fatalf("personal rule: %d %s", pRuleRec.Code, pRuleRec.Body.String())
	}
	var pRule rule
	_ = json.Unmarshal(pRuleRec.Body.Bytes(), &pRule)
	if pRule.Enabled {
		t.Fatalf("expected enabled=false")
	}

	gRuleRec := doJSON(t, h, "PUT", "/api/v1/admin/rules", adminToken, map[string]any{
		"pattern": "global.example", "kind": "domain", "action": "BLOCK",
	})
	var gRule rule
	_ = json.Unmarshal(gRuleRec.Body.Bytes(), &gRule)
	if !gRule.Enabled {
		t.Fatalf("expected default enabled=true when omitted")
	}

	// Device cannot delete global rule
	if rec := doJSON(t, h, "DELETE", "/api/v1/personal-rules/"+gRule.ID, devKey, nil); rec.Code != 403 {
		t.Fatalf("expected 403 deleting global rule, got %d", rec.Code)
	}
	// Device can delete own personal rule
	if rec := doJSON(t, h, "DELETE", "/api/v1/personal-rules/"+pRule.ID, devKey, nil); rec.Code != 204 {
		t.Fatalf("expected 204 deleting personal rule, got %d", rec.Code)
	}

	// Simulate stale seen, verify /api/v1/config updates seen and /state reports online via activeConnections
	if _, err := s.db.Exec("UPDATE devices SET seen=? WHERE id=?", time.Now().Unix()-300, devID); err != nil {
		t.Fatal(err)
	}
	cfgRec := doJSON(t, h, "GET", "/api/v1/config", devKey, nil)
	if cfgRec.Code != 200 {
		t.Fatalf("config: %d", cfgRec.Code)
	}
	etag := cfgRec.Header().Get("ETag")
	if rec304 := doJSON(t, h, "GET", "/api/v1/config", devKey, nil); rec304.Code != 200 {
		t.Fatalf("expected 200 without etag, got %d", rec304.Code)
	}
	req304 := httptest.NewRequest("GET", "/api/v1/config", nil)
	req304.Header.Set("Authorization", "Bearer "+devKey)
	req304.Header.Set("If-None-Match", etag)
	rec304 := httptest.NewRecorder()
	h.ServeHTTP(rec304, req304)
	if rec304.Code != 304 {
		t.Fatalf("expected 304 with etag, got %d", rec304.Code)
	}

	stateRec := doJSON(t, h, "GET", "/api/v1/admin/state", adminToken, nil)
	if stateRec.Code != 200 {
		t.Fatalf("state: %d", stateRec.Code)
	}
	var st struct {
		Devices []struct {
			ID                string `json:"id"`
			Online            bool   `json:"online"`
			ActiveConnections int    `json:"activeConnections"`
			Seen              int64  `json:"seen"`
		} `json:"devices"`
	}
	_ = json.Unmarshal(stateRec.Body.Bytes(), &st)
	if len(st.Devices) != 1 || !st.Devices[0].Online || st.Devices[0].ActiveConnections != 1 || st.Devices[0].Seen < time.Now().Unix()-10 {
		t.Fatalf("unexpected device online state: %+v", st.Devices)
	}
}
