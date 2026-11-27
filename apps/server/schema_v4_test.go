package main

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrateV3ToV4PreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"001.sql", "002.sql", "003.sql"} {
		sqlBytes, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version=3;"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO users(id,name) VALUES('u1','Alice');
		INSERT INTO devices(id,user_id,label,transport,expires,primary_id,direct_id) VALUES('d1','u1','Laptop','agent',999999,'p-id','d-id');
		INSERT INTO service_groups(id,name,action,enabled,locked,revision) VALUES('g1','ChatGPT','PROXY',1,0,2);
		INSERT INTO service_group_entries(id,group_id,kind,pattern) VALUES('e1','g1','domain','chatgpt.com');
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
	var canEdit int
	if err := migrated.QueryRow("SELECT can_edit_global FROM users WHERE id='u1'").Scan(&canEdit); err != nil || canEdit != 0 {
		t.Fatalf("expected default can_edit_global=0, got %d (err=%v)", canEdit, err)
	}
	var entryEnabled int
	if err := migrated.QueryRow("SELECT enabled FROM service_group_entries WHERE id='e1'").Scan(&entryEnabled); err != nil || entryEnabled != 1 {
		t.Fatalf("expected default entry enabled=1, got %d (err=%v)", entryEnabled, err)
	}
	var linkType string
	var accessEnabled int
	if err := migrated.QueryRow("SELECT link_type,access_enabled FROM devices WHERE id='d1'").Scan(&linkType, &accessEnabled); err != nil || linkType != "temp" || accessEnabled != 1 {
		t.Fatalf("expected migrated device defaults, got %q %d (err=%v)", linkType, accessEnabled, err)
	}
}

func TestUniversalInvitesAccessControlAndSharedGroups(t *testing.T) {
	s, adminToken := testServer(t, "http://127.0.0.1:80/probe")
	h := s.handler()

	// Create universal permanent invite when no users exist yet (auto-creates default user).
	permInv := doJSON(t, h, "POST", "/api/v1/admin/invites", adminToken, map[string]any{
		"label": "Планшет", "linkType": "permanent", "canEditGlobal": true, "universal": true,
	})
	if permInv.Code != 201 {
		t.Fatalf("permanent invite: %d %s", permInv.Code, permInv.Body.String())
	}
	var invResp struct {
		ID       string `json:"id"`
		Link     string `json:"link"`
		LinkType string `json:"linkType"`
		Expires  int64  `json:"expires"`
	}
	_ = json.Unmarshal(permInv.Body.Bytes(), &invResp)
	if invResp.LinkType != "permanent" || invResp.Expires != 0 {
		t.Fatalf("unexpected permanent invite response: %+v", invResp)
	}

	// Universal invite can connect as browser or agent.
	devKey := randomToken()
	connRec := doJSON(t, h, "POST", "/api/v1/connect", "", map[string]any{
		"token": strings.Split(invResp.Link, "#")[1], "deviceKey": devKey, "transport": "agent",
	})
	if connRec.Code != 201 {
		t.Fatalf("universal connect: %d %s", connRec.Code, connRec.Body.String())
	}

	// Client with canEditGlobal=true can create and update shared groups.
	cfgRec := doJSON(t, h, "GET", "/api/v1/config", devKey, nil)
	if cfgRec.Code != 200 {
		t.Fatalf("config: %d", cfgRec.Code)
	}
	var cfg struct {
		CanEditGlobal bool `json:"canEditGlobal"`
	}
	_ = json.Unmarshal(cfgRec.Body.Bytes(), &cfg)
	if !cfg.CanEditGlobal {
		t.Fatalf("expected canEditGlobal=true in /api/v1/config")
	}

	saveGrp := doJSON(t, h, "PUT", "/api/v1/shared-groups", devKey, map[string]any{
		"name": "SharedApp", "action": "PROXY", "enabled": true,
		"entries": []map[string]any{
			{"kind": "domain", "pattern": "app.example", "enabled": true},
			{"kind": "domain", "pattern": "disabled.example", "enabled": false},
		},
	})
	if saveGrp.Code != 200 {
		t.Fatalf("client save group: %d %s", saveGrp.Code, saveGrp.Body.String())
	}
	var grp serviceGroup
	_ = json.Unmarshal(saveGrp.Body.Bytes(), &grp)
	if len(grp.Entries) != 2 || grp.Entries[0].Enabled == grp.Entries[1].Enabled {
		t.Fatalf("expected preserved entry enabled flags, got %+v", grp.Entries)
	}

	// Suspend and resume device access.
	susp := doJSON(t, h, "PUT", "/api/v1/admin/devices/"+invResp.ID+"/access", adminToken, map[string]any{"accessEnabled": false})
	if susp.Code != 204 {
		t.Fatalf("suspend access: %d", susp.Code)
	}
	if rec := doJSON(t, h, "GET", "/api/v1/config", devKey, nil); rec.Code != 401 {
		t.Fatalf("expected 401 while suspended, got %d", rec.Code)
	}
	resm := doJSON(t, h, "PUT", "/api/v1/admin/devices/"+invResp.ID+"/access", adminToken, map[string]any{"accessEnabled": true})
	if resm.Code != 204 {
		t.Fatalf("resume access: %d", resm.Code)
	}
	if rec := doJSON(t, h, "GET", "/api/v1/config", devKey, nil); rec.Code != 200 {
		t.Fatalf("expected 200 after resume, got %d", rec.Code)
	}

	// Read-only device cannot edit or delete shared groups.
	roUserRec := doJSON(t, h, "POST", "/api/v1/admin/users", adminToken, map[string]any{"name": "Guest"})
	var roUser struct{ ID string }
	_ = json.Unmarshal(roUserRec.Body.Bytes(), &roUser)
	roInvRec := doJSON(t, h, "POST", "/api/v1/admin/invites", adminToken, map[string]any{
		"userId": roUser.ID, "label": "Гость", "linkType": "temp", "durationMinutes": 60, "canEditGlobal": false,
	})
	var roInv struct {
		ID   string `json:"id"`
		Link string `json:"link"`
	}
	_ = json.Unmarshal(roInvRec.Body.Bytes(), &roInv)
	roKey := randomToken()
	if rec := doJSON(t, h, "POST", "/api/v1/connect", "", map[string]any{
		"token": strings.Split(roInv.Link, "#")[1], "deviceKey": roKey, "transport": "browser",
	}); rec.Code != 201 {
		t.Fatalf("connect ro: %d", rec.Code)
	}
	if rec := doJSON(t, h, "DELETE", "/api/v1/shared-groups/"+grp.ID, roKey, nil); rec.Code != 403 {
		t.Fatalf("expected 403 for read-only client deleting shared group, got %d", rec.Code)
	}

	// User permissions update grants access.
	permRec := doJSON(t, h, "PUT", "/api/v1/admin/users/"+roUser.ID+"/permissions", adminToken, map[string]any{"canEditGlobal": true})
	if permRec.Code != 200 {
		t.Fatalf("permissions update: %d", permRec.Code)
	}
	if rec := doJSON(t, h, "DELETE", "/api/v1/shared-groups/"+grp.ID, roKey, nil); rec.Code != 204 {
		t.Fatalf("expected 204 after granting user permission, got %d", rec.Code)
	}

	// Revoke + expire -> history cleanup.
	if rec := doJSON(t, h, "DELETE", "/api/v1/admin/devices/"+invResp.ID, adminToken, nil); rec.Code != 204 {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if _, err := s.db.Exec("UPDATE devices SET access_expires=? WHERE id=?", time.Now().Unix()-10, roInv.ID); err != nil {
		t.Fatal(err)
	}
	if rec := doJSON(t, h, "GET", "/api/v1/config", roKey, nil); rec.Code != 401 {
		t.Fatalf("expected 401 for expired link, got %d", rec.Code)
	}
	if rec := doJSON(t, h, "DELETE", "/api/v1/admin/devices/history", adminToken, nil); rec.Code != 204 {
		t.Fatalf("clear history: %d", rec.Code)
	}
	stateRec := doJSON(t, h, "GET", "/api/v1/admin/state", adminToken, nil)
	var st struct {
		Devices []struct{ ID string } `json:"devices"`
	}
	_ = json.Unmarshal(stateRec.Body.Bytes(), &st)
	if len(st.Devices) != 0 {
		t.Fatalf("expected empty devices after clearing history, got %+v", st.Devices)
	}
}
