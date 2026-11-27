package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

type apiError struct {
	status int
	code   string
}

func (e apiError) Error() string { return e.code }

func report(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var api apiError
	if errors.As(err, &api) {
		fail(w, api.status, api.code)
	} else if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "not_found")
	} else {
		internal(w, err)
	}
	return true
}

func revision(q queryer) (int64, error) {
	var rev int64
	err := q.QueryRow("SELECT revision FROM state").Scan(&rev)
	return rev, err
}

// Mutations serialize with core replacement. Readers see the configuration
// only after the candidate has started and the transaction has committed.
func (s *server) mutate(event string, restart bool, change func(*sql.Tx, int64) error) error {
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rev, err := revision(tx)
	if err != nil {
		return err
	}
	if err = change(tx, rev+1); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE state SET revision=?", rev+1); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO audit(revision,event,time) VALUES(?,?,?)", rev+1, event, time.Now().Unix()); err != nil {
		return err
	}
	old := s.core.current
	if restart {
		next, err := s.coreConfig(tx)
		if err != nil {
			return err
		}
		if string(next) != string(old) {
			if err := s.core.replace(next); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil && restart {
		s.core.stop()
		s.core.current = old
		s.core.launch(old)
	}
	return err
}

func ensure(q queryer, statement string, args ...any) error {
	var found int
	return q.QueryRow(statement, args...).Scan(&found)
}

func affected(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := r.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *server) user(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name          string
		CanEditGlobal *bool
	}
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 100 {
		fail(w, 400, "invalid_name")
		return
	}
	id := r.PathValue("id")
	event := "user.updated"
	if id == "" {
		event = "user.created"
		id = uuid()
	}
	var canEditGlobal bool
	if input.CanEditGlobal != nil {
		canEditGlobal = *input.CanEditGlobal
	}
	err := s.mutate(event, false, func(tx *sql.Tx, _ int64) error {
		exists := ensure(tx, "SELECT 1 FROM users WHERE name=? AND id<>?", input.Name, id)
		if !errors.Is(exists, sql.ErrNoRows) {
			if exists != nil {
				return exists
			}
			return apiError{409, "name_taken"}
		}
		if event == "user.updated" {
			if input.CanEditGlobal != nil {
				return affected(tx.Exec("UPDATE users SET name=?,can_edit_global=? WHERE id=?", input.Name, canEditGlobal, id))
			}
			err := affected(tx.Exec("UPDATE users SET name=? WHERE id=?", input.Name, id))
			if err != nil {
				return err
			}
			return tx.QueryRow("SELECT can_edit_global=1 FROM users WHERE id=?", id).Scan(&canEditGlobal)
		}
		_, err := tx.Exec("INSERT INTO users(id,name,can_edit_global) VALUES(?,?,?)", id, input.Name, canEditGlobal)
		return err
	})
	if !report(w, err) {
		status := http.StatusOK
		if event == "user.created" {
			status = http.StatusCreated
		}
		send(w, status, obj{"id": id, "name": input.Name, "canEditGlobal": canEditGlobal})
	}
}

func (s *server) userPermissions(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CanEditGlobal bool
	}
	if !decode(w, r, &input) {
		return
	}
	id := r.PathValue("id")
	err := s.mutate("user.permissions", false, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("UPDATE users SET can_edit_global=? WHERE id=?", input.CanEditGlobal, id))
	})
	if !report(w, err) {
		send(w, 200, obj{"id": id, "canEditGlobal": input.CanEditGlobal})
	}
}

func (s *server) deleteUser(w http.ResponseWriter, r *http.Request) {
	err := s.mutate("user.deleted", true, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("DELETE FROM users WHERE id=?", r.PathValue("id")))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func validHeaders(headers map[string]string) (string, bool) {
	if len(headers) > 16 {
		return "", false
	}
	if len(headers) == 0 {
		return "{}", true
	}
	normalized := make(map[string]string, len(headers))
	for rawKey, val := range headers {
		key := strings.TrimSpace(rawKey)
		if key == "" || len(key) > 128 || len(val) > 1024 || strings.ContainsAny(val, "\r\n\x00") {
			return "", false
		}
		for i := 0; i < len(key); i++ {
			b := key[i]
			if b <= 0x20 || b >= 0x7f || b == ':' {
				return "", false
			}
		}
		lower := strings.ToLower(key)
		if lower == "host" || lower == "proxy-authorization" {
			return "", false
		}
		if _, dup := normalized[key]; dup {
			return "", false
		}
		normalized[key] = val
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func (s *server) probeProxy(ctx context.Context, p proxyInfo) bool {
	scheme := "http"
	if p.TLS {
		scheme = "https"
	}
	proxy := &url.URL{Scheme: scheme, Host: net.JoinHostPort(p.Host, fmt.Sprint(p.Port))}
	if p.Username != "" {
		proxy.User = url.UserPassword(p.Username, p.Password)
	}
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxy), DisableKeepAlives: true,
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	}
	if len(p.Headers) > 0 {
		hdr := make(http.Header, len(p.Headers))
		for k, v := range p.Headers {
			hdr.Set(k, v)
		}
		tr.ProxyConnectHeader = hdr
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "HEAD", s.cfg.ProbeURL, nil)
	if err != nil {
		return false
	}
	if len(p.Headers) > 0 && req.URL.Scheme == "http" {
		for k, v := range p.Headers {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (s *server) proxy(w http.ResponseWriter, r *http.Request) {
	var p proxyInfo
	if !decode(w, r, &p) {
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	headersJSON, headersOK := validHeaders(p.Headers)
	if p.Name == "" || len(p.Name) > 100 || !validHost(p.Host) || !validPort(p.Port) ||
		len(p.Username) > 256 || len(p.Password) > 1024 ||
		strings.ContainsAny(p.Username, ":\r\n") || (p.Username == "" && p.Password != "") || !headersOK {
		fail(w, 400, "invalid_proxy")
		return
	}
	if !s.probeProxy(r.Context(), p) {
		fail(w, 422, "proxy_unreachable")
		return
	}
	fresh := p.ID == ""
	if fresh {
		p.ID = uuid()
	}
	credentials, _ := json.Marshal([2]string{p.Username, p.Password})
	sealed := s.secrets.Seal(nil, nil, credentials, []byte(p.ID))
	err := s.mutate("proxy.saved", true, func(tx *sql.Tx, _ int64) error {
		exists := ensure(tx, "SELECT 1 FROM proxies WHERE name=? AND id<>?", p.Name, p.ID)
		if !errors.Is(exists, sql.ErrNoRows) {
			if exists != nil {
				return exists
			}
			return apiError{409, "name_taken"}
		}
		if fresh {
			_, err := tx.Exec("INSERT INTO proxies(id,name,host,port,tls,credentials,headers) VALUES(?,?,?,?,?,?,?)", p.ID, p.Name, p.Host, p.Port, p.TLS, sealed, headersJSON)
			return err
		}
		return affected(tx.Exec("UPDATE proxies SET name=?,host=?,port=?,tls=?,credentials=?,headers=? WHERE id=?", p.Name, p.Host, p.Port, p.TLS, sealed, headersJSON, p.ID))
	})
	if !report(w, err) {
		send(w, 200, obj{"id": p.ID})
	}
}

func (s *server) deleteProxy(w http.ResponseWriter, r *http.Request) {
	err := s.mutate("proxy.deleted", true, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("DELETE FROM proxies WHERE id=?", r.PathValue("id")))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func (s *server) routes(w http.ResponseWriter, r *http.Request) {
	var input struct {
		UserID   string
		ProxyIDs []string
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.ProxyIDs) > 16 {
		fail(w, 400, "too_many_proxies")
		return
	}
	err := s.mutate("routes.saved", true, func(tx *sql.Tx, _ int64) error {
		if err := ensure(tx, "SELECT 1 FROM users WHERE id=?", input.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM routes WHERE user_id=?", input.UserID); err != nil {
			return err
		}
		seen := map[string]bool{}
		for priority, id := range input.ProxyIDs {
			if seen[id] {
				return apiError{400, "duplicate_route"}
			}
			seen[id] = true
			if err := ensure(tx, "SELECT 1 FROM proxies WHERE id=?", id); err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO routes VALUES(?,?,?)", input.UserID, id, priority); err != nil {
				return err
			}
		}
		return nil
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func (s *server) invite(w http.ResponseWriter, r *http.Request) {
	var input struct {
		UserID, Label, Transport, LinkType string
		Minutes, DurationMinutes           int
		CanEditGlobal, Universal           bool
	}
	if !decode(w, r, &input) {
		return
	}
	input.Label = strings.TrimSpace(input.Label)
	if input.Label == "" || len(input.Label) > 100 {
		fail(w, 400, "invalid_invite")
		return
	}
	isUniversal := input.Universal || input.Transport == "" || input.Transport == "universal"
	transport := input.Transport
	if isUniversal {
		transport = "agent"
	} else if transport != "agent" && transport != "browser" {
		fail(w, 400, "invalid_invite")
		return
	}
	now := time.Now().Unix()
	linkType := input.LinkType
	var expiry, accessExpires, durationSec int64
	switch linkType {
	case "permanent":
		expiry = 0
		accessExpires = 0
		durationSec = 0
	case "temp":
		mins := input.DurationMinutes
		if mins == 0 {
			mins = input.Minutes
		}
		if mins < 1 || mins > 525600 {
			fail(w, 400, "invalid_invite")
			return
		}
		durationSec = int64(mins) * 60
		accessExpires = now + durationSec
		expiry = now + max(int64(15*60), durationSec)
	case "":
		linkType = "temp"
		if input.Minutes == 0 {
			input.Minutes = 15
		}
		if input.Minutes < 1 || input.Minutes > 60 {
			fail(w, 400, "invalid_invite")
			return
		}
		expiry = now + int64(input.Minutes)*60
	default:
		fail(w, 400, "invalid_invite")
		return
	}
	id, token := uuid(), randomToken()
	tokenHash := digest(token)
	subEnc := s.secrets.Seal(nil, nil, []byte(token), []byte(id))
	err := s.mutate("device.invited", false, func(tx *sql.Tx, _ int64) error {
		userID := input.UserID
		if userID == "" {
			err := tx.QueryRow("SELECT id FROM users ORDER BY name LIMIT 1").Scan(&userID)
			if errors.Is(err, sql.ErrNoRows) {
				userID = uuid()
				if _, err := tx.Exec("INSERT INTO users(id,name,can_edit_global) VALUES(?,'Основной',0)", userID); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
		} else if err := ensure(tx, "SELECT 1 FROM users WHERE id=?", userID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO devices(id,user_id,label,transport,invite_hash,expires,primary_id,direct_id,universal,can_edit_global,link_type,link_duration_sec,access_expires,access_enabled,sub_token_hash,sub_token_enc)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)`, id, userID, input.Label, transport, tokenHash, expiry, uuid(), uuid(), isUniversal, input.CanEditGlobal, linkType, durationSec, accessExpires, tokenHash, subEnc)
		return err
	})
	if !report(w, err) {
		send(w, 201, obj{
			"id":            id,
			"link":          strings.TrimRight(s.cfg.PublicURL, "/") + "/connect#" + token,
			"subUrl":        s.subURL(token),
			"expires":       expiry,
			"accessExpires": accessExpires,
			"linkType":      linkType,
		})
	}
}

func (s *server) subURL(token string) string {
	if token == "" {
		return ""
	}
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/api/sub/singbox?token=" + url.QueryEscape(token)
}

func (s *server) connect(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token     string
		DeviceKey string
		Transport string
	}
	if !decode(w, r, &in) {
		return
	}
	if !tokenFormat.MatchString(in.Token) || !tokenFormat.MatchString(in.DeviceKey) ||
		in.Token == in.DeviceKey || (in.Transport != "agent" && in.Transport != "browser") {
		fail(w, 400, "invalid_link")
		return
	}
	var id string
	err := s.mutate("device.connected", in.Transport == "agent", func(tx *sql.Tx, _ int64) error {
		tokDigest := digest(in.Token)
		err := tx.QueryRow(`SELECT id FROM devices WHERE (invite_hash=? OR sub_token_hash=?) AND (transport=? OR universal=1) AND revoked=0
			AND access_enabled=1 AND token_hash IS NULL AND (expires=0 OR expires>?)`, tokDigest, tokDigest, in.Transport, time.Now().Unix()).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return apiError{401, "invalid_or_expired_link"}
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec("UPDATE devices SET transport=?,universal=0,invite_hash=NULL,token_hash=?,seen=? WHERE id=?", in.Transport, digest(in.DeviceKey), time.Now().Unix(), id)
		return err
	})
	if !report(w, err) {
		send(w, 201, obj{"deviceId": id})
	}
}

type device struct {
	id, userID, transport, primary, direct string
	canEditGlobal                          bool
}

func identity(q queryer, r *http.Request) (device, error) {
	var d device
	token := bearer(r)
	if token == "" {
		return d, apiError{401, "device_unauthorized"}
	}
	err := q.QueryRow(`SELECT d.id,d.user_id,d.transport,d.primary_id,d.direct_id,(d.can_edit_global=1 OR u.can_edit_global=1)
		FROM devices d JOIN users u ON u.id=d.user_id
		WHERE d.token_hash=? AND d.revoked=0 AND d.access_enabled=1 AND (d.access_expires=0 OR d.access_expires>?)`,
		digest(token), time.Now().Unix()).Scan(&d.id, &d.userID, &d.transport, &d.primary, &d.direct, &d.canEditGlobal)
	if errors.Is(err, sql.ErrNoRows) {
		err = apiError{401, "device_unauthorized"}
	}
	return d, err
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request) {
	err := s.mutate("device.revoked", true, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("UPDATE devices SET revoked=1,invite_hash=NULL,token_hash=NULL,sub_token_hash=NULL,sub_token_enc=NULL,sub_active=0,closed_reason='Ссылка закрыта',closed_at=? WHERE id=? AND revoked=0",
			time.Now().Unix(), r.PathValue("id")))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func (s *server) ensureDeviceSubLink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var sealed []byte
	var revoked bool
	err := s.db.QueryRow("SELECT sub_token_enc,revoked=1 FROM devices WHERE id=?", id).Scan(&sealed, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "not_found")
		return
	}
	if report(w, err) {
		return
	}
	if revoked {
		fail(w, 409, "device_revoked")
		return
	}
	if len(sealed) > 0 {
		if raw, err := s.secrets.Open(nil, nil, sealed, []byte(id)); err == nil && len(raw) > 0 {
			send(w, 200, obj{"subUrl": s.subURL(string(raw))})
			return
		}
	}
	subToken := randomToken()
	subEnc := s.secrets.Seal(nil, nil, []byte(subToken), []byte(id))
	err = s.mutate("device.sub_link", false, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("UPDATE devices SET sub_token_hash=?,sub_token_enc=? WHERE id=? AND revoked=0", digest(subToken), subEnc, id))
	})
	if !report(w, err) {
		send(w, 200, obj{"subUrl": s.subURL(subToken)})
	}
}

func (s *server) deviceAccess(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccessEnabled bool
	}
	if !decode(w, r, &input) {
		return
	}
	err := s.mutate("device.access_updated", true, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("UPDATE devices SET access_enabled=? WHERE id=? AND revoked=0", input.AccessEnabled, r.PathValue("id")))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func (s *server) clearDeviceHistory(w http.ResponseWriter, _ *http.Request) {
	err := s.mutate("device.history_cleared", false, func(tx *sql.Tx, _ int64) error {
		_, err := tx.Exec("DELETE FROM devices WHERE revoked=1 OR (access_expires>0 AND access_expires<=?)", time.Now().Unix())
		return err
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

type rule struct {
	ID       string `json:"id"`
	UserID   string `json:"userId,omitempty"`
	Kind     string `json:"kind"`
	Pattern  string `json:"pattern"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
	Locked   bool   `json:"locked"`
	Revision int64  `json:"revision"`
}

var packageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

func (p *rule) validate() bool {
	p.Pattern = strings.TrimSpace(p.Pattern)
	if p.Kind != "package" {
		p.Pattern = strings.ToLower(p.Pattern)
	}
	switch p.Action {
	case "PROXY", "AUTO", "LOCAL_DIRECT", "SERVER_DIRECT", "BLOCK", "INHERIT":
	default:
		return false
	}
	switch p.Kind {
	case "domain", "suffix":
		p.Pattern = strings.TrimRight(p.Pattern, ".")
		return hostname.MatchString(p.Pattern) && len(p.Pattern) <= 253
	case "process":
		p.Pattern = strings.ReplaceAll(p.Pattern, "/", "\\")
		return strings.HasSuffix(p.Pattern, ".exe") && len(p.Pattern) > 4 && len(p.Pattern) <= 1024 &&
			!strings.ContainsAny(p.Pattern, "\r\n\x00")
	case "package":
		return len(p.Pattern) <= 255 && packageName.MatchString(p.Pattern)
	default:
		return false
	}
}

func (s *server) saveRule(w http.ResponseWriter, r *http.Request, personal bool) {
	p := rule{Enabled: true}
	if !decode(w, r, &p) {
		return
	}
	if !p.validate() || p.Locked && (p.Action == "INHERIT" || p.Kind == "process" || p.Kind == "package") {
		fail(w, 400, "invalid_rule")
		return
	}
	err := s.mutate("rule.saved", false, func(tx *sql.Tx, rev int64) error {
		if personal {
			d, err := identity(tx, r)
			if err != nil {
				return err
			}
			if p.Locked || d.transport == "browser" && (p.Kind == "process" || p.Kind == "package") {
				return apiError{403, "forbidden_rule"}
			}
			p.UserID = d.userID
		}
		if p.UserID != "" {
			if err := ensure(tx, "SELECT 1 FROM users WHERE id=?", p.UserID); err != nil {
				return err
			}
		}
		var id string
		var current int64
		var locked bool
		err := tx.QueryRow("SELECT id,revision,locked FROM rules WHERE COALESCE(user_id,'')=? AND kind=? AND pattern=?",
			p.UserID, p.Kind, p.Pattern).Scan(&id, &current, &locked)
		if err == nil {
			if locked && personal {
				return apiError{403, "locked_rule"}
			}
			if p.Revision != current {
				return apiError{409, "rule_conflict"}
			}
			_, err = tx.Exec("UPDATE rules SET action=?,enabled=?,locked=?,revision=? WHERE id=?", p.Action, p.Enabled, p.Locked, rev, id)
		} else if errors.Is(err, sql.ErrNoRows) {
			if p.Revision != 0 {
				return apiError{409, "rule_conflict"}
			}
			id = uuid()
			_, err = tx.Exec("INSERT INTO rules(id,user_id,pattern,kind,action,locked,revision,enabled) VALUES(?,NULLIF(?,''),?,?,?,?,?,?)",
				id, p.UserID, p.Pattern, p.Kind, p.Action, p.Locked, rev, p.Enabled)
		}
		p.ID, p.Revision = id, rev
		return err
	})
	if !report(w, err) {
		send(w, 200, p)
	}
}

func (s *server) adminRule(w http.ResponseWriter, r *http.Request)    { s.saveRule(w, r, false) }
func (s *server) personalRule(w http.ResponseWriter, r *http.Request) { s.saveRule(w, r, true) }

func (s *server) deletePersonalRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.mutate("rule.deleted", false, func(tx *sql.Tx, _ int64) error {
		d, err := identity(tx, r)
		if err != nil {
			return err
		}
		var userID string
		var locked bool
		err = tx.QueryRow("SELECT COALESCE(user_id,''),locked FROM rules WHERE id=?", id).Scan(&userID, &locked)
		if err != nil {
			return err
		}
		if userID != d.userID || locked {
			return apiError{403, "forbidden_rule"}
		}
		return affected(tx.Exec("DELETE FROM rules WHERE id=? AND user_id=? AND locked=0", id, d.userID))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func (s *server) deleteRule(w http.ResponseWriter, r *http.Request) {
	err := s.mutate("rule.deleted", false, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("DELETE FROM rules WHERE id=?", r.PathValue("id")))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func rules(q queryer, user string, all bool) ([]rule, error) {
	rows, err := q.Query(`SELECT id,COALESCE(user_id,''),kind,pattern,action,enabled,locked,revision FROM rules
		WHERE ? OR user_id IS NULL OR user_id=? ORDER BY locked DESC,user_id IS NULL,LENGTH(pattern) DESC,pattern,kind`, all, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]rule, 0)
	for rows.Next() {
		var p rule
		if err := rows.Scan(&p.ID, &p.UserID, &p.Kind, &p.Pattern, &p.Action, &p.Enabled, &p.Locked, &p.Revision); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *server) config(w http.ResponseWriter, r *http.Request) {
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
	if report(w, err) {
		return
	}
	var d device
	var android, delivered bool
	defer func() {
		tx.Rollback()
		if delivered {
			now := time.Now().Unix()
			if _, err := s.db.Exec("UPDATE devices SET seen=? WHERE id=? AND seen<? AND revoked=0", now, d.id, now-30); err != nil {
				log.Printf("device seen update failed (%T)", err)
			}
			s.recordDeviceRelease(r, d, android)
		}
	}()
	d, err = identity(tx, r)
	if report(w, err) {
		return
	}
	rev, err := revision(tx)
	if report(w, err) {
		return
	}
	android = d.transport == "agent" && r.URL.Query().Get("platform") == "android"
	tag := fmt.Sprintf("\"%s-%d\"", d.id, rev)
	if android {
		tag = fmt.Sprintf("\"%s-%d-android\"", d.id, rev)
	}
	w.Header().Set("ETag", tag)
	if r.Header.Get("If-None-Match") == tag {
		delivered = true
		w.WriteHeader(304)
		return
	}
	policies, err := rules(tx, d.userID, false)
	if report(w, err) {
		return
	}
	policies = slices.DeleteFunc(policies, func(p rule) bool {
		return p.Kind == "process" && (android || d.transport == "browser") || p.Kind == "package" && !android
	})
	groups, err := listGroups(tx, d.userID, false, true)
	if report(w, err) {
		return
	}
	result := obj{
		"api": 1, "deviceId": d.id, "revision": rev, "rules": policies,
		"groups":        filterGroupEntries(groups, d.transport, android),
		"canEditGlobal": d.canEditGlobal,
	}
	if d.transport == "agent" {
		paused, err := clientUpdatesPaused(tx)
		if report(w, err) {
			return
		}
		result["clientUpdatesPaused"] = paused
		backups, err := s.proxies(tx, d.userID)
		if report(w, err) {
			return
		}
		result["probeUrl"] = s.cfg.ProbeURL
		result["proxies"] = backups
		result["home"] = endpoint{s.cfg.TunnelHost, s.cfg.TunnelPort, d.primary, d.direct, s.cfg.ServerName,
			base64.RawURLEncoding.EncodeToString(s.key.PublicKey().Bytes()), s.shortID}
	}
	delivered = true
	send(w, 200, result)
}

func (s *server) ack(w http.ResponseWriter, r *http.Request) {
	var in struct{ Revision int64 }
	if !decode(w, r, &in) {
		return
	}
	d, err := identity(s.db, r)
	if report(w, err) {
		return
	}
	rev, err := revision(s.db)
	if report(w, err) {
		return
	}
	if in.Revision <= 0 || in.Revision > rev {
		fail(w, 400, "invalid_revision")
		return
	}
	_, err = s.db.Exec("UPDATE devices SET ack_revision=MAX(ack_revision,?),seen=? WHERE id=? AND revoked=0", in.Revision, time.Now().Unix(), d.id)
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func list(q queryer, stmt string) ([]obj, error) {
	rows, err := q.Query(stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := make([]obj, 0)
	for rows.Next() {
		values := make([]any, len(keys))
		ptrs := make([]any, len(keys))
		for j := range values {
			ptrs[j] = &values[j]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := obj{}
		for j, key := range keys {
			row[key] = values[j]
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *server) state(w http.ResponseWriter, r *http.Request) {
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
	if report(w, err) {
		return
	}
	defer tx.Rollback()
	data := obj{}
	queries := map[string]string{
		"users":   "SELECT id,name,can_edit_global AS canEditGlobal FROM users ORDER BY name",
		"proxies": "SELECT id,name,host,port,tls,headers FROM proxies ORDER BY name",
		"routes":  "SELECT user_id AS userId,proxy_id AS proxyId,priority FROM routes ORDER BY user_id,priority",
		"devices": `SELECT d.id,d.user_id AS userId,d.label,d.transport,d.ack_revision AS ackRevision,d.seen,d.expires,
			d.link_type AS linkType,d.link_duration_sec AS linkDurationSec,d.access_expires AS accessExpires,
			d.access_enabled AS accessEnabled,d.can_edit_global AS canEditGlobal,d.closed_reason AS closedReason,
			d.closed_at AS closedAt,d.universal,d.sub_active AS subActive,d.sub_token_enc AS subTokenEnc,
			CASE WHEN COALESCE(r.platform,'')<>'' THEN r.platform WHEN d.sub_active=1 AND d.token_hash IS NULL THEN 'ios' ELSE '' END AS platform,
			COALESCE(r.version,'') AS installedVersion,COALESCE(r.reported_at,0) AS reportedAt,
			CASE WHEN d.revoked=1 THEN 'revoked' WHEN d.token_hash IS NOT NULL OR d.sub_active=1 THEN 'connected' ELSE 'invited' END AS status
			FROM devices d LEFT JOIN device_reports r ON r.device_id=d.id ORDER BY d.seen DESC,d.label`,
		"audit": "SELECT revision,event,time FROM audit ORDER BY revision DESC LIMIT 100",
	}
	for k, q := range queries {
		value, err := list(tx, q)
		if report(w, err) {
			return
		}
		data[k] = value
	}
	if users, ok := data["users"].([]obj); ok {
		for _, u := range users {
			v, _ := u["canEditGlobal"].(int64)
			u["canEditGlobal"] = v == 1
		}
	}
	if proxies, ok := data["proxies"].([]obj); ok {
		for _, p := range proxies {
			raw, _ := p["headers"].(string)
			p["headers"] = decodeHeaders(raw)
		}
	}
	active := s.core.activeDevices(r.Context())
	now := time.Now().Unix()
	if devices, ok := data["devices"].([]obj); ok {
		for _, d := range devices {
			id, _ := d["id"].(string)
			status, _ := d["status"].(string)
			seen, _ := d["seen"].(int64)
			accessExpires, _ := d["accessExpires"].(int64)
			accessEnabled, _ := d["accessEnabled"].(int64)
			canEditGlobal, _ := d["canEditGlobal"].(int64)
			universal, _ := d["universal"].(int64)
			subActive, _ := d["subActive"].(int64)
			expired := status != "revoked" && accessExpires > 0 && accessExpires <= now
			d["accessEnabled"] = accessEnabled == 1
			d["canEditGlobal"] = canEditGlobal == 1
			d["universal"] = universal == 1
			d["subActive"] = subActive == 1
			d["expired"] = expired
			if sealed, ok := d["subTokenEnc"].([]byte); ok && len(sealed) > 0 && status != "revoked" {
				if raw, err := s.secrets.Open(nil, nil, sealed, []byte(id)); err == nil && len(raw) > 0 {
					d["subUrl"] = s.subURL(string(raw))
				}
			}
			delete(d, "subTokenEnc")
			conns := active[id]
			d["activeConnections"] = conns
			d["online"] = status == "connected" && accessEnabled == 1 && !expired && (conns > 0 || (seen > 0 && now-seen <= 90))
		}
	}
	data["revision"], err = revision(tx)
	if report(w, err) {
		return
	}
	data["rules"], err = rules(tx, "", true)
	if report(w, err) {
		return
	}
	data["groups"], err = listGroups(tx, "", true, false)
	if !report(w, err) {
		send(w, 200, data)
	}
}

func (s *server) probe(w http.ResponseWriter, r *http.Request) {
	var p proxyInfo
	var sealed []byte
	var rawHeaders string
	err := s.db.QueryRow("SELECT id,name,host,port,tls,credentials,headers FROM proxies WHERE id=?", r.PathValue("id")).
		Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.TLS, &sealed, &rawHeaders)
	if report(w, err) {
		return
	}
	raw, err := s.secrets.Open(nil, nil, sealed, []byte(p.ID))
	if report(w, err) {
		return
	}
	var cred [2]string
	if report(w, json.Unmarshal(raw, &cred)) {
		return
	}
	p.Username, p.Password = cred[0], cred[1]
	p.Headers = decodeHeaders(rawHeaders)
	send(w, 200, obj{"reachable": s.probeProxy(r.Context(), p)})
}

func (s *server) backup(w http.ResponseWriter, _ *http.Request) {
	dir := filepath.Join(filepath.Dir(s.cfg.Database), "backups")
	if report(w, os.MkdirAll(dir, 0700)) {
		return
	}
	name := time.Now().UTC().Format("20060102T150405") + "-" + uuid() + ".sqlite"
	s.write.Lock()
	err := affectedBackup(s.db, filepath.Join(dir, name))
	s.write.Unlock()
	if !report(w, err) {
		send(w, 201, obj{"file": name})
	}
}

func affectedBackup(db *sql.DB, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = db.Exec("VACUUM INTO ?", path)
	if err != nil {
		os.Remove(path)
	}
	return err
}
