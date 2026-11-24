package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	var input struct{ Name string }
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 100 {
		fail(w, 400, "invalid_name")
		return
	}
	id := uuid()
	err := s.mutate("user.created", false, func(tx *sql.Tx, _ int64) error {
		exists := ensure(tx, "SELECT 1 FROM users WHERE name=?", input.Name)
		if !errors.Is(exists, sql.ErrNoRows) {
			if exists != nil {
				return exists
			}
			return apiError{409, "name_taken"}
		}
		_, err := tx.Exec("INSERT INTO users(id,name) VALUES(?,?)", id, input.Name)
		return err
	})
	if !report(w, err) {
		send(w, 201, obj{"id": id, "name": input.Name})
	}
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
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "HEAD", s.cfg.ProbeURL, nil)
	if err != nil {
		return false
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
	if p.Name == "" || len(p.Name) > 100 || !validHost(p.Host) || !validPort(p.Port) ||
		len(p.Username) > 256 || len(p.Password) > 1024 ||
		strings.ContainsAny(p.Username, ":\r\n") || (p.Username == "" && p.Password != "") {
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
			_, err := tx.Exec("INSERT INTO proxies(id,name,host,port,tls,credentials) VALUES(?,?,?,?,?,?)", p.ID, p.Name, p.Host, p.Port, p.TLS, sealed)
			return err
		}
		return affected(tx.Exec("UPDATE proxies SET name=?,host=?,port=?,tls=?,credentials=? WHERE id=?", p.Name, p.Host, p.Port, p.TLS, sealed, p.ID))
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
		UserID, Label, Transport string
		Minutes                  int
	}
	if !decode(w, r, &input) {
		return
	}
	input.Label = strings.TrimSpace(input.Label)
	if input.Minutes == 0 {
		input.Minutes = 15
	}
	if input.Label == "" || len(input.Label) > 100 || input.Minutes < 1 || input.Minutes > 60 ||
		(input.Transport != "agent" && input.Transport != "browser") {
		fail(w, 400, "invalid_invite")
		return
	}
	id, token := uuid(), randomToken()
	expiry := time.Now().Add(time.Duration(input.Minutes) * time.Minute).Unix()
	err := s.mutate("device.invited", false, func(tx *sql.Tx, _ int64) error {
		if err := ensure(tx, "SELECT 1 FROM users WHERE id=?", input.UserID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO devices(id,user_id,label,transport,invite_hash,expires,primary_id,direct_id)
			VALUES(?,?,?,?,?,?,?,?)`, id, input.UserID, input.Label, input.Transport, digest(token), expiry, uuid(), uuid())
		return err
	})
	if !report(w, err) {
		send(w, 201, obj{"id": id, "link": strings.TrimRight(s.cfg.PublicURL, "/") + "/connect#" + token, "expires": expiry})
	}
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
		err := tx.QueryRow(`SELECT id FROM devices WHERE invite_hash=? AND transport=? AND revoked=0
			AND token_hash IS NULL AND expires>?`, digest(in.Token), in.Transport, time.Now().Unix()).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return apiError{401, "invalid_or_expired_link"}
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec("UPDATE devices SET invite_hash=NULL,token_hash=?,seen=? WHERE id=?", digest(in.DeviceKey), time.Now().Unix(), id)
		return err
	})
	if !report(w, err) {
		send(w, 201, obj{"deviceId": id})
	}
}

type device struct{ id, userID, transport, primary, direct string }

func identity(q queryer, r *http.Request) (device, error) {
	var d device
	token := bearer(r)
	if token == "" {
		return d, apiError{401, "device_unauthorized"}
	}
	err := q.QueryRow("SELECT id,user_id,transport,primary_id,direct_id FROM devices WHERE token_hash=? AND revoked=0",
		digest(token)).Scan(&d.id, &d.userID, &d.transport, &d.primary, &d.direct)
	if errors.Is(err, sql.ErrNoRows) {
		err = apiError{401, "device_unauthorized"}
	}
	return d, err
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request) {
	err := s.mutate("device.revoked", true, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("UPDATE devices SET revoked=1,invite_hash=NULL,token_hash=NULL WHERE id=? AND revoked=0", r.PathValue("id")))
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
	var p rule
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
			_, err = tx.Exec("UPDATE rules SET action=?,locked=?,revision=? WHERE id=?", p.Action, p.Locked, rev, id)
		} else if errors.Is(err, sql.ErrNoRows) {
			if p.Revision != 0 {
				return apiError{409, "rule_conflict"}
			}
			id = uuid()
			_, err = tx.Exec("INSERT INTO rules VALUES(?,NULLIF(?,''),?,?,?,?,?)", id, p.UserID, p.Pattern, p.Kind, p.Action, p.Locked, rev)
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

func (s *server) deleteRule(w http.ResponseWriter, r *http.Request) {
	err := s.mutate("rule.deleted", false, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("DELETE FROM rules WHERE id=?", r.PathValue("id")))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func rules(q queryer, user string, all bool) ([]rule, error) {
	rows, err := q.Query(`SELECT id,COALESCE(user_id,''),kind,pattern,action,locked,revision FROM rules
		WHERE ? OR user_id IS NULL OR user_id=? ORDER BY locked DESC,user_id IS NULL,LENGTH(pattern) DESC,pattern,kind`, all, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]rule, 0)
	for rows.Next() {
		var p rule
		if err := rows.Scan(&p.ID, &p.UserID, &p.Kind, &p.Pattern, &p.Action, &p.Locked, &p.Revision); err != nil {
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
	defer tx.Rollback()
	d, err := identity(tx, r)
	if report(w, err) {
		return
	}
	rev, err := revision(tx)
	if report(w, err) {
		return
	}
	android := d.transport == "agent" && r.URL.Query().Get("platform") == "android"
	tag := fmt.Sprintf("\"%s-%d\"", d.id, rev)
	if android {
		tag = fmt.Sprintf("\"%s-%d-android\"", d.id, rev)
	}
	w.Header().Set("ETag", tag)
	if r.Header.Get("If-None-Match") == tag {
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
	result := obj{"api": 1, "deviceId": d.id, "revision": rev, "rules": policies}
	if d.transport == "agent" {
		backups, err := s.proxies(tx, d.userID)
		if report(w, err) {
			return
		}
		result["probeUrl"] = s.cfg.ProbeURL
		result["proxies"] = backups
		result["home"] = endpoint{s.cfg.TunnelHost, s.cfg.TunnelPort, d.primary, d.direct, s.cfg.ServerName,
			base64.RawURLEncoding.EncodeToString(s.key.PublicKey().Bytes()), s.shortID}
	}
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
		"users":   "SELECT id,name FROM users ORDER BY name",
		"proxies": "SELECT id,name,host,port,tls FROM proxies ORDER BY name",
		"routes":  "SELECT user_id AS userId,proxy_id AS proxyId,priority FROM routes ORDER BY user_id,priority",
		"devices": `SELECT id,user_id AS userId,label,transport,ack_revision AS ackRevision,seen,expires,
			CASE WHEN revoked=1 THEN 'revoked' WHEN token_hash IS NOT NULL THEN 'connected' ELSE 'invited' END AS status FROM devices ORDER BY seen DESC,label`,
		"audit": "SELECT revision,event,time FROM audit ORDER BY revision DESC LIMIT 100",
	}
	for k, q := range queries {
		value, err := list(tx, q)
		if report(w, err) {
			return
		}
		data[k] = value
	}
	data["revision"], err = revision(tx)
	if report(w, err) {
		return
	}
	data["rules"], err = rules(tx, "", true)
	if !report(w, err) {
		send(w, 200, data)
	}
}

func (s *server) probe(w http.ResponseWriter, r *http.Request) {
	var p proxyInfo
	var sealed []byte
	err := s.db.QueryRow("SELECT id,name,host,port,tls,credentials FROM proxies WHERE id=?", r.PathValue("id")).
		Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.TLS, &sealed)
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
