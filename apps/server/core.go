package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type obj = map[string]any

type engine struct {
	binary, control, token string
	process                *exec.Cmd
	exit                   chan struct{}
	current                []byte
}

func loopbackAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func (e *engine) ready(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+e.control+"/version", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := engineHTTP.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

var engineHTTP = &http.Client{
	Transport: &http.Transport{DisableKeepAlives: true},
	Timeout:   400 * time.Millisecond,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func (e *engine) stop() {
	if e.process != nil {
		e.process.Process.Kill()
		<-e.exit
		e.process = nil
	}
}

func (e *engine) launch(data []byte) error {
	cmd := exec.Command(e.binary, "run", "-c", "stdin")
	cmd.Stdin = bytes.NewReader(data)
	job, err := prepareChild(cmd)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		job.close()
		return err
	}
	if err := job.attach(cmd.Process.Pid); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		job.close()
		return err
	}
	e.process = cmd
	exited := make(chan struct{})
	e.exit = exited
	go func() {
		cmd.Wait()
		job.close()
		close(exited)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-exited:
			e.stop()
			return errors.New("sing-box exited during startup")
		case <-ctx.Done():
			e.stop()
			return errors.New("sing-box startup timed out")
		case <-tick.C:
			if e.ready(ctx) {
				return nil
			}
		}
	}
}

func (e *engine) replace(data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.binary, "check", "-c", "stdin")
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil {
		return errors.New("sing-box rejected candidate configuration")
	}
	e.stop()
	if err := e.launch(data); err != nil {
		if e.current != nil {
			e.launch(e.current)
		}
		return err
	}
	e.current = data
	return nil
}

func (e *engine) supervise(ctx context.Context, lock *sync.Mutex) {
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				lock.Lock()
				if ctx.Err() == nil && e.current != nil {
					select {
					case <-e.exit:
						e.stop()
						e.launch(e.current)
					default:
						if e.process == nil {
							e.launch(e.current)
						}
					}
				}
				lock.Unlock()
			}
		}
	}()
}

type queryer interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

type proxyInfo struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	TLS      bool              `json:"tls"`
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

func decodeHeaders(raw string) map[string]string {
	if raw == "" || raw == "{}" {
		return nil
	}
	var parsed map[string]string
	if json.Unmarshal([]byte(raw), &parsed) != nil || len(parsed) == 0 {
		return nil
	}
	return parsed
}

func (e *engine) activeDevices(ctx context.Context) map[string]int {
	counts := map[string]int{}
	if e.control == "" {
		return counts
	}
	reqCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", "http://"+e.control+"/connections", nil)
	if err != nil {
		return counts
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := engineHTTP.Do(req)
	if err != nil {
		return counts
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return counts
	}
	var payload struct {
		Connections []struct {
			Metadata struct {
				User string `json:"user"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if json.NewDecoder(resp.Body).Decode(&payload) != nil {
		return counts
	}
	for _, conn := range payload.Connections {
		user := conn.Metadata.User
		if id, ok := strings.CutSuffix(user, "-proxy"); ok && id != "" {
			counts[id]++
		} else if id, ok := strings.CutSuffix(user, "-direct"); ok && id != "" {
			counts[id]++
		}
	}
	return counts
}

type endpoint struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	ID         string `json:"id"`
	DirectID   string `json:"directId"`
	ServerName string `json:"serverName"`
	PublicKey  string `json:"publicKey"`
	ShortID    string `json:"shortId"`
}

func (s *server) proxies(q queryer, user string) ([]proxyInfo, error) {
	query := "SELECT p.id,p.name,p.host,p.port,p.tls,p.credentials,p.headers FROM proxies p JOIN routes r ON r.proxy_id=p.id WHERE r.user_id=? ORDER BY r.priority"
	rows, err := q.Query(query, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]proxyInfo, 0)
	for rows.Next() {
		var p proxyInfo
		var sealed []byte
		var rawHeaders string
		if err := rows.Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.TLS, &sealed, &rawHeaders); err != nil {
			return nil, err
		}
		data, err := s.secrets.Open(nil, nil, sealed, []byte(p.ID))
		if err != nil {
			return nil, err
		}
		var credentials [2]string
		if err := json.Unmarshal(data, &credentials); err != nil {
			return nil, err
		}
		p.Username, p.Password = credentials[0], credentials[1]
		p.Headers = decodeHeaders(rawHeaders)
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *server) coreConfig(q queryer) ([]byte, error) {
	type account struct{ uid, id, primary, direct string }
	rows, err := q.Query("SELECT user_id,id,primary_id,direct_id FROM devices WHERE revoked=0 AND access_enabled=1 AND (access_expires=0 OR access_expires>?) AND ((transport='agent' AND token_hash IS NOT NULL) OR sub_active=1) ORDER BY id", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	var accounts []account
	for rows.Next() {
		var a account
		if err := rows.Scan(&a.uid, &a.id, &a.primary, &a.direct); err != nil {
			rows.Close()
			return nil, err
		}
		accounts = append(accounts, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	users := make([]obj, 0, len(accounts)*2)
	rules := []obj{{"network": "udp", "action": "reject"}}
	dnsServers := []obj{{"type": "local", "tag": "system"}}
	outbounds := []obj{{"type": "direct", "tag": "server-direct"}}
	if !s.cfg.LoopbackDev {
		resolve := obj{"action": "resolve"}
		if dns := s.cfg.DestinationDNS; dns != nil {
			dnsServers = append(dnsServers, obj{
				"type": "https", "tag": "destination-dns", "server": dns.Address,
				"tls": obj{"enabled": true, "server_name": dns.ServerName},
			})
			resolve["server"] = "destination-dns"
		}
		rules = append(rules,
			resolve,
			obj{"ip_cidr": []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "224.0.0.0/3", "fe80::/10", "ff00::/8"}, "action": "reject"},
			obj{"ip_is_private": true, "action": "reject"})
	}
	primaries := map[string]string{}
	for _, a := range accounts {
		proxyTag, knownUser := primaries[a.uid]
		if !knownUser {
			proxies, err := s.proxies(q, a.uid)
			if err != nil {
				return nil, err
			}
			if len(proxies) > 0 {
				p := proxies[0]
				proxyTag = "user-" + a.uid
				out := obj{"type": "http", "tag": proxyTag, "server": p.Host, "server_port": p.Port,
					"username": p.Username, "password": p.Password}
				if p.TLS {
					out["tls"] = obj{"enabled": true, "server_name": p.Host}
				}
				if len(p.Headers) > 0 {
					out["headers"] = p.Headers
				}
				outbounds = append(outbounds, out)
			}
			primaries[a.uid] = proxyTag
		}
		primaryName, directName := a.id+"-proxy", a.id+"-direct"
		users = append(users, obj{"name": primaryName, "uuid": a.primary, "flow": "xtls-rprx-vision"},
			obj{"name": directName, "uuid": a.direct, "flow": "xtls-rprx-vision"})
		if proxyTag != "" {
			rules = append(rules, obj{"auth_user": primaryName, "action": "route", "outbound": proxyTag})
		}
		rules = append(rules, obj{"auth_user": directName, "action": "route", "outbound": "server-direct"})
	}
	// An explicit rejection prevents the first outbound becoming a default.
	rules = append(rules, obj{"action": "reject"})
	listen, rawPort, _ := net.SplitHostPort(s.cfg.TunnelListen)
	port, _ := strconv.Atoi(rawPort)
	inbounds := []obj{}
	if len(users) != 0 {
		inbounds = append(inbounds, obj{"type": "vless", "tag": "devices", "listen": listen, "listen_port": port, "users": users,
			"tls": obj{"enabled": true, "server_name": s.cfg.ServerName,
				"reality": obj{"enabled": true, "handshake": obj{"server": s.cfg.HandshakeHost, "server_port": s.cfg.HandshakePort},
					"private_key": base64.RawURLEncoding.EncodeToString(s.key.Bytes()), "short_id": []string{s.shortID}}}})
	}
	return json.Marshal(obj{
		"log":      obj{"disabled": true},
		"route":    obj{"rules": rules, "default_domain_resolver": "system"},
		"dns":      obj{"servers": dnsServers, "final": "system"},
		"inbounds": inbounds, "outbounds": outbounds,
		"experimental": obj{"clash_api": obj{"external_controller": s.core.control, "secret": s.core.token}},
	})
}
