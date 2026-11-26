package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

type cliStringSlice []string

func (s *cliStringSlice) String() string { return strings.Join(*s, ",") }
func (s *cliStringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type cliClient struct {
	baseURL string
	token   string
	http    *http.Client
	jsonOut bool
	out     io.Writer
}

type cliUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cliProxy struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Host    string            `json:"host"`
	Port    int               `json:"port"`
	TLS     int               `json:"tls"`
	Headers map[string]string `json:"headers,omitempty"`
}

type cliDevice struct {
	ID                string `json:"id"`
	UserID            string `json:"userId"`
	Label             string `json:"label"`
	Transport         string `json:"transport"`
	AckRevision       int64  `json:"ackRevision"`
	Seen              int64  `json:"seen"`
	Expires           int64  `json:"expires"`
	Platform          string `json:"platform"`
	InstalledVersion  string `json:"installedVersion"`
	Status            string `json:"status"`
	Online            bool   `json:"online"`
	ActiveConnections int    `json:"activeConnections"`
}

type cliState struct {
	Revision int64       `json:"revision"`
	Users    []cliUser   `json:"users"`
	Proxies  []cliProxy  `json:"proxies"`
	Routes   []struct {
		UserID   string `json:"userId"`
		ProxyID  string `json:"proxyId"`
		Priority int    `json:"priority"`
	} `json:"routes"`
	Devices []cliDevice    `json:"devices"`
	Rules   []rule         `json:"rules"`
	Groups  []serviceGroup `json:"groups"`
}

func runCLI(ctx context.Context, args []string) error {
	return runCLIWithIO(ctx, args, os.Stdout, os.Stderr)
}

func runCLIWithIO(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("homeproxy-server ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgFlag := fs.String("config", "server.json", "path to server.json")
	urlFlag := fs.String("url", "", "override admin API base URL")
	tokenFlag := fs.String("token", "", "override administrative token")
	jsonFlag := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printCLIHelp(stdout)
			return nil
		}
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 || rest[0] == "help" || rest[0] == "-h" || rest[0] == "--help" {
		printCLIHelp(stdout)
		return nil
	}

	client, err := buildCLIClient(*cfgFlag, *urlFlag, *tokenFlag, *jsonFlag, stdout)
	if err != nil {
		return err
	}

	cmd, subArgs := rest[0], rest[1:]
	switch cmd {
	case "status":
		return client.cmdStatus(ctx)
	case "users":
		return client.cmdUsers(ctx, subArgs, stderr)
	case "proxies":
		return client.cmdProxies(ctx, subArgs, stderr)
	case "devices":
		return client.cmdDevices(ctx, subArgs, stderr)
	case "rules":
		return client.cmdRules(ctx, subArgs, stderr)
	case "groups":
		return client.cmdGroups(ctx, subArgs, stderr)
	case "backup":
		return client.cmdBackup(ctx)
	default:
		return fmt.Errorf("unknown ctl command %q (use 'help')", cmd)
	}
}

func printCLIHelp(w io.Writer) {
	fmt.Fprintln(w, `HomeProxy Server CLI

Usage:
  homeproxy-server.exe ctl [-config server.json] [-url URL] [-token TOKEN] [-json] <command> ...

Commands:
  status
  users list
  users add <name>
  users rename <id|name> <newName>
  users delete <id|name>
  users assign-proxies <userId|name> [proxyId|name ...]
  proxies list
  proxies add -name <n> -host <h> -port <p> [-tls] [-user <u>] [-pass <pw>] [-header "Key: Value"]...
  proxies update <id|name> [-name <n>] [-host <h>] [-port <p>] [-tls=true|false] [-user <u>] [-pass <pw>] [-header "Key: Value"]...
  proxies remove <id|name>
  proxies probe <id|name>
  devices list
  devices online
  devices invite -user <id|name> -label <label> [-transport agent|browser] [-minutes 15]
  devices revoke <id|label>
  rules list
  rules set -kind <domain|suffix|process|package> -pattern <p> -action <ACTION> [-user <id|name>] [-locked] [-disabled]
  rules toggle <id> [-enabled=true|false]
  rules remove <id>
  groups list
  groups create -name <n> -action <ACTION> [-user <id|name>] [-locked] [-disabled] [-entry kind:pattern]...
  groups add-entry <groupId|name> -kind <domain|suffix|ip_cidr|process|package> -pattern <p>
  groups remove-entry <groupId|name> -kind <kind> -pattern <p>
  groups set-action <groupId|name> <ACTION>
  groups toggle <groupId|name> [-enabled=true|false]
  groups delete <groupId|name>
  backup`)
}

func buildCLIClient(cfgPath, overrideURL, overrideToken string, jsonOut bool, out io.Writer) (*cliClient, error) {
	var cfg settings
	var hasCfg bool
	if overrideURL == "" || overrideToken == "" {
		abs, err := resolveConfigPath(cfgPath)
		if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(abs)
		if err == nil {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return nil, fmt.Errorf("parse %s: %w", abs, err)
			}
			cfg.resolvePaths(filepath.Dir(abs))
			hasCfg = true
		} else if overrideURL == "" {
			return nil, fmt.Errorf("cannot read %s (or pass -url and -token): %w", abs, err)
		}
	}

	token := strings.TrimSpace(overrideToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("HOMEPROXY_ADMIN_TOKEN"))
	}
	if token == "" && hasCfg && cfg.AdminTokenFile != "" {
		raw, err := os.ReadFile(cfg.AdminTokenFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read adminTokenFile %s: %w", cfg.AdminTokenFile, err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		return nil, errors.New("admin token is required (-token, HOMEPROXY_ADMIN_TOKEN, or adminTokenFile)")
	}

	var tlsCfg *tls.Config
	baseURL := strings.TrimRight(strings.TrimSpace(overrideURL), "/")
	if baseURL == "" {
		if cfg.LocalAdmin != "" {
			baseURL = "http://" + cfg.LocalAdmin
		} else {
			host, port, err := net.SplitHostPort(cfg.Listen)
			if err != nil {
				return nil, fmt.Errorf("invalid listen address %q: %w", cfg.Listen, err)
			}
			switch host {
			case "", "0.0.0.0":
				host = "127.0.0.1"
			case "::":
				host = "::1"
			}
			addr := net.JoinHostPort(host, port)
			if cfg.CertFile != "" {
				baseURL = "https://" + addr
				pemBytes, err := os.ReadFile(cfg.CertFile)
				if err != nil {
					return nil, fmt.Errorf("read certFile %s: %w", cfg.CertFile, err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pemBytes) {
					return nil, errors.New("certFile does not contain valid PEM certificates")
				}
				tlsCfg = &tls.Config{RootCAs: pool}
				if pub, err := url.Parse(cfg.PublicURL); err == nil && pub.Hostname() != "" {
					tlsCfg.ServerName = pub.Hostname()
				}
			} else {
				baseURL = "http://" + addr
			}
		}
	} else if strings.HasPrefix(baseURL, "https://") && hasCfg && cfg.CertFile != "" {
		if pemBytes, err := os.ReadFile(cfg.CertFile); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pemBytes) {
				tlsCfg = &tls.Config{RootCAs: pool}
			}
		}
	}

	tr := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: tlsCfg,
	}
	return &cliClient{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Transport: tr, Timeout: 25 * time.Second},
		jsonOut: jsonOut,
		out:     out,
	}, nil
}

func (c *cliClient) do(ctx context.Context, method, path string, inBody, outBody any) error {
	var bodyReader io.Reader
	if inBody != nil {
		raw, err := json.Marshal(inBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if inBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("API %s %s (%d): %s", method, path, resp.StatusCode, apiErr.Error)
		}
		return fmt.Errorf("API %s %s (%d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if outBody != nil && len(raw) > 0 {
		return json.Unmarshal(raw, outBody)
	}
	return nil
}

func (c *cliClient) state(ctx context.Context) (cliState, error) {
	var st cliState
	err := c.do(ctx, "GET", "/api/v1/admin/state", nil, &st)
	return st, err
}

func (c *cliClient) printJSON(v any) error {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (c *cliClient) table(headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
}

func resolveRef[T any](items []T, ref string, idOf func(T) string, nameOf func(T) string, label string) (T, error) {
	var zero T
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return zero, fmt.Errorf("empty %s reference", label)
	}
	for _, item := range items {
		if idOf(item) == ref {
			return item, nil
		}
	}
	var matches []T
	for _, item := range items {
		if strings.EqualFold(nameOf(item), ref) {
			matches = append(matches, item)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return zero, fmt.Errorf("ambiguous %s %q (%d matches), specify ID", label, ref, len(matches))
	}
	return zero, fmt.Errorf("%s %q not found", label, ref)
}

func splitTargetAndFlags(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func parseCLIHeaders(entries []string) (map[string]string, error) {
	out := make(map[string]string)
	for _, raw := range entries {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		k, v, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("invalid header %q, expected 'Key: Value'", raw)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

func (c *cliClient) health(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/healthz", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 && resp.StatusCode != 503 {
		return nil, fmt.Errorf("API GET /healthz (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("invalid /healthz JSON (%d): %w", resp.StatusCode, err)
	}
	return out, nil
}

func (c *cliClient) cmdStatus(ctx context.Context) error {
	health, err := c.health(ctx)
	if err != nil {
		return err
	}
	st, err := c.state(ctx)
	if err != nil {
		return err
	}
	online, connected := 0, 0
	for _, d := range st.Devices {
		if d.Status == "connected" {
			connected++
		}
		if d.Online {
			online++
		}
	}
	if c.jsonOut {
		return c.printJSON(map[string]any{
			"health":           health,
			"revision":         st.Revision,
			"users":            len(st.Users),
			"proxies":          len(st.Proxies),
			"devicesTotal":     len(st.Devices),
			"devicesConnected": connected,
			"devicesOnline":    online,
			"rules":            len(st.Rules),
			"groups":           len(st.Groups),
		})
	}
	fmt.Fprintf(c.out, "Ready:    %v\n", health["ready"])
	fmt.Fprintf(c.out, "Version:  %v (API %v, DB schema %v, PID %v)\n", health["version"], health["api"], health["dbSchema"], health["pid"])
	fmt.Fprintf(c.out, "Revision: %d\n", st.Revision)
	fmt.Fprintf(c.out, "Users:    %d\n", len(st.Users))
	fmt.Fprintf(c.out, "Proxies:  %d\n", len(st.Proxies))
	fmt.Fprintf(c.out, "Devices:  %d online / %d connected (%d total)\n", online, connected, len(st.Devices))
	fmt.Fprintf(c.out, "Policies: %d rules, %d groups\n", len(st.Rules), len(st.Groups))
	return nil
}

func (c *cliClient) cmdUsers(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("users subcommand required: list, add, rename, delete, assign-proxies")
	}
	switch args[0] {
	case "list":
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(st.Users)
		}
		proxyNames := map[string]string{}
		for _, p := range st.Proxies {
			proxyNames[p.ID] = p.Name
		}
		rows := make([][]string, 0, len(st.Users))
		for _, u := range st.Users {
			var assigned []string
			for _, r := range st.Routes {
				if r.UserID == u.ID {
					assigned = append(assigned, proxyNames[r.ProxyID])
				}
			}
			rows = append(rows, []string{u.ID, u.Name, strings.Join(assigned, ", ")})
		}
		c.table([]string{"ID", "NAME", "PROXIES"}, rows)
		return nil
	case "add":
		if len(args) < 2 {
			return errors.New("usage: users add <name>")
		}
		var out map[string]any
		if err := c.do(ctx, "POST", "/api/v1/admin/users", map[string]string{"name": strings.Join(args[1:], " ")}, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\t%s\n", out["id"], out["name"])
		return nil
	case "rename":
		if len(args) < 3 {
			return errors.New("usage: users rename <id|name> <newName>")
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		u, err := resolveRef(st.Users, args[1], func(x cliUser) string { return x.ID }, func(x cliUser) string { return x.Name }, "user")
		if err != nil {
			return err
		}
		var out map[string]any
		if err := c.do(ctx, "PUT", "/api/v1/admin/users/"+u.ID, map[string]string{"name": strings.Join(args[2:], " ")}, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\t%s\n", out["id"], out["name"])
		return nil
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: users delete <id|name>")
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		u, err := resolveRef(st.Users, args[1], func(x cliUser) string { return x.ID }, func(x cliUser) string { return x.Name }, "user")
		if err != nil {
			return err
		}
		if err := c.do(ctx, "DELETE", "/api/v1/admin/users/"+u.ID, nil, nil); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(map[string]string{"deleted": u.ID})
		}
		fmt.Fprintf(c.out, "deleted %s\n", u.ID)
		return nil
	case "assign-proxies":
		if len(args) < 2 {
			return errors.New("usage: users assign-proxies <userId|name> [proxyId|name ...]")
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		u, err := resolveRef(st.Users, args[1], func(x cliUser) string { return x.ID }, func(x cliUser) string { return x.Name }, "user")
		if err != nil {
			return err
		}
		pids := make([]string, 0, len(args)-2)
		for _, ref := range args[2:] {
			p, err := resolveRef(st.Proxies, ref, func(x cliProxy) string { return x.ID }, func(x cliProxy) string { return x.Name }, "proxy")
			if err != nil {
				return err
			}
			pids = append(pids, p.ID)
		}
		if err := c.do(ctx, "PUT", "/api/v1/admin/routes", map[string]any{"userId": u.ID, "proxyIds": pids}, nil); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(map[string]any{"userId": u.ID, "proxyIds": pids})
		}
		fmt.Fprintf(c.out, "assigned %d proxies to %s\n", len(pids), u.Name)
		return nil
	default:
		fmt.Fprintln(stderr, "users subcommands: list, add, rename, delete, assign-proxies")
		return fmt.Errorf("unknown users subcommand %q", args[0])
	}
}

func (c *cliClient) cmdProxies(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("proxies subcommand required: list, add, update, remove, probe")
	}
	switch args[0] {
	case "list":
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(st.Proxies)
		}
		rows := make([][]string, 0, len(st.Proxies))
		for _, p := range st.Proxies {
			tlsText := "HTTP"
			if p.TLS != 0 {
				tlsText = "HTTPS"
			}
			rows = append(rows, []string{p.ID, p.Name, fmt.Sprintf("%s:%d", p.Host, p.Port), tlsText, fmt.Sprintf("%d", len(p.Headers))})
		}
		c.table([]string{"ID", "NAME", "ADDRESS", "TLS", "HEADERS"}, rows)
		return nil
	case "add":
		fs := flag.NewFlagSet("proxies add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "proxy name")
		host := fs.String("host", "", "proxy host")
		port := fs.Int("port", 0, "proxy port")
		useTLS := fs.Bool("tls", false, "use TLS")
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		var headers cliStringSlice
		fs.Var(&headers, "header", "HTTP header 'Key: Value'")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		hdrMap, err := parseCLIHeaders(headers)
		if err != nil {
			return err
		}
		var out map[string]any
		if err := c.do(ctx, "PUT", "/api/v1/admin/proxies", map[string]any{
			"name": *name, "host": *host, "port": *port, "tls": *useTLS,
			"username": *user, "password": *pass, "headers": hdrMap,
		}, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintln(c.out, out["id"])
		return nil
	case "update":
		target, rest := splitTargetAndFlags(args[1:])
		fs := flag.NewFlagSet("proxies update", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "proxy name")
		host := fs.String("host", "", "proxy host")
		port := fs.Int("port", 0, "proxy port")
		useTLS := fs.Bool("tls", false, "use TLS")
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		var headers cliStringSlice
		fs.Var(&headers, "header", "HTTP header 'Key: Value'")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if target == "" {
			if fs.NArg() == 0 {
				return errors.New("usage: proxies update <id|name> [flags]")
			}
			target = fs.Arg(0)
		}
		visited := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		cur, err := resolveRef(st.Proxies, target, func(x cliProxy) string { return x.ID }, func(x cliProxy) string { return x.Name }, "proxy")
		if err != nil {
			return err
		}
		hdrMap := cur.Headers
		if visited["header"] {
			hdrMap, err = parseCLIHeaders(headers)
			if err != nil {
				return err
			}
		}
		if visited["name"] {
			cur.Name = *name
		}
		if visited["host"] {
			cur.Host = *host
		}
		if visited["port"] {
			cur.Port = *port
		}
		tlsBool := cur.TLS != 0
		if visited["tls"] {
			tlsBool = *useTLS
		}
		var out map[string]any
		if err := c.do(ctx, "PUT", "/api/v1/admin/proxies", map[string]any{
			"id": cur.ID, "name": cur.Name, "host": cur.Host, "port": cur.Port,
			"tls": tlsBool, "username": *user, "password": *pass, "headers": hdrMap,
		}, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintln(c.out, out["id"])
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: proxies remove <id|name>")
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		cur, err := resolveRef(st.Proxies, args[1], func(x cliProxy) string { return x.ID }, func(x cliProxy) string { return x.Name }, "proxy")
		if err != nil {
			return err
		}
		if err := c.do(ctx, "DELETE", "/api/v1/admin/proxies/"+cur.ID, nil, nil); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(map[string]string{"deleted": cur.ID})
		}
		fmt.Fprintf(c.out, "deleted %s\n", cur.ID)
		return nil
	case "probe":
		if len(args) != 2 {
			return errors.New("usage: proxies probe <id|name>")
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		cur, err := resolveRef(st.Proxies, args[1], func(x cliProxy) string { return x.ID }, func(x cliProxy) string { return x.Name }, "proxy")
		if err != nil {
			return err
		}
		var out struct {
			Reachable bool `json:"reachable"`
		}
		if err := c.do(ctx, "POST", "/api/v1/admin/probes/"+cur.ID, nil, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		if out.Reachable {
			fmt.Fprintf(c.out, "%s: reachable\n", cur.Name)
		} else {
			fmt.Fprintf(c.out, "%s: unreachable\n", cur.Name)
		}
		return nil
	default:
		return fmt.Errorf("unknown proxies subcommand %q", args[0])
	}
}

func (c *cliClient) cmdDevices(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("devices subcommand required: list, online, invite, revoke")
	}
	switch args[0] {
	case "list", "online":
		onlyOnline := args[0] == "online"
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		userNames := map[string]string{}
		for _, u := range st.Users {
			userNames[u.ID] = u.Name
		}
		filtered := st.Devices
		if onlyOnline {
			filtered = nil
			for _, d := range st.Devices {
				if d.Online {
					filtered = append(filtered, d)
				}
			}
		}
		if c.jsonOut {
			return c.printJSON(filtered)
		}
		rows := make([][]string, 0, len(filtered))
		for _, d := range filtered {
			stateText := d.Status
			if d.Status == "connected" {
				if d.Online {
					stateText = "online"
				} else {
					stateText = "offline"
				}
			}
			seen := "-"
			if d.Seen > 0 {
				seen = time.Unix(d.Seen, 0).Format("2006-01-02 15:04:05")
			}
			ver := d.InstalledVersion
			if ver == "" {
				ver = "-"
			}
			rows = append(rows, []string{
				d.ID, d.Label, userNames[d.UserID], d.Transport, stateText,
				fmt.Sprintf("%d", d.ActiveConnections), ver, seen,
			})
		}
		c.table([]string{"ID", "LABEL", "USER", "CLIENT", "STATE", "CONNS", "VERSION", "SEEN"}, rows)
		return nil
	case "invite":
		fs := flag.NewFlagSet("devices invite", flag.ContinueOnError)
		fs.SetOutput(stderr)
		userRef := fs.String("user", "", "user ID or name")
		label := fs.String("label", "", "device label")
		transport := fs.String("transport", "agent", "agent or browser")
		minutes := fs.Int("minutes", 15, "expiry in minutes")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		u, err := resolveRef(st.Users, *userRef, func(x cliUser) string { return x.ID }, func(x cliUser) string { return x.Name }, "user")
		if err != nil {
			return err
		}
		var out map[string]any
		if err := c.do(ctx, "POST", "/api/v1/admin/invites", map[string]any{
			"userId": u.ID, "label": *label, "transport": *transport, "minutes": *minutes,
		}, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "ID:   %s\nLink: %s\n", out["id"], out["link"])
		return nil
	case "revoke":
		if len(args) != 2 {
			return errors.New("usage: devices revoke <id|label>")
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		d, err := resolveRef(st.Devices, args[1], func(x cliDevice) string { return x.ID }, func(x cliDevice) string { return x.Label }, "device")
		if err != nil {
			return err
		}
		if err := c.do(ctx, "DELETE", "/api/v1/admin/devices/"+d.ID, nil, nil); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(map[string]string{"revoked": d.ID})
		}
		fmt.Fprintf(c.out, "revoked %s\n", d.ID)
		return nil
	default:
		return fmt.Errorf("unknown devices subcommand %q", args[0])
	}
}

func (c *cliClient) cmdRules(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("rules subcommand required: list, set, toggle, remove")
	}
	switch args[0] {
	case "list":
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(st.Rules)
		}
		userNames := map[string]string{}
		for _, u := range st.Users {
			userNames[u.ID] = u.Name
		}
		rows := make([][]string, 0, len(st.Rules))
		for _, r := range st.Rules {
			scope := "GLOBAL"
			if r.UserID != "" {
				scope = "PERSONAL:" + userNames[r.UserID]
			}
			rows = append(rows, []string{
				r.ID, scope, r.Kind, r.Pattern, r.Action,
				fmt.Sprintf("%v", r.Enabled), fmt.Sprintf("%v", r.Locked),
			})
		}
		c.table([]string{"ID", "SCOPE", "KIND", "PATTERN", "ACTION", "ENABLED", "LOCKED"}, rows)
		return nil
	case "set":
		fs := flag.NewFlagSet("rules set", flag.ContinueOnError)
		fs.SetOutput(stderr)
		kind := fs.String("kind", "", "domain|suffix|process|package")
		pattern := fs.String("pattern", "", "rule pattern")
		action := fs.String("action", "", "PROXY|AUTO|LOCAL_DIRECT|SERVER_DIRECT|BLOCK|INHERIT")
		userRef := fs.String("user", "", "user ID or name (empty for GLOBAL)")
		locked := fs.Bool("locked", false, "priority over local rules")
		disabled := fs.Bool("disabled", false, "create/save rule disabled")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		uid := ""
		if strings.TrimSpace(*userRef) != "" {
			u, err := resolveRef(st.Users, *userRef, func(x cliUser) string { return x.ID }, func(x cliUser) string { return x.Name }, "user")
			if err != nil {
				return err
			}
			uid = u.ID
		}
		var rev int64
		norm := rule{Kind: *kind, Pattern: *pattern, Action: *action}
		if norm.validate() {
			for _, existing := range st.Rules {
				if existing.UserID == uid && existing.Kind == norm.Kind && existing.Pattern == norm.Pattern {
					rev = existing.Revision
					break
				}
			}
		}
		var out rule
		if err := c.do(ctx, "PUT", "/api/v1/admin/rules", map[string]any{
			"userId": uid, "kind": *kind, "pattern": *pattern, "action": *action,
			"enabled": !*disabled, "locked": *locked, "revision": rev,
		}, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\t%s\t%s\n", out.ID, out.Pattern, out.Action)
		return nil
	case "toggle":
		target, rest := splitTargetAndFlags(args[1:])
		fs := flag.NewFlagSet("rules toggle", flag.ContinueOnError)
		fs.SetOutput(stderr)
		enabledFlag := fs.Bool("enabled", true, "set enabled state")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if target == "" {
			if fs.NArg() == 0 {
				return errors.New("usage: rules toggle <id> [-enabled=true|false]")
			}
			target = fs.Arg(0)
		}
		visited := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		var found *rule
		for i := range st.Rules {
			if st.Rules[i].ID == target {
				found = &st.Rules[i]
				break
			}
		}
		if found == nil {
			return fmt.Errorf("rule %q not found", target)
		}
		next := !found.Enabled
		if visited["enabled"] {
			next = *enabledFlag
		}
		var out rule
		if err := c.do(ctx, "PUT", "/api/v1/admin/rules", map[string]any{
			"userId": found.UserID, "kind": found.Kind, "pattern": found.Pattern, "action": found.Action,
			"enabled": next, "locked": found.Locked, "revision": found.Revision,
		}, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\tenabled=%v\n", out.ID, out.Enabled)
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: rules remove <id>")
		}
		if err := c.do(ctx, "DELETE", "/api/v1/admin/rules/"+args[1], nil, nil); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(map[string]string{"deleted": args[1]})
		}
		fmt.Fprintf(c.out, "deleted %s\n", args[1])
		return nil
	default:
		return fmt.Errorf("unknown rules subcommand %q", args[0])
	}
}

func resolveGroup(st cliState, ref string) (serviceGroup, error) {
	return resolveRef(st.Groups, ref, func(g serviceGroup) string { return g.ID }, func(g serviceGroup) string { return g.Name }, "group")
}

func (c *cliClient) cmdGroups(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("groups subcommand required: list, create, add-entry, remove-entry, set-action, toggle, delete")
	}
	switch args[0] {
	case "list":
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(st.Groups)
		}
		userNames := map[string]string{}
		for _, u := range st.Users {
			userNames[u.ID] = u.Name
		}
		rows := make([][]string, 0, len(st.Groups))
		for _, g := range st.Groups {
			scope := "GLOBAL"
			if g.UserID != "" {
				scope = "PERSONAL:" + userNames[g.UserID]
			}
			rows = append(rows, []string{
				g.ID, g.Name, scope, g.Action,
				fmt.Sprintf("%v", g.Enabled), fmt.Sprintf("%v", g.Locked), fmt.Sprintf("%d", len(g.Entries)),
			})
		}
		c.table([]string{"ID", "NAME", "SCOPE", "ACTION", "ENABLED", "LOCKED", "ENTRIES"}, rows)
		return nil
	case "create":
		fs := flag.NewFlagSet("groups create", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "group name")
		action := fs.String("action", "", "PROXY|AUTO|LOCAL_DIRECT|SERVER_DIRECT|BLOCK|INHERIT")
		userRef := fs.String("user", "", "user ID or name")
		locked := fs.Bool("locked", false, "priority over local rules")
		disabled := fs.Bool("disabled", false, "create group disabled")
		var entriesFlag cliStringSlice
		fs.Var(&entriesFlag, "entry", "entry kind:pattern")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		uid := ""
		if strings.TrimSpace(*userRef) != "" {
			st, err := c.state(ctx)
			if err != nil {
				return err
			}
			u, err := resolveRef(st.Users, *userRef, func(x cliUser) string { return x.ID }, func(x cliUser) string { return x.Name }, "user")
			if err != nil {
				return err
			}
			uid = u.ID
		}
		entries := make([]serviceGroupEntry, 0, len(entriesFlag))
		for _, raw := range entriesFlag {
			kind, pat, ok := strings.Cut(raw, ":")
			if !ok {
				return fmt.Errorf("invalid entry %q, expected kind:pattern", raw)
			}
			entries = append(entries, serviceGroupEntry{Kind: strings.TrimSpace(kind), Pattern: strings.TrimSpace(pat)})
		}
		var out serviceGroup
		if err := c.do(ctx, "PUT", "/api/v1/admin/groups", map[string]any{
			"name": *name, "userId": uid, "action": *action,
			"enabled": !*disabled, "locked": *locked, "entries": entries,
		}, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\t%s\n", out.ID, out.Name)
		return nil
	case "add-entry":
		target, rest := splitTargetAndFlags(args[1:])
		fs := flag.NewFlagSet("groups add-entry", flag.ContinueOnError)
		fs.SetOutput(stderr)
		kind := fs.String("kind", "", "domain|suffix|ip_cidr|process|package")
		pattern := fs.String("pattern", "", "entry pattern")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if target == "" {
			if fs.NArg() == 0 {
				return errors.New("usage: groups add-entry <groupId|name> -kind <kind> -pattern <pattern>")
			}
			target = fs.Arg(0)
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		grp, err := resolveGroup(st, target)
		if err != nil {
			return err
		}
		grp.Entries = append(grp.Entries, serviceGroupEntry{Kind: *kind, Pattern: *pattern})
		var out serviceGroup
		if err := c.do(ctx, "PUT", "/api/v1/admin/groups", grp, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\tentries=%d\n", out.Name, len(out.Entries))
		return nil
	case "remove-entry":
		target, rest := splitTargetAndFlags(args[1:])
		fs := flag.NewFlagSet("groups remove-entry", flag.ContinueOnError)
		fs.SetOutput(stderr)
		kind := fs.String("kind", "", "entry kind")
		pattern := fs.String("pattern", "", "entry pattern")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if target == "" {
			if fs.NArg() == 0 {
				return errors.New("usage: groups remove-entry <groupId|name> -kind <kind> -pattern <pattern>")
			}
			target = fs.Arg(0)
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		grp, err := resolveGroup(st, target)
		if err != nil {
			return err
		}
		probe := serviceGroupEntry{Kind: *kind, Pattern: *pattern}
		_ = validateEntry(&probe)
		filtered := make([]serviceGroupEntry, 0, len(grp.Entries))
		removed := false
		for _, e := range grp.Entries {
			if e.Kind == probe.Kind && e.Pattern == probe.Pattern {
				removed = true
				continue
			}
			filtered = append(filtered, e)
		}
		if !removed {
			return fmt.Errorf("entry %s:%s not found in group %s", *kind, *pattern, grp.Name)
		}
		grp.Entries = filtered
		var out serviceGroup
		if err := c.do(ctx, "PUT", "/api/v1/admin/groups", grp, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\tentries=%d\n", out.Name, len(out.Entries))
		return nil
	case "set-action":
		if len(args) != 3 {
			return errors.New("usage: groups set-action <groupId|name> <ACTION>")
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		grp, err := resolveGroup(st, args[1])
		if err != nil {
			return err
		}
		grp.Action = strings.ToUpper(strings.TrimSpace(args[2]))
		var out serviceGroup
		if err := c.do(ctx, "PUT", "/api/v1/admin/groups", grp, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\t%s\n", out.Name, out.Action)
		return nil
	case "toggle":
		target, rest := splitTargetAndFlags(args[1:])
		fs := flag.NewFlagSet("groups toggle", flag.ContinueOnError)
		fs.SetOutput(stderr)
		enabledFlag := fs.Bool("enabled", true, "set enabled state")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if target == "" {
			if fs.NArg() == 0 {
				return errors.New("usage: groups toggle <groupId|name> [-enabled=true|false]")
			}
			target = fs.Arg(0)
		}
		visited := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		grp, err := resolveGroup(st, target)
		if err != nil {
			return err
		}
		if visited["enabled"] {
			grp.Enabled = *enabledFlag
		} else {
			grp.Enabled = !grp.Enabled
		}
		var out serviceGroup
		if err := c.do(ctx, "PUT", "/api/v1/admin/groups", grp, &out); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "%s\tenabled=%v\n", out.Name, out.Enabled)
		return nil
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: groups delete <groupId|name>")
		}
		st, err := c.state(ctx)
		if err != nil {
			return err
		}
		grp, err := resolveGroup(st, args[1])
		if err != nil {
			return err
		}
		if err := c.do(ctx, "DELETE", "/api/v1/admin/groups/"+grp.ID, nil, nil); err != nil {
			return err
		}
		if c.jsonOut {
			return c.printJSON(map[string]string{"deleted": grp.ID})
		}
		fmt.Fprintf(c.out, "deleted %s\n", grp.ID)
		return nil
	default:
		return fmt.Errorf("unknown groups subcommand %q", args[0])
	}
}

func (c *cliClient) cmdBackup(ctx context.Context) error {
	var out map[string]any
	if err := c.do(ctx, "POST", "/api/v1/admin/backups", nil, &out); err != nil {
		return err
	}
	if c.jsonOut {
		return c.printJSON(out)
	}
	fmt.Fprintln(c.out, out["file"])
	return nil
}
