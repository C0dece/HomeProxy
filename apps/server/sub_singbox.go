package main

import (
	"cmp"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	singboxSelectorTag     = "proxy"
	singboxHomeServerTag   = "HomeProxy Server"
	singboxServerDirectTag = "homeproxy-server-direct"
	singboxDirectTag       = "direct"
	singboxBlockTag        = "block"
)

type effectiveSubRule struct {
	kind    string
	pattern string
	action  string
	userID  string
	locked  bool
}

func (s *server) subSingbox(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if !tokenFormat.MatchString(token) {
		fail(w, 403, "forbidden")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
	if report(w, err) {
		return
	}
	txClosed := false
	defer func() {
		if !txClosed {
			_ = tx.Rollback()
		}
	}()

	now := time.Now().Unix()
	var dev struct {
		id            string
		userID        string
		primary       string
		direct        string
		revoked       bool
		accessEnabled bool
		accessExpires int64
		seen          int64
		subActive     bool
	}
	err = tx.QueryRow(`SELECT id, user_id, primary_id, direct_id, revoked=1, access_enabled=1, access_expires, seen, sub_active=1
		FROM devices WHERE sub_token_hash=?`, digest(token)).
		Scan(&dev.id, &dev.userID, &dev.primary, &dev.direct, &dev.revoked, &dev.accessEnabled, &dev.accessExpires, &dev.seen, &dev.subActive)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 403, "forbidden")
		return
	}
	if report(w, err) {
		return
	}
	if dev.revoked || !dev.accessEnabled || (dev.accessExpires > 0 && dev.accessExpires <= now) {
		fail(w, 403, "forbidden")
		return
	}

	proxies, err := s.proxies(tx, dev.userID)
	if report(w, err) {
		return
	}
	policies, err := rules(tx, dev.userID, false)
	if report(w, err) {
		return
	}
	groups, err := listGroups(tx, dev.userID, false, true)
	if report(w, err) {
		return
	}
	_ = tx.Rollback()
	txClosed = true

	if !dev.subActive {
		err = s.mutate("device.sub_activated", true, func(wtx *sql.Tx, _ int64) error {
			return affected(wtx.Exec(`UPDATE devices SET sub_active=1, seen=?
				WHERE id=? AND revoked=0 AND access_enabled=1 AND (access_expires=0 OR access_expires>?)`,
				now, dev.id, now))
		})
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 403, "forbidden")
			return
		}
		if report(w, err) {
			return
		}
	} else if dev.seen < now-30 {
		if _, err := s.db.Exec("UPDATE devices SET seen=? WHERE id=? AND seen<? AND revoked=0", now, dev.id, now-30); err != nil {
			log.Printf("sub device seen update failed (%T)", err)
		}
	}

	finalOutbound := singboxDirectTag
	if r.URL.Query().Get("final") == singboxSelectorTag {
		finalOutbound = singboxSelectorTag
	}

	payload := s.buildSingboxConfig(dev.primary, dev.direct, proxies, policies, groups, finalOutbound)
	raw, err := json.MarshalIndent(payload, "", "  ")
	if report(w, err) {
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "1")
	w.Header().Set("Content-Disposition", `attachment; filename="HomeProxy.json"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

func (s *server) buildSingboxConfig(primaryID, directID string, proxies []proxyInfo, policies []rule, groups []serviceGroup, finalOutbound string) obj {
	if finalOutbound != singboxSelectorTag {
		finalOutbound = singboxDirectTag
	}

	usedTags := map[string]bool{
		singboxSelectorTag:     true,
		singboxDirectTag:       true,
		singboxBlockTag:        true,
		singboxHomeServerTag:   true,
		singboxServerDirectTag: true,
	}

	outbounds := make([]obj, 0, len(proxies)+5)
	selectorOutbounds := make([]string, 0, len(proxies)+1)

	for i, p := range proxies {
		tag := uniqueSingboxTag(usedTags, p.Name, fmt.Sprintf("proxy-%d", i+1))
		out := obj{
			"type":        "http",
			"tag":         tag,
			"server":      p.Host,
			"server_port": p.Port,
		}
		if p.Username != "" {
			out["username"] = p.Username
			out["password"] = p.Password
		}
		if p.TLS {
			out["tls"] = obj{"enabled": true, "server_name": p.Host}
		}
		if len(p.Headers) > 0 {
			out["headers"] = p.Headers
		}
		outbounds = append(outbounds, out)
		selectorOutbounds = append(selectorOutbounds, tag)
	}

	hasHomeServer := s.cfg.TunnelHost != "" && s.cfg.TunnelPort > 0 && s.cfg.ServerName != "" && s.key != nil
	var pubKey string
	if hasHomeServer {
		pubKey = base64.RawURLEncoding.EncodeToString(s.key.PublicKey().Bytes())
		outbounds = append(outbounds, singboxVlessRealityOutbound(
			singboxHomeServerTag, s.cfg.TunnelHost, s.cfg.TunnelPort, primaryID, s.cfg.ServerName, pubKey, s.shortID,
		))
		selectorOutbounds = append(selectorOutbounds, singboxHomeServerTag)
	}
	if len(selectorOutbounds) == 0 {
		selectorOutbounds = append(selectorOutbounds, singboxDirectTag)
	}

	merged := collectEffectiveSubRules(policies, groups)
	routeRules := []obj{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
		{"ip_is_private": true, "action": "route", "outbound": singboxDirectTag},
	}

	needServerDirect := false
	for i := 0; i < len(merged); {
		cur := merged[i]
		if cur.action == "SERVER_DIRECT" && hasHomeServer {
			needServerDirect = true
		}
		patterns := []string{cur.pattern}
		j := i + 1
		for j < len(merged) && merged[j].kind == cur.kind && merged[j].action == cur.action {
			patterns = append(patterns, merged[j].pattern)
			j++
		}
		if ruleObj, ok := buildSingboxRouteRule(cur.kind, cur.action, patterns, hasHomeServer); ok {
			routeRules = append(routeRules, ruleObj)
		}
		i = j
	}

	if needServerDirect && hasHomeServer {
		outbounds = append(outbounds, singboxVlessRealityOutbound(
			singboxServerDirectTag, s.cfg.TunnelHost, s.cfg.TunnelPort, directID, s.cfg.ServerName, pubKey, s.shortID,
		))
	}

	outbounds = append(outbounds,
		obj{
			"type":      "selector",
			"tag":       singboxSelectorTag,
			"outbounds": selectorOutbounds,
			"default":   selectorOutbounds[0],
		},
		obj{"type": "direct", "tag": singboxDirectTag},
		obj{"type": "block", "tag": singboxBlockTag},
	)

	return obj{
		"log": obj{
			"level":     "warn",
			"timestamp": true,
		},
		"dns": obj{
			"servers": []obj{
				{
					"type": "local",
					"tag":  "local-dns",
				},
				{
					"type":        "fakeip",
					"tag":         "fakeip",
					"inet4_range": "198.18.0.0/15",
					"inet6_range": "fc00::/18",
				},
				{
					"type":   "https",
					"tag":    "remote-dns",
					"server": "9.9.9.9",
					"path":   "/dns-query",
					"tls": obj{
						"enabled":     true,
						"server_name": "dns.quad9.net",
					},
					"detour": singboxSelectorTag,
				},
			},
			"rules": []obj{
				{
					"query_type":  []string{"A", "AAAA"},
					"action":      "route",
					"server":      "fakeip",
					"rewrite_ttl": 60,
				},
			},
			"final": "remote-dns",
		},
		"inbounds": []obj{
			{
				"type": "tun",
				"tag":  "tun-in",
				"address": []string{
					"172.19.0.1/30",
					"fdfe:dcba:9876::1/126",
				},
				"mtu":          9000,
				"auto_route":   true,
				"strict_route": true,
				"stack":        "system",
			},
		},
		"outbounds": outbounds,
		"route": obj{
			"auto_detect_interface":   true,
			"default_domain_resolver": "local-dns",
			"rules":                   routeRules,
			"final":                   finalOutbound,
		},
	}
}

func singboxVlessRealityOutbound(tag, host string, port int, uuid, serverName, pubKey, shortID string) obj {
	return obj{
		"type":        "vless",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"uuid":        uuid,
		"flow":        "xtls-rprx-vision",
		"tls": obj{
			"enabled":     true,
			"server_name": serverName,
			"utls": obj{
				"enabled":     true,
				"fingerprint": "chrome",
			},
			"reality": obj{
				"enabled":    true,
				"public_key": pubKey,
				"short_id":   shortID,
			},
		},
	}
}

func uniqueSingboxTag(used map[string]bool, name, fallback string) string {
	base := strings.TrimSpace(name)
	if base == "" {
		base = fallback
	}
	if !used[base] {
		used[base] = true
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s #%d", base, n)
		if !used[candidate] {
			used[candidate] = true
			return candidate
		}
	}
}

func collectEffectiveSubRules(policies []rule, groups []serviceGroup) []effectiveSubRule {
	out := make([]effectiveSubRule, 0, len(policies))
	for _, r := range policies {
		if !r.Enabled || r.Action == "INHERIT" || !supportedSingboxRuleKind(r.Kind) {
			continue
		}
		out = append(out, effectiveSubRule{
			kind:    r.Kind,
			pattern: r.Pattern,
			action:  r.Action,
			userID:  r.UserID,
			locked:  r.Locked,
		})
	}
	for _, g := range groups {
		if !g.Enabled || g.Action == "INHERIT" {
			continue
		}
		for _, e := range g.Entries {
			if !e.Enabled || !supportedSingboxRuleKind(e.Kind) {
				continue
			}
			out = append(out, effectiveSubRule{
				kind:    e.Kind,
				pattern: e.Pattern,
				action:  g.Action,
				userID:  g.UserID,
				locked:  g.Locked,
			})
		}
	}
	slices.SortStableFunc(out, func(a, b effectiveSubRule) int {
		if a.locked != b.locked {
			if a.locked {
				return -1
			}
			return 1
		}
		aPersonal := a.userID != ""
		bPersonal := b.userID != ""
		if aPersonal != bPersonal {
			if aPersonal {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(singboxKindOrder(a.kind), singboxKindOrder(b.kind)); c != 0 {
			return c
		}
		if c := cmp.Compare(len(b.pattern), len(a.pattern)); c != 0 {
			return c
		}
		return cmp.Compare(a.pattern, b.pattern)
	})
	return out
}

func supportedSingboxRuleKind(kind string) bool {
	return kind == "domain" || kind == "suffix" || kind == "ip_cidr"
}

func singboxKindOrder(kind string) int {
	switch kind {
	case "domain":
		return 0
	case "suffix":
		return 1
	default:
		return 2
	}
}

func buildSingboxRouteRule(kind, action string, patterns []string, hasHomeServer bool) (obj, bool) {
	item := obj{}
	switch kind {
	case "domain":
		item["domain"] = patterns
	case "suffix":
		item["domain_suffix"] = patterns
	case "ip_cidr":
		item["ip_cidr"] = patterns
	default:
		return nil, false
	}

	switch action {
	case "PROXY", "AUTO":
		item["action"] = "route"
		item["outbound"] = singboxSelectorTag
	case "LOCAL_DIRECT":
		item["action"] = "route"
		item["outbound"] = singboxDirectTag
	case "SERVER_DIRECT":
		item["action"] = "route"
		if hasHomeServer {
			item["outbound"] = singboxServerDirectTag
		} else {
			item["outbound"] = singboxDirectTag
		}
	case "BLOCK":
		item["action"] = "route"
		item["outbound"] = singboxBlockTag
	default:
		return nil, false
	}
	return item, true
}
