package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
)

type serviceGroupEntry struct {
	ID      string `json:"id,omitempty"`
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

func (e *serviceGroupEntry) UnmarshalJSON(data []byte) error {
	type alias struct {
		ID      string `json:"id,omitempty"`
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
		Enabled *bool  `json:"enabled"`
	}
	var raw alias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.ID = raw.ID
	e.Kind = raw.Kind
	e.Pattern = raw.Pattern
	if raw.Enabled != nil {
		e.Enabled = *raw.Enabled
	} else {
		e.Enabled = true
	}
	return nil
}

type serviceGroup struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	UserID   string              `json:"userId,omitempty"`
	Action   string              `json:"action"`
	Enabled  bool                `json:"enabled"`
	Locked   bool                `json:"locked"`
	Revision int64               `json:"revision"`
	Entries  []serviceGroupEntry `json:"entries"`
}

func validateEntry(entry *serviceGroupEntry) bool {
	entry.Pattern = strings.TrimSpace(entry.Pattern)
	if entry.Kind != "package" {
		entry.Pattern = strings.ToLower(entry.Pattern)
	}
	switch entry.Kind {
	case "domain", "suffix":
		entry.Pattern = strings.TrimRight(entry.Pattern, ".")
		return hostname.MatchString(entry.Pattern) && len(entry.Pattern) <= 253
	case "ip_cidr":
		if strings.Contains(entry.Pattern, "/") {
			prefix, err := netip.ParsePrefix(entry.Pattern)
			if err != nil {
				return false
			}
			entry.Pattern = prefix.Masked().String()
			return true
		}
		addr, err := netip.ParseAddr(entry.Pattern)
		if err != nil {
			return false
		}
		entry.Pattern = netip.PrefixFrom(addr, addr.BitLen()).String()
		return true
	case "process":
		entry.Pattern = strings.ReplaceAll(entry.Pattern, "/", "\\")
		return strings.HasSuffix(entry.Pattern, ".exe") && len(entry.Pattern) > 4 && len(entry.Pattern) <= 1024 &&
			!strings.ContainsAny(entry.Pattern, "\r\n\x00")
	case "package":
		return len(entry.Pattern) <= 255 && packageName.MatchString(entry.Pattern)
	default:
		return false
	}
}

func (g *serviceGroup) validate() bool {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" || len(g.Name) > 100 {
		return false
	}
	switch g.Action {
	case "PROXY", "AUTO", "LOCAL_DIRECT", "SERVER_DIRECT", "BLOCK", "INHERIT":
	default:
		return false
	}
	if g.Locked && g.Action == "INHERIT" {
		return false
	}
	if len(g.Entries) > 256 {
		return false
	}
	seen := make(map[string]bool, len(g.Entries))
	for i := range g.Entries {
		if !validateEntry(&g.Entries[i]) {
			return false
		}
		key := g.Entries[i].Kind + "\x00" + g.Entries[i].Pattern
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func listGroups(q queryer, user string, all bool, onlyEnabled bool) ([]serviceGroup, error) {
	rows, err := q.Query(`SELECT id,name,COALESCE(user_id,''),action,enabled,locked,revision FROM service_groups
		WHERE (? OR user_id IS NULL OR user_id=?) AND (NOT ? OR enabled=1)
		ORDER BY locked DESC,user_id IS NULL,name`, all, user, onlyEnabled)
	if err != nil {
		return nil, err
	}
	groups := make([]serviceGroup, 0)
	index := map[string]int{}
	for rows.Next() {
		var g serviceGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.UserID, &g.Action, &g.Enabled, &g.Locked, &g.Revision); err != nil {
			rows.Close()
			return nil, err
		}
		g.Entries = make([]serviceGroupEntry, 0)
		index[g.ID] = len(groups)
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(groups) == 0 {
		return groups, nil
	}
	entryRows, err := q.Query(`SELECT id,group_id,kind,pattern,enabled FROM service_group_entries ORDER BY kind,pattern`)
	if err != nil {
		return nil, err
	}
	defer entryRows.Close()
	for entryRows.Next() {
		var id, groupID, kind, pattern string
		var enabled bool
		if err := entryRows.Scan(&id, &groupID, &kind, &pattern, &enabled); err != nil {
			return nil, err
		}
		if pos, ok := index[groupID]; ok {
			groups[pos].Entries = append(groups[pos].Entries, serviceGroupEntry{
				ID: id, Kind: kind, Pattern: pattern, Enabled: enabled,
			})
		}
	}
	return groups, entryRows.Err()
}

func filterGroupEntries(groups []serviceGroup, transport string, android bool) []serviceGroup {
	out := make([]serviceGroup, 0, len(groups))
	for _, g := range groups {
		filtered := make([]serviceGroupEntry, 0, len(g.Entries))
		for _, e := range g.Entries {
			switch e.Kind {
			case "domain", "suffix":
				filtered = append(filtered, e)
			case "ip_cidr":
				if transport == "agent" {
					filtered = append(filtered, e)
				}
			case "process":
				if transport == "agent" && !android {
					filtered = append(filtered, e)
				}
			case "package":
				if transport == "agent" && android {
					filtered = append(filtered, e)
				}
			}
		}
		g.Entries = filtered
		out = append(out, g)
	}
	return out
}

func saveGroupTx(tx *sql.Tx, rev int64, g *serviceGroup, clientMode bool, clientUserID string) error {
	if g.UserID != "" {
		if err := ensure(tx, "SELECT 1 FROM users WHERE id=?", g.UserID); err != nil {
			return err
		}
	}
	exists := ensure(tx, "SELECT 1 FROM service_groups WHERE name=? AND id<>?", g.Name, g.ID)
	if !errors.Is(exists, sql.ErrNoRows) {
		if exists != nil {
			return exists
		}
		return apiError{409, "name_taken"}
	}
	if g.ID != "" {
		var current int64
		var existingUserID string
		var existingLocked bool
		err := tx.QueryRow("SELECT revision,COALESCE(user_id,''),locked FROM service_groups WHERE id=?", g.ID).
			Scan(&current, &existingUserID, &existingLocked)
		if err != nil {
			return err
		}
		if clientMode && (existingLocked || (existingUserID != "" && existingUserID != clientUserID)) {
			return apiError{403, "forbidden_group"}
		}
		if g.Revision != current {
			return apiError{409, "group_conflict"}
		}
		if _, err := tx.Exec(`UPDATE service_groups SET name=?,user_id=NULLIF(?,''),action=?,enabled=?,locked=?,revision=? WHERE id=?`,
			g.Name, g.UserID, g.Action, g.Enabled, g.Locked, rev, g.ID); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM service_group_entries WHERE group_id=?", g.ID); err != nil {
			return err
		}
	} else {
		if g.Revision != 0 {
			return apiError{409, "group_conflict"}
		}
		g.ID = uuid()
		if _, err := tx.Exec(`INSERT INTO service_groups(id,name,user_id,action,enabled,locked,revision)
			VALUES(?,?,NULLIF(?,''),?,?,?,?)`, g.ID, g.Name, g.UserID, g.Action, g.Enabled, g.Locked, rev); err != nil {
			return err
		}
	}
	for i := range g.Entries {
		g.Entries[i].ID = uuid()
		if _, err := tx.Exec(`INSERT INTO service_group_entries(id,group_id,kind,pattern,enabled) VALUES(?,?,?,?,?)`,
			g.Entries[i].ID, g.ID, g.Entries[i].Kind, g.Entries[i].Pattern, g.Entries[i].Enabled); err != nil {
			return err
		}
	}
	g.Revision = rev
	return nil
}

func (s *server) saveGroup(w http.ResponseWriter, r *http.Request) {
	g := serviceGroup{Enabled: true}
	if !decode(w, r, &g) {
		return
	}
	if !g.validate() {
		fail(w, 400, "invalid_group")
		return
	}
	err := s.mutate("group.saved", false, func(tx *sql.Tx, rev int64) error {
		return saveGroupTx(tx, rev, &g, false, "")
	})
	if !report(w, err) {
		send(w, 200, g)
	}
}

func (s *server) clientSaveGroup(w http.ResponseWriter, r *http.Request) {
	g := serviceGroup{Enabled: true}
	if !decode(w, r, &g) {
		return
	}
	if !g.validate() {
		fail(w, 400, "invalid_group")
		return
	}
	err := s.mutate("group.saved", false, func(tx *sql.Tx, rev int64) error {
		d, err := identity(tx, r)
		if err != nil {
			return err
		}
		if !d.canEditGlobal || g.Locked || (g.UserID != "" && g.UserID != d.userID) {
			return apiError{403, "forbidden_group"}
		}
		return saveGroupTx(tx, rev, &g, true, d.userID)
	})
	if !report(w, err) {
		send(w, 200, g)
	}
}

func (s *server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	err := s.mutate("group.deleted", false, func(tx *sql.Tx, _ int64) error {
		return affected(tx.Exec("DELETE FROM service_groups WHERE id=?", r.PathValue("id")))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}

func (s *server) clientDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.mutate("group.deleted", false, func(tx *sql.Tx, _ int64) error {
		d, err := identity(tx, r)
		if err != nil {
			return err
		}
		if !d.canEditGlobal {
			return apiError{403, "forbidden_group"}
		}
		var userID string
		var locked bool
		if err := tx.QueryRow("SELECT COALESCE(user_id,''),locked FROM service_groups WHERE id=?", id).Scan(&userID, &locked); err != nil {
			return err
		}
		if locked || (userID != "" && userID != d.userID) {
			return apiError{403, "forbidden_group"}
		}
		return affected(tx.Exec("DELETE FROM service_groups WHERE id=?", id))
	})
	if !report(w, err) {
		w.WriteHeader(204)
	}
}
