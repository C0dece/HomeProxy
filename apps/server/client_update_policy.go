package main

import (
	"database/sql"
	"errors"
	"net/http"
)

const createClientUpdatePolicy = `
CREATE TABLE IF NOT EXISTS client_update_policy (
	id INTEGER PRIMARY KEY CHECK(id=1),
	paused INTEGER NOT NULL CHECK(paused IN (0,1))
)`

func clientUpdatesPaused(q queryer) (bool, error) {
	var paused bool
	err := q.QueryRow("SELECT paused FROM client_update_policy WHERE id=1").Scan(&paused)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return paused, err
}

func (s *server) clientUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var body struct {
			Paused *bool `json:"paused"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Paused == nil {
			fail(w, http.StatusBadRequest, "invalid_update_policy")
			return
		}
		err := s.mutate("client-update-policy.saved", false, func(tx *sql.Tx, _ int64) error {
			_, err := tx.Exec(`INSERT INTO client_update_policy VALUES(1,?)
				ON CONFLICT(id) DO UPDATE SET paused=excluded.paused`, *body.Paused)
			return err
		})
		if report(w, err) {
			return
		}
	}
	paused, err := clientUpdatesPaused(s.db)
	if !report(w, err) {
		send(w, http.StatusOK, obj{"paused": paused})
	}
}
