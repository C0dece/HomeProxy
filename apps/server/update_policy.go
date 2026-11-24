package main

import (
	"errors"
	"net/http"
	"os"
)

const updatePauseSuffix = ".updates-paused"

func updatePaused(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("invalid update pause marker")
	}
	return true, nil
}

func (s *server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ManageAutomaticUpdates {
		if r.Method == http.MethodPut {
			fail(w, http.StatusConflict, "update_policy_disabled")
			return
		}
		send(w, http.StatusOK, obj{"managed": false, "paused": false})
		return
	}

	path := s.cfg.Database + updatePauseSuffix
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
		s.write.Lock()
		defer s.write.Unlock()
		paused, err := updatePaused(path)
		if err == nil && paused != *body.Paused {
			if *body.Paused {
				var file *os.File
				file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err == nil {
					err = file.Close()
				}
			} else {
				err = os.Remove(path)
			}
		}
		if err != nil {
			fail(w, http.StatusServiceUnavailable, "update_policy_unavailable")
			return
		}
	}
	paused, err := updatePaused(path)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "update_policy_unavailable")
		return
	}
	send(w, http.StatusOK, obj{"managed": true, "paused": paused})
}
