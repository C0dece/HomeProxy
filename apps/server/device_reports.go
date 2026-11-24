package main

import (
	"log"
	"net/http"
	"time"
)

// This optional table leaves the existing schema readable by older releases.
const createDeviceReports = `
CREATE TABLE IF NOT EXISTS device_reports (
	device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
	platform TEXT NOT NULL CHECK(platform IN ('windows','android','browser')),
	version TEXT NOT NULL,
	reported_at INTEGER NOT NULL
)`

func (s *server) recordDeviceRelease(r *http.Request, d device, android bool) {
	version := r.Header.Get("X-HomeProxy-Version")
	if len(version) > 32 || !updateVersion.MatchString(version) {
		return
	}
	platform := "windows"
	switch {
	case d.transport == "browser":
		platform = "browser"
	case android:
		platform = "android"
	}
	now := time.Now().Unix()
	_, err := s.db.ExecContext(r.Context(), `
		INSERT INTO device_reports(device_id, platform, version, reported_at)
		SELECT id, ?, ?, ? FROM devices WHERE id=? AND revoked=0
		ON CONFLICT(device_id) DO UPDATE SET platform=excluded.platform, version=excluded.version,
			reported_at=excluded.reported_at
		WHERE device_reports.version<>excluded.version OR device_reports.platform<>excluded.platform
			OR device_reports.reported_at<=excluded.reported_at-120`, platform, version, now, d.id)
	if err != nil && r.Context().Err() == nil {
		log.Printf("device release report failed (%T)", err)
	}
}
