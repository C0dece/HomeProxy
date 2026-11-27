package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const serverReleaseFeed = "https://github.com/C0dece/HomeProxy/releases/latest/download"

var updateCheckHTTP = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("untrusted redirect")
		}
		return nil
	},
}

type releaseArtifact struct {
	Component string `json:"component"`
	Channel   string `json:"channel"`
	Version   string `json:"version"`
	Platform  string `json:"platform"`
	Arch      string `json:"arch"`
	APIMin    int    `json:"apiMin"`
	APIMax    int    `json:"apiMax"`
	DBSchema  int    `json:"dbSchema"`
	Notes     string `json:"notes"`
}

type serverUpdateInfo struct {
	Current    string `json:"current"`
	DBSchema   int    `json:"dbSchema"`
	Latest     string `json:"latest,omitempty"`
	Available  bool   `json:"available"`
	CanApply   bool   `json:"canApply"`
	Notes      string `json:"notes,omitempty"`
	ReleaseURL string `json:"releaseUrl,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func serverUpdaterPaths() (verifierPath, publicKeyPath string, ok bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", "", false
	}
	dir := filepath.Dir(exe)
	verifier := filepath.Join(dir, "homeproxy-verify-release.exe")
	pubKey := filepath.Join(dir, "release-public.pem")
	vInfo, vErr := os.Stat(verifier)
	pInfo, pErr := os.Stat(pubKey)
	if vErr != nil || !vInfo.Mode().IsRegular() || pErr != nil || !pInfo.Mode().IsRegular() {
		return "", "", false
	}
	return verifier, pubKey, true
}

func parseSemver3(raw string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(raw), "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, part := range parts {
		if part == "" {
			return out, false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func newerSemver3(candidate, current [3]int) bool {
	for i := range 3 {
		if candidate[i] != current[i] {
			return candidate[i] > current[i]
		}
	}
	return false
}

func fetchLimited(ctx context.Context, client *http.Client, target string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected release metadata status")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("invalid release metadata size")
	}
	return data, nil
}

func checkServerUpdateFrom(
	ctx context.Context,
	client *http.Client,
	feed string,
	pubKeyPEM []byte,
	currentVersion string,
	currentAPI int,
	currentSchema int,
	canApply bool,
) (serverUpdateInfo, error) {
	info := serverUpdateInfo{
		Current:  currentVersion,
		DBSchema: currentSchema,
		CanApply: canApply,
	}
	block, rest := pem.Decode(pubKeyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return info, errors.New("invalid release public key")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return info, err
	}
	pubKey, ok := parsedKey.(ed25519.PublicKey)
	if !ok {
		return info, errors.New("unexpected release key type")
	}

	rawManifest, err := fetchLimited(ctx, client, strings.TrimRight(feed, "/")+"/release.json", 1<<20)
	if err != nil {
		return info, err
	}
	rawSig, err := fetchLimited(ctx, client, strings.TrimRight(feed, "/")+"/release.sig", 4096)
	if err != nil {
		return info, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSig)))
	if err != nil || !ed25519.Verify(pubKey, rawManifest, sig) {
		return info, errors.New("release signature verification failed")
	}

	var manifest struct {
		Format    int               `json:"format"`
		Artifacts []releaseArtifact `json:"artifacts"`
	}
	if err := json.Unmarshal(rawManifest, &manifest); err != nil || manifest.Format != 1 {
		return info, errors.New("unsupported release manifest")
	}

	curVer, curOK := parseSemver3(currentVersion)
	if !curOK {
		return info, errors.New("invalid installed version")
	}
	var bestVer [3]int
	var best releaseArtifact
	for _, entry := range manifest.Artifacts {
		if entry.Component != "server" || entry.Channel != "stable" ||
			entry.Platform != runtime.GOOS || entry.Arch != runtime.GOARCH {
			continue
		}
		candVer, ok := parseSemver3(entry.Version)
		if !ok || !newerSemver3(candVer, curVer) {
			continue
		}
		if entry.APIMin <= 0 || currentAPI < entry.APIMin || currentAPI > entry.APIMax || entry.DBSchema < currentSchema {
			continue
		}
		if best.Version == "" || newerSemver3(candVer, bestVer) {
			best = entry
			bestVer = candVer
		}
	}

	if best.Version != "" {
		info.Available = true
		info.Latest = best.Version
		info.Notes = best.Notes
		info.ReleaseURL = "https://github.com/C0dece/HomeProxy/releases/tag/v" + best.Version
	}
	return info, nil
}

func (s *server) checkServerUpdate(w http.ResponseWriter, r *http.Request) {
	_, pubKeyPath, ok := serverUpdaterPaths()
	if !ok {
		send(w, http.StatusOK, serverUpdateInfo{
			Current:    releaseVersion,
			DBSchema:   schemaVersion,
			Available:  false,
			CanApply:   false,
			ReleaseURL: "https://github.com/C0dece/HomeProxy/releases/latest",
			Reason:     "not_installed_release",
		})
		return
	}
	pubKeyPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "update_key_unreadable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	info, err := checkServerUpdateFrom(ctx, updateCheckHTTP, serverReleaseFeed, pubKeyPEM, releaseVersion, apiVersion, schemaVersion, runtime.GOOS == "windows")
	if err != nil {
		send(w, http.StatusOK, serverUpdateInfo{
			Current:    releaseVersion,
			DBSchema:   schemaVersion,
			Available:  false,
			CanApply:   false,
			ReleaseURL: "https://github.com/C0dece/HomeProxy/releases/latest",
			Reason:     "check_failed",
		})
		return
	}
	send(w, http.StatusOK, info)
}

func (s *server) applyServerUpdate(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "windows" {
		fail(w, http.StatusConflict, "server_update_unavailable")
		return
	}
	verifierPath, pubKeyPath, ok := serverUpdaterPaths()
	if !ok {
		fail(w, http.StatusConflict, "server_update_unavailable")
		return
	}
	pubKeyPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "update_key_unreadable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	info, err := checkServerUpdateFrom(ctx, updateCheckHTTP, serverReleaseFeed, pubKeyPEM, releaseVersion, apiVersion, schemaVersion, true)
	if err != nil {
		fail(w, http.StatusBadGateway, "update_check_failed")
		return
	}
	if !info.Available {
		fail(w, http.StatusConflict, "no_update_available")
		return
	}
	if err := startDetached(
		verifierPath,
		"-apply-service",
		"-manifest", serverReleaseFeed+"/release.json",
		"-signature", serverReleaseFeed+"/release.sig",
		"-public-key", pubKeyPath,
		"-channel", "stable",
	); err != nil {
		fail(w, http.StatusInternalServerError, "update_launch_failed")
		return
	}
	send(w, http.StatusAccepted, obj{
		"started": true,
		"target":  info.Latest,
	})
}
