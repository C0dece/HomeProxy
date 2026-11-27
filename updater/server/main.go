// Command homeproxy-verify-release verifies and stages signed release artifacts.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type version [3]uint64

var versionFormat = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func parseVersion(s string) (version, error) {
	var result version
	parts := versionFormat.FindStringSubmatch(s)
	if len(parts) != 4 {
		return result, errors.New("use a numeric major.minor.patch version")
	}
	for i := range result {
		part, err := strconv.ParseUint(parts[i+1], 10, 64)
		if err != nil {
			return result, err
		}
		result[i] = part
	}
	return result, nil
}

func (v version) after(current version) bool {
	for i, value := range v {
		if value != current[i] {
			return value > current[i]
		}
	}
	return false
}

type artifact struct {
	Component   string `json:"component"`
	Channel     string `json:"channel"`
	Version     string `json:"version"`
	VersionCode int64  `json:"versionCode,omitempty"`
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	URL         string `json:"url"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	APIMin      int    `json:"apiMin"`
	APIMax      int    `json:"apiMax"`
	DBSchema    int    `json:"dbSchema"`
	Notes       string `json:"notes"`
}

type selection struct {
	component, channel, platform, arch string
	current                            version
	api, dbSchema                      int
}

func choose(raw, signature, publicKey []byte, selected selection) (artifact, error) {
	var result artifact
	block, rest := pem.Decode(publicKey)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return result, errors.New("expected one PEM public key")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return result, err
	}
	key, ok := value.(ed25519.PublicKey)
	sig, sigErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if !ok || sigErr != nil || !ed25519.Verify(key, raw, sig) {
		return result, errors.New("release manifest signature mismatch")
	}
	manifest := struct {
		Format    int        `json:"format"`
		Artifacts []artifact `json:"artifacts"`
	}{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Format != 1 {
		return result, errors.New("unsupported release manifest")
	}
	var newest version
	for _, entry := range manifest.Artifacts {
		if entry.Component != selected.component || entry.Channel != selected.channel ||
			entry.Platform != selected.platform || entry.Arch != selected.arch {
			continue
		}
		v, err := parseVersion(entry.Version)
		expected, hashErr := hex.DecodeString(entry.SHA256)
		if err != nil || hashErr != nil || len(expected) != sha256.Size || entry.Size <= 0 || entry.Size > 1<<30 ||
			entry.APIMin <= 0 || entry.APIMax < entry.APIMin {
			return result, errors.New("invalid release entry")
		}
		if !v.after(selected.current) || selected.api < entry.APIMin || selected.api > entry.APIMax ||
			entry.Component == "server" && entry.DBSchema != selected.dbSchema {
			continue
		}
		switch {
		case result.Version == "" || v.after(newest):
			result, newest = entry, v
		case v == newest:
			return result, errors.New("duplicate release")
		}
	}
	if result.Version == "" {
		return result, errors.New("no newer compatible release")
	}
	return result, nil
}

var client = &http.Client{
	Timeout: 3 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("untrusted redirect")
		}
		return nil
	},
}

func open(source string, local bool) (io.ReadCloser, error) {
	if local {
		return os.Open(source)
	}
	u, err := url.Parse(source)
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil {
		return nil, errors.New("download URL must use HTTPS")
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HomeProxy-Updater")
	res, err := client.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) {
			return nil, errors.New("release source unreachable (network or timeout)")
		}
		return nil, errors.New("release download failed")
	}
	if res.StatusCode == http.StatusTooManyRequests ||
		(res.StatusCode == http.StatusForbidden && res.Header.Get("X-RateLimit-Remaining") == "0") {
		res.Body.Close()
		return nil, errors.New("GitHub API rate limit exceeded")
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("release HTTP status %d", res.StatusCode)
	}
	return res.Body, nil
}

func read(source string, max int64) ([]byte, error) {
	f, err := open(source, !strings.Contains(source, "://"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("invalid release metadata size")
	}
	return data, nil
}

func stage(pkg artifact, localFile, output string) error {
	source := pkg.URL
	if localFile != "" {
		source = localFile
	}
	in, err := open(source, localFile != "")
	if err != nil {
		return err
	}
	defer in.Close()
	f, err := os.CreateTemp(filepath.Dir(output), ".homeproxy-stage-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(in, pkg.Size+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		return err
	}
	if n != pkg.Size || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), pkg.SHA256) {
		return errors.New("artifact size or checksum mismatch")
	}
	// A hard link publishes the fully verified file and cannot overwrite a
	// concurrently created destination.
	return os.Link(f.Name(), output)
}

func run() error {
	manifest := flag.String("manifest", "", "HTTPS URL or local signed manifest")
	signature := flag.String("signature", "", "HTTPS URL or local detached base64 signature")
	keyPath := flag.String("public-key", "", "trusted local Ed25519 public key in PEM")
	local := flag.String("package", "", "use a local artifact instead of downloading")
	output := flag.String("out", "", "stage the verified artifact to this new path")
	component := flag.String("component", "server", "release component")
	channel := flag.String("channel", "stable", "stable, beta or dev")
	installed := flag.String("current", "0.0.0", "installed component version")
	platform := flag.String("platform", runtime.GOOS, "target operating system")
	arch := flag.String("arch", runtime.GOARCH, "target architecture")
	api := flag.Int("api", 1, "required API version")
	schema := flag.Int("db-schema", 5, "required database schema")
	apply := flag.Bool("apply-service", false, "install a verified release into the local HomeProxyServer service")
	recoverUpdate := flag.Bool("recover-service", false, "restore the previous version after an interrupted local update")
	flag.Parse()
	if *apply && *recoverUpdate {
		return errors.New("choose apply-service or recover-service")
	}
	if *apply || *recoverUpdate {
		if *output != "" || *component != "server" || *platform != runtime.GOOS || *arch != runtime.GOARCH {
			return errors.New("service operations only support the local server component and manage their own output")
		}
		installation, closeService, err := openInstallation()
		if err != nil {
			return err
		}
		defer closeService()
		lock, err := installation.lock()
		if err != nil {
			return err
		}
		defer lock.Close()
		if *recoverUpdate {
			return installation.recover()
		}
		return installation.apply(*manifest, *signature, *keyPath, *local, *channel)
	}
	if *output == "" {
		return errors.New("out is required when staging a release")
	}
	current, err := parseVersion(*installed)
	if err != nil {
		return err
	}
	pkg, err := loadRelease(*manifest, *signature, *keyPath,
		selection{*component, *channel, *platform, *arch, current, *api, *schema})
	if err != nil {
		return err
	}
	if err := stage(pkg, *local, *output); err != nil {
		return err
	}
	fmt.Printf("Staged %s %s (%s/%s)\n", pkg.Component, pkg.Version, pkg.Platform, pkg.Arch)
	return nil
}

func loadRelease(manifest, signature, keyPath string, selected selection) (artifact, error) {
	if manifest == "" || signature == "" || keyPath == "" {
		return artifact{}, errors.New("manifest, signature and trusted public-key are required")
	}
	if selected.channel != "stable" && selected.channel != "beta" && selected.channel != "dev" {
		return artifact{}, errors.New("unsupported release channel")
	}
	raw, err := read(manifest, 1<<20)
	if err != nil {
		return artifact{}, err
	}
	sig, err := read(signature, 1024)
	if err != nil {
		return artifact{}, err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return artifact{}, err
	}
	return choose(raw, sig, key, selected)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
