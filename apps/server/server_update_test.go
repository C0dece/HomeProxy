package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

func TestCheckServerUpdateFromVerifiesSignatureAndSchema(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	manifest := map[string]any{
		"format": 1,
		"artifacts": []map[string]any{
			{
				"component": "server", "channel": "stable", "version": "0.3.1",
				"platform": runtime.GOOS, "arch": runtime.GOARCH,
				"apiMin": 1, "apiMax": 1, "dbSchema": 4, "notes": "Downgrade blocked",
			},
			{
				"component": "server", "channel": "stable", "version": "0.3.2",
				"platform": runtime.GOOS, "arch": runtime.GOARCH,
				"apiMin": 1, "apiMax": 1, "dbSchema": 5, "notes": "HomeProxy 0.3.2",
			},
		},
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, rawManifest))
	tamperSig := false

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release.json":
			_, _ = w.Write(rawManifest)
		case "/release.sig":
			if tamperSig {
				_, _ = w.Write([]byte("AAAA"))
				return
			}
			_, _ = w.Write([]byte(sig))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	info, err := checkServerUpdateFrom(context.Background(), srv.Client(), srv.URL, pubPEM, "0.3.0", 1, 5, true)
	if err != nil {
		t.Fatalf("expected valid update check, got %v", err)
	}
	if !info.Available || info.Latest != "0.3.2" || !info.CanApply {
		t.Fatalf("unexpected update info: %+v", info)
	}

	// Same or higher installed version -> no update.
	upToDate, err := checkServerUpdateFrom(context.Background(), srv.Client(), srv.URL, pubPEM, "0.3.2", 1, 5, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if upToDate.Available {
		t.Fatalf("expected no update available when already on 0.3.2: %+v", upToDate)
	}

	// Schema downgrade (installed schema 6 vs artifacts 4, 5) -> no update.
	downgrade, err := checkServerUpdateFrom(context.Background(), srv.Client(), srv.URL, pubPEM, "0.3.0", 1, 6, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if downgrade.Available {
		t.Fatalf("expected schema downgrade to be rejected: %+v", downgrade)
	}

	// Bad signature -> error.
	tamperSig = true
	if _, err := checkServerUpdateFrom(context.Background(), srv.Client(), srv.URL, pubPEM, "0.3.0", 1, 5, true); err == nil {
		t.Fatal("expected signature verification error")
	}
}
