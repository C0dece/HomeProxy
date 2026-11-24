package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedRelease(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	body := []byte("local release fixture")
	digest := sha256.Sum256(body)
	entry := artifact{Component: "server", Platform: "windows", Arch: "amd64", Channel: "stable",
		Version: "0.2.0", APIMin: 1, APIMax: 1, DBSchema: 1, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(body))}
	raw, err := json.Marshal(map[string]any{"format": 1, "artifacts": []artifact{entry}})
	if err != nil {
		t.Fatal(err)
	}
	sign := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)))
	sel := selection{"server", "stable", "windows", "amd64", version{0, 1, 0}, 1, 1}
	if _, err := choose(append([]byte(" "), raw...), sign, key, sel); err == nil {
		t.Fatal("modified manifest accepted")
	}
	incompatible := sel
	incompatible.dbSchema = 2
	if _, err := choose(raw, sign, key, incompatible); err == nil {
		t.Fatal("incompatible manifest accepted")
	}
	pkg, err := choose(raw, sign, key, sel)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	if err := os.WriteFile(input, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage(pkg, input, output); err == nil {
		t.Fatal("corrupted artifact accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("bad artifact was published")
	}
	if err := os.WriteFile(input, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage(pkg, input, output); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(output)
	if err != nil || string(actual) != string(body) {
		t.Fatal("staged artifact differs from signed input")
	}
	if err := stage(pkg, input, output); err == nil {
		t.Fatal("existing artifact was overwritten")
	}
}
