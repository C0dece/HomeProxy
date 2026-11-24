package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestAdminAssetSource(t *testing.T) {
	original := bundledAdmin
	bundledAdmin = fstest.MapFS{"index.html": {Data: []byte("bundled")}}
	t.Cleanup(func() { bundledAdmin = original })

	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "index.html"), []byte("external"), 0600); err != nil {
		t.Fatal(err)
	}
	disabled := ""
	for _, tc := range []struct {
		name   string
		dir    *string
		status int
		body   string
	}{
		{"bundled default", nil, http.StatusOK, "bundled"},
		{"external override", &external, http.StatusOK, "external"},
		{"explicitly disabled", &disabled, http.StatusNotFound, "404 page not found\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &server{cfg: settings{AdminDir: tc.dir}}
			rec := httptest.NewRecorder()
			app.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != tc.status || rec.Body.String() != tc.body {
				t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), tc.status, tc.body)
			}
		})
	}
}
