package scannerdb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sekscan/internal/config"
	"sekscan/internal/store"
	"strings"
	"testing"
	"time"
)

type dbTransport func(*http.Request) (*http.Response, error)

func (f dbTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func dbZip(t *testing.T, bad bool) []byte {
	t.Helper()
	entries := map[string]string{"index/db.json": `{"modified":"2020-01-01T00:00:00Z"}`, "index/modules.json": `[{"path":"stdlib","vulns":[{"id":"GO-2026-1000"}]}]`, "index/vulns.json": `[{"id":"GO-2026-1000","modified":"2020-01-01T00:00:00Z"}]`, "ID/GO-2026-1000.json": `{"id":"GO-2026-1000","affected":[]}`}
	if bad {
		delete(entries, "ID/GO-2026-1000.json")
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for n, v := range entries {
		f, err := w.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(v))
	}
	w.Close()
	return b.Bytes()
}
func TestGoDatabaseUpdateOfflineRelocationIntegrityAndAge(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	blob := dbZip(t, false)
	calls := 0
	client := &http.Client{Transport: dbTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://vuln.go.dev/vulndb.zip" || r.Header.Get("Authorization") != "" {
			t.Fatal(r)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(blob)), Header: make(http.Header)}, nil
	})}
	if err := UpdateGovulncheck(context.Background(), c, client); err != nil {
		t.Fatal(err)
	}
	s := InspectGovulncheck(c)
	if s.State != "ready" || calls != 1 {
		t.Fatal(s, calls)
	}
	// Old last-advisory modification must not make a newly downloaded DB stale.
	if s.BuiltAt.Year() != time.Now().Year() {
		t.Fatal("uses advisory date as download age")
	}
	moved := filepath.Join(t.TempDir(), "cache-moved")
	if err := os.Rename(c.Paths.Cache, moved); err != nil {
		t.Fatal(err)
	}
	c.Paths.Cache = moved
	s = InspectGovulncheck(c)
	if s.State != "ready" || !strings.HasPrefix(s.Path, moved) {
		t.Fatal(s)
	}
	metaPath := filepath.Join(moved, "govulncheck", "current.json")
	b, _ := os.ReadFile(metaPath)
	var meta goSnapshot
	json.Unmarshal(b, &meta)
	meta.DownloadedAt = time.Now().Add(-365 * 24 * time.Hour)
	store.JSON(metaPath, meta)
	if InspectGovulncheck(c).State != "stale" {
		t.Fatal("stale DB accepted")
	}
	meta.DownloadedAt = time.Now()
	store.JSON(metaPath, meta)
	os.WriteFile(filepath.Join(s.Path, "ID", "GO-2026-1000.json"), []byte("changed"), 0600)
	if InspectGovulncheck(c).State != "invalid" {
		t.Fatal("tampered DB accepted")
	}
}
func TestGoDatabaseMissingIncompleteOrExtraData(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	if InspectGovulncheck(c).State != "missing" {
		t.Fatal("missing DB accepted")
	}
	blob := dbZip(t, true)
	client := &http.Client{Transport: dbTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(blob))}, nil
	})}
	if UpdateGovulncheck(context.Background(), c, client) == nil {
		t.Fatal("incomplete database published")
	}
	if _, err := os.Stat(filepath.Join(c.Paths.Cache, "govulncheck", "current.json")); !os.IsNotExist(err) {
		t.Fatal("bad snapshot active")
	}
	blob = dbZip(t, false)
	if err := UpdateGovulncheck(context.Background(), c, client); err != nil {
		t.Fatal(err)
	}
	s := InspectGovulncheck(c)
	os.WriteFile(filepath.Join(s.Path, "extra.json"), []byte("{}"), 0600)
	if InspectGovulncheck(c).State != "invalid" {
		t.Fatal("untracked cache file accepted")
	}
}

func TestGoDatabaseBundleTransfer(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	blob := dbZip(t, false)
	client := &http.Client{Transport: dbTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(blob)), Header: make(http.Header)}, nil
	})}
	if err := UpdateGovulncheck(context.Background(), c, client); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "dbs.tar.gz")
	if err := store.ExportBundle(c.Paths.Cache, archive); err != nil {
		t.Fatal(err)
	}
	other := config.Default()
	other.ResolvePaths(t.TempDir())
	if err := store.ImportBundle(other.Paths.Cache, archive); err != nil {
		t.Fatal(err)
	}
	if got := InspectGovulncheck(other); got.State != "ready" {
		t.Fatal(got)
	}
}
