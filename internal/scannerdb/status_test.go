package scannerdb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/runner"
	"sekscan/internal/store"
)

func TestTrivyReadinessRequiresMetadataAndDatabase(t *testing.T) {
	for _, java := range []bool{false, true} {
		name := "main"
		sub, filename := "db", "trivy.db"
		if java {
			name = "java"
			sub = "java-db"
			filename = "trivy-java.db"
		}
		t.Run(name, func(t *testing.T) {
			c := config.Default()
			c.ResolvePaths(t.TempDir())
			root := filepath.Join(c.Paths.Cache, "trivy", sub)
			if got := InspectTrivy(c, java); got.State != "missing" {
				t.Fatal(got)
			}
			os.MkdirAll(root, 0700)
			writeMeta := func(stamp time.Time) {
				t.Helper()
				if err := store.JSON(filepath.Join(root, "metadata.json"), map[string]any{"Version": 2, "UpdatedAt": stamp}); err != nil {
					t.Fatal(err)
				}
			}
			writeMeta(time.Now().UTC())
			if got := InspectTrivy(c, java); got.State == "ready" {
				t.Fatal("metadata-only cache reported ready")
			}
			os.WriteFile(filepath.Join(root, filename), []byte("synthetic nonempty file; not a database"), 0600)
			if got := InspectTrivy(c, java); got.State != "ready" || !strings.Contains(got.Validation, "scanner validates schema") {
				t.Fatal(got)
			}
			writeMeta(time.Now().Add(-6 * 24 * time.Hour))
			if got := InspectTrivy(c, java); got.State != "stale" {
				t.Fatal(got)
			}
			writeMeta(time.Now().Add(time.Hour))
			if got := InspectTrivy(c, java); got.State != "stale" {
				t.Fatal(got)
			}
			os.WriteFile(filepath.Join(root, "metadata.json"), []byte(`{"unrecognized":true}`), 0600)
			if got := InspectTrivy(c, java); got.State != "invalid" {
				t.Fatal(got)
			}
		})
	}
}

type statusExecutor struct {
	data    []byte
	request runner.Request
}

func (x *statusExecutor) Run(_ context.Context, r runner.Request) (runner.Result, error) {
	if len(r.Args) == 1 {
		return runner.Result{Stdout: []byte("grype 1.2.3")}, nil
	}
	x.request = r
	return runner.Result{Stdout: x.data}, nil
}
func TestGrypeReadinessUsesNativeValidation(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := deps.NewConfigured("", c)
	exe := filepath.Join(c.Paths.Bin, "grype", "1.2.3", "grype")
	if m.GOOS == "windows" {
		exe += ".exe"
	}
	os.MkdirAll(filepath.Dir(exe), 0700)
	os.WriteFile(exe, []byte("synthetic executable"), 0700)
	hash, _ := store.SHA256(exe)
	store.JSON(filepath.Join(c.Paths.Bin, "grype", "current.json"), deps.Installed{Name: "grype", Version: "1.2.3", BinarySHA256: hash, GOOS: m.GOOS, GOARCH: m.GOARCH})
	db := filepath.Join(c.Paths.Cache, "grype", "db", "6", "vulnerability.db")
	os.MkdirAll(filepath.Dir(db), 0700)
	os.WriteFile(db, []byte("synthetic nonempty database marker"), 0600)
	x := &statusExecutor{}
	m.Executor = x
	doc := map[string]any{"valid": true, "built": time.Now().UTC(), "schemaVersion": "6.1.3", "path": db}
	set := func() { t.Helper(); x.data, _ = json.Marshal(doc) }
	set()
	got := InspectGrype(context.Background(), c, m)
	if got.State != "ready" || got.Path != db {
		t.Fatal(got)
	}
	if !strings.Contains(strings.Join(x.request.Env, "\n"), "GRYPE_DB_AUTO_UPDATE=false") {
		t.Fatal("status might update DB")
	}
	for _, arg := range []string{"db", "status", "--output", "json"} {
		if !strings.Contains(strings.Join(x.request.Args, " "), arg) {
			t.Fatal(x.request.Args)
		}
	}
	doc["valid"] = false
	set()
	if got = InspectGrype(context.Background(), c, m); got.State != "invalid" {
		t.Fatal(got)
	}
	doc["valid"] = true
	doc["path"] = filepath.Join(t.TempDir(), "wrong.db")
	set()
	if got = InspectGrype(context.Background(), c, m); got.State == "ready" {
		t.Fatal("outside cache accepted")
	}
	doc["path"] = db
	doc["built"] = time.Now().Add(-6 * 24 * time.Hour)
	set()
	if got = InspectGrype(context.Background(), c, m); got.State != "stale" {
		t.Fatal(got)
	}
	doc["built"] = time.Now().UTC()
	set()
	os.Remove(db)
	if got = InspectGrype(context.Background(), c, m); got.State == "ready" {
		t.Fatal("missing file accepted")
	}
	x.data = []byte(`{"error":"SECRET_SENTINEL"}`)
	if got = InspectGrype(context.Background(), c, m); got.State != "incompatible-output" || strings.Contains(got.Error, "SECRET_SENTINEL") {
		t.Fatal(got)
	}
}
func TestDatabaseAgeValidation(t *testing.T) {
	for _, tt := range []struct {
		built time.Time
		age   string
	}{{time.Time{}, "120h"}, {time.Now(), "bad"}, {time.Now(), "0h"}, {time.Now().Add(time.Hour), "120h"}, {time.Now().Add(-6 * 24 * time.Hour), "120h"}} {
		if checkAge(tt.built, tt.age) == nil {
			t.Fatal("accepted invalid/stale age")
		}
	}
	if err := checkAge(time.Now().Add(-time.Hour), "120h"); err != nil {
		t.Fatal(err)
	}
}
