package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sekscan/internal/config"
	"sekscan/internal/report"
	"sekscan/internal/store"
	"strings"
	"testing"
)

func TestRemoveSemgrepConfigCommandPreservesOtherSettings(t *testing.T) {
	cleanRuntimeEnv(t)
	home := t.TempDir()
	original := filepath.Join(home, "sekscan.json")
	raw := []byte(`{"version":2,"checks":{"semgrep":true,"gitleaks":false,"hadolint":false},"tools":{"semgrep":{"version":"1.179.0"},"uv":{"version":"1.2.3"},"syft":{"version":"1.2.3"}},"policy":{"fail_at":"critical"},"project":{"key":"app"}}`)
	os.WriteFile(original, raw, 0600)
	sentinel := filepath.Join(home, "bin", "semgrep", "keep.txt")
	os.MkdirAll(filepath.Dir(sentinel), 0700)
	os.WriteFile(sentinel, []byte("preserve"), 0600)
	next := filepath.Join(home, "sekscan-clean.json")
	var out, errs bytes.Buffer
	args := []string{"config", "remove-semgrep", "--config", original, "--out", next}
	if code := Run(context.Background(), args, &out, &errs); code != 0 {
		t.Fatal(code, errs.String())
	}
	if !strings.Contains(errs.String(), "legacy Semgrep settings") {
		t.Fatal("migration warning missing")
	}
	c, err := config.Load(next)
	if err != nil {
		t.Fatal(err)
	}
	if c.Checks.Gitleaks || c.Checks.Hadolint || c.Policy.FailAt != "critical" || c.Tools["syft"].Version != "1.2.3" || c.Project.Key != "app" {
		t.Fatal(c)
	}
	after, _ := os.ReadFile(original)
	if !bytes.Equal(raw, after) {
		t.Fatal("original overwritten")
	}
	after, _ = os.ReadFile(sentinel)
	if string(after) != "preserve" {
		t.Fatal("legacy installation deleted")
	}
	cleaned, _ := os.ReadFile(next)
	if bytes.Contains(cleaned, []byte("semgrep")) {
		t.Fatal(string(cleaned))
	}
	if code := Run(context.Background(), args, &out, &errs); code != 2 {
		t.Fatal("overwrite allowed")
	}
}
func TestRemovedSemgrepCLICommandsExplainRemoval(t *testing.T) {
	cleanRuntimeEnv(t)
	for _, action := range []string{"install", "status", "check", "update", "test"} {
		t.Run(action, func(t *testing.T) {
			var out, errs bytes.Buffer
			code := Run(context.Background(), []string{"deps", action, "semgrep", "--home", t.TempDir(), "--no-config", "--yes"}, &out, &errs)
			if code != 2 || !strings.Contains(errs.String(), "Semgrep support was removed") {
				t.Fatal(code, errs.String())
			}
		})
	}
}
func TestLegacyWorkspaceSourceScanNoLongerRequiresSemgrep(t *testing.T) {
	cfg, home := batchFixture(t)
	raw, _ := os.ReadFile(cfg)
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	doc["checks"].(map[string]any)["semgrep"] = true
	doc["tools"].(map[string]any)["semgrep"] = map[string]any{"version": "1.179.0", "path": "/missing/semgrep"}
	doc["tools"].(map[string]any)["uv"] = map[string]any{"version": "latest"}
	doc["extensions"] = []any{map[string]any{"name": "semgrep", "executable": "/missing/semgrep", "required": true, "targets": []string{"dir"}, "args": []string{"{output}"}, "success_codes": []int{0}}}
	if err := store.JSON(cfg, doc); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(home, "application")
	os.MkdirAll(src, 0700)
	os.WriteFile(filepath.Join(src, "app.py"), []byte("print('fixture')\n"), 0600)
	dest := filepath.Join(home, "report")
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "dir:" + src, "--project", "fixture", "--config", cfg, "--out", dest}, &out, &errs); code != 1 {
		t.Fatal(code, errs.String())
	}
	r, err := report.Load(filepath.Join(dest, "results.json"))
	if err != nil || !r.Complete {
		t.Fatal(err, r)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "Semgrep support has been removed") {
		t.Fatal("coverage migration notice missing from report")
	}
	for _, e := range r.Engines {
		if config.RemovedScanner(e.Name) {
			t.Fatal("removed scanner ran", e)
		}
	}
	for _, s := range []string{`engine=semgrep`, `"engine":"semgrep"`} {
		if strings.Contains(errs.String(), s) {
			t.Fatal(errs.String())
		}
	}
}
