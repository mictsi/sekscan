package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sekscan/internal/batch"
	"sekscan/internal/config"
	"sekscan/internal/report"
	"sekscan/internal/store"
	"testing"
)

func TestUpgradeDefaultScannerConfigPreservesPolicyAndPins(t *testing.T) {
	cleanRuntimeEnv(t)
	home := t.TempDir()
	old := config.Default()
	old.Checks.Hadolint = false
	old.Checks.Gitleaks = false
	old.Policy.FailAt = "critical"
	tool := old.Tools["syft"]
	tool.Version = "1.2.3"
	old.Tools["syft"] = tool
	original := filepath.Join(home, "sekscan.json")
	store.JSON(original, old)
	before, _ := os.ReadFile(original)
	next := filepath.Join(home, "sekscan-expanded.json")
	var out, errs bytes.Buffer
	args := []string{"config", "enable-default-scanners", "--config", original, "--out", next}
	if code := Run(context.Background(), args, &out, &errs); code != 0 {
		t.Fatal(code, errs.String())
	}
	c, err := config.Load(next)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Checks.Hadolint || !c.Checks.Gitleaks || c.Policy.FailAt != "critical" || c.Tools["syft"].Version != "1.2.3" {
		t.Fatal(c.Checks, c.Policy)
	}
	after, _ := os.ReadFile(original)
	if !bytes.Equal(before, after) {
		t.Fatal("original config changed")
	}
	if code := Run(context.Background(), args, &out, &errs); code != 2 {
		t.Fatal("overwrite accepted")
	}
}
func TestBatchDefaultCheckOverrides(t *testing.T) {
	cleanRuntimeEnv(t)
	home := t.TempDir()
	manifest := filepath.Join(home, "projects.json")
	os.WriteFile(manifest, []byte(`{"version":1,"defaults":{"hadolint":true,"gosec":true},"projects":[{"project":"app","path":".","settings":{"hadolint":false,"zizmor":false}}]}`), 0600)
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"batch", manifest, "--no-config", "--home", home, "--dry-run", "--gosec=false"}, &out, &errs); code != 0 {
		t.Fatal(code, errs.String())
	}
	var plan struct {
		Jobs     []batch.Job `json:"jobs"`
		Projects []batch.Job `json:"projects"`
	}
	_ = json.Unmarshal(out.Bytes(), &plan)
	// The JSON schema accepts the same explicit boolean settings as runtime planning.
	m, jobs, err := batch.Load(manifest)
	_ = m
	if err != nil || len(jobs) != 1 || *jobs[0].Settings.Hadolint || *jobs[0].Settings.Zizmor {
		t.Fatal(jobs, err)
	}
	s := settingsFlags([]string{"--gosec=false"}, batch.Settings{Gosec: boolPtr(false)})
	c := configureJob(config.Default(), batch.Job{Project: "app", Settings: s})
	if c.Checks.Gosec {
		t.Fatal("explicit false lost")
	}
}
func boolPtr(b bool) *bool { return &b }
func TestScanExplicitFalseDisablesDefaultExtensions(t *testing.T) {
	cfg, home := batchFixture(t)
	source := filepath.Join(home, "source")
	os.MkdirAll(source, 0700)
	os.WriteFile(filepath.Join(source, "Dockerfile"), []byte("FROM scratch\n"), 0600)
	os.WriteFile(filepath.Join(source, "app.py"), []byte("eval(input())\n"), 0600)
	output := filepath.Join(home, "report")
	var out, errs bytes.Buffer
	args := []string{"scan", "dir:" + source, "--project", "app", "--config", cfg, "--hadolint=false", "--gitleaks=false", "--actionlint=false", "--out", output}
	if code := Run(context.Background(), args, &out, &errs); code != 1 {
		t.Fatal(code, errs.String())
	}
	r, err := report.Load(filepath.Join(output, "results.json"))
	if err != nil || !r.Complete {
		t.Fatal(err, r)
	}
	for _, e := range r.Engines {
		if e.Name == "hadolint" || e.Name == "semgrep" || e.Name == "gitleaks" || e.Name == "actionlint" {
			t.Fatal("disabled engine ran", e)
		}
	}
}
