package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSemgrepRetiredDefaults(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil || bytes.Contains(b, []byte("semgrep")) || bytes.Contains(b, []byte(`"uv"`)) {
		t.Fatal(string(b), err)
	}
	for _, name := range c.RequiredTools() {
		if RemovedScanner(name) || name == "uv" {
			t.Fatal(name)
		}
	}
	for _, e := range c.EffectiveExtensions() {
		if RemovedScannerExtension(e) {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"syft", "grype", "trivy", "gitleaks", "actionlint", "hadolint", "zizmor", "gosec", "govulncheck", "go"} {
		if _, ok := c.Tools[name]; !ok {
			t.Fatal("missing remaining tool", name)
		}
	}
}

func TestLegacySemgrepConfigIgnoredBeforePathValidation(t *testing.T) {
	for _, enabled := range []string{"true", "false"} {
		t.Run(enabled, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "sekscan.json")
			raw := []byte(`{"checks":{"semgrep":` + enabled + `,"gitleaks":false},"tools":{"semgrep":{"version":"1.179.0","native_config":"/missing/private/rules.yaml"},"uv":{"version":"0.1.0"},"syft":{"version":"1.2.3"}},"policy":{"fail_at":"critical"},"extensions":[{"name":"semgrep","executable":"/private/semgrep","native_config":"/outside/rules"}]}`)
			if err := os.WriteFile(name, raw, 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(name)
			if err != nil {
				t.Fatal(err)
			}
			c.ResolvePaths(filepath.Dir(name))
			if err = c.ValidatePortable(); err != nil {
				t.Fatal(err)
			}
			if c.Checks.Gitleaks || c.Policy.FailAt != "critical" || c.Tools["syft"].Version != "1.2.3" {
				t.Fatal("unrelated settings changed")
			}
			if len(c.MigrationWarnings) != 1 || len(c.Extensions) != 0 {
				t.Fatal(c.MigrationWarnings, c.Extensions)
			}
			b, _ := json.Marshal(c)
			if bytes.Contains(b, []byte("semgrep")) || bytes.Contains(b, []byte(`"uv"`)) {
				t.Fatal(string(b))
			}
			after, _ := os.ReadFile(name)
			if !bytes.Equal(raw, after) {
				t.Fatal("source file changed")
			}
			again := c.WithoutSemgrep()
			if !reflect.DeepEqual(c, again) {
				t.Fatal("migration not idempotent")
			}
		})
	}
}

func TestRetiredExtensionAliasesAndCustomPreservation(t *testing.T) {
	for _, e := range []Extension{
		{Name: "semgrep"}, {Name: "custom", Tool: "semgrep"},
		{Name: "custom", Executable: "/bin/semgrep"}, {Name: "custom", Executable: `C:\bin\semgrep.exe`},
		{Name: "custom", RequiresTools: []string{"semgrep"}},
	} {
		c := Default()
		c.Extensions = []Extension{e}
		c.Tools["semgrep"] = Tool{Version: "latest"}
		original := len(c.Tools)
		cleaned := c.WithoutSemgrep()
		if len(cleaned.Extensions) != 0 || len(c.Extensions) != 1 || len(c.Tools) != original {
			t.Fatal("bad filtering or source mutation")
		}
		for _, ext := range c.EffectiveExtensions() {
			if RemovedScannerExtension(ext) {
				t.Fatal("legacy extension active")
			}
		}
	}
	c := Default()
	c.Tools["semgrep"] = Tool{Version: "latest"}
	c.Tools["uv"] = Tool{Version: "1.2.3"}
	custom := Extension{Name: "team-analysis", Tool: "uv", Args: []string{"run", "{output}"}, Targets: []string{"dir"}, SuccessCodes: []int{0}}
	c.Extensions = []Extension{custom}
	cleaned := c.WithoutSemgrep()
	if _, ok := cleaned.Tools["uv"]; !ok || !reflect.DeepEqual(cleaned.Extensions, []Extension{custom}) {
		t.Fatal("unrelated uv integration lost")
	}
}

func TestRetiredChecksStillRejectUnknownOrInvalidSettings(t *testing.T) {
	for _, raw := range []string{`{"checks":{"semgrep":"true"}}`, `{"checks":{"misspelled":true}}`, `{"checks":{"semgrep":false},"unknown":true}`} {
		file := filepath.Join(t.TempDir(), "sekscan.json")
		os.WriteFile(file, []byte(raw), 0600)
		if _, err := Load(file); err == nil {
			t.Fatal(raw)
		}
	}
	for _, name := range []string{"semgrep", "Semgrep.exe", "pysemgrep", "semgrep-core"} {
		if !RemovedScanner(name) {
			t.Fatal(name)
		}
	}
	if RemovedScanner("semgrep-compatible-custom") {
		t.Fatal("unrelated custom tool rejected")
	}
	c := Default()
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "MigrationWarnings") {
		t.Fatal(string(b))
	}
}
