package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/report"
	"sekscan/internal/store"
)

func TestHelpAndArgumentHandling(t *testing.T) {
	for _, args := range [][]string{{}, {"--help"}, {"version"}, {"scan", "--help"}} {
		var out, err bytes.Buffer
		if code := Run(context.Background(), args, &out, &err); code != 0 {
			t.Fatalf("%v: %d %s", args, code, err.String())
		}
	}
	var out, err bytes.Buffer
	if code := Run(context.Background(), []string{"bogus", "--home", t.TempDir()}, &out, &err); code != 2 {
		t.Fatal(code)
	}
}
func TestExternalScannerEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds external test fixtures")
	}
	root, e := filepath.Abs(filepath.Join("..", ".."))
	if e != nil {
		t.Fatal(e)
	}
	binDir := t.TempDir()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	helper := filepath.Join(binDir, "fixture"+suffix)
	cmd := exec.Command("go", "build", "-o", helper, "./internal/testsupport/fakescanner/main.go")
	cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local")
	cmd.Dir = root
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(output))
	}
	data, e := os.ReadFile(helper)
	if e != nil {
		t.Fatal(e)
	}
	c := config.Default()
	c.Portable = false
	for _, name := range []string{"syft", "grype", "trivy", "gitleaks"} {
		p := filepath.Join(binDir, name+suffix)
		if e = os.WriteFile(p, data, 0700); e != nil {
			t.Fatal(e)
		}
		c.Tools[name] = config.Tool{Path: p, Version: "1.2.3"}
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(c)
	os.WriteFile(cfgPath, b, 0600)
	t.Setenv("SEKSCAN_FIXTURE_DIR", filepath.Join(root, "testdata", "fixtures"))
	output := filepath.Join(t.TempDir(), "report")
	var stdout, stderr bytes.Buffer
	args := []string{"scan", "--project", "test-project", "dir:" + filepath.Join(root, "testdata", "project"), "--config", cfgPath, "--out", output, "--cache-dir", t.TempDir()}
	code := Run(context.Background(), args, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d %s %s", code, stdout.String(), stderr.String())
	}
	r, e := report.Load(filepath.Join(output, "results.json"))
	if e != nil {
		t.Fatal(e)
	}
	if !r.Complete || len(r.Components) != 10 || r.Summary.Reviews != 3 {
		t.Fatalf("unexpected report %+v", r.Summary)
	}
	for _, name := range report.OutputFiles {
		b, e := os.ReadFile(filepath.Join(output, name))
		if e != nil {
			t.Fatal(name, e)
		}
		if strings.Contains(string(b), "SECRET_SENTINEL") {
			t.Fatalf("secret leaked to %s", name)
		}
	}
	// A required failed scanner must produce an incomplete report, even with other findings.
	t.Setenv("SEKSCAN_FAIL_ENGINE", "grype")
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), args, &stdout, &stderr)
	if code != 2 {
		t.Fatal(code, stdout.String(), stderr.String())
	}
	r, e = report.Load(filepath.Join(output, "results.json"))
	if e != nil || r.Complete {
		t.Fatal("failed scanner reported success", e)
	}
	if strings.Contains(stderr.String(), "SECRET_SENTINEL") {
		t.Fatal("secret leaked to CLI stderr")
	}
	// A failed inventory blocks Grype; it must not masquerade as a DB failure.
	t.Setenv("SEKSCAN_FAIL_ENGINE", "syft")
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), args, &stdout, &stderr)
	if code != 2 {
		t.Fatal("failed Syft did not make scan incomplete", code)
	}
	blocked, err := report.Load(filepath.Join(output, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, engine := range blocked.Engines {
		if engine.Name == "grype" {
			found = engine.Status == "skipped" && strings.Contains(engine.Error, "Blocked by Syft failure") && strings.Contains(engine.Error, "not executed")
		}
	}
	if !found {
		t.Fatal("missing explicit dependency failure")
	}
	if strings.Contains(stderr.String(), "SECRET_SENTINEL") {
		t.Fatal("private scanner stderr leaked")
	}
	t.Setenv("SEKSCAN_FAIL_ENGINE", "")
	// Optional Gitleaks is a real external process here, but reports are fixture data.
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), append(args, "--gitleaks"), &stdout, &stderr)
	if code != 1 {
		t.Fatal(code, stderr.String())
	}
	// Move managed executables and relative configuration, then scan offline.
	managedRoot := filepath.Join(t.TempDir(), "portable-before")
	portable := config.Default()
	for _, name := range []string{"syft", "grype", "trivy", "gitleaks"} {
		executable := filepath.Join(managedRoot, "bin", name, "1.2.3", name+suffix)
		if err := os.MkdirAll(filepath.Dir(executable), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(executable, data, 0700); err != nil {
			t.Fatal(err)
		}
		hash, err := store.SHA256(executable)
		if err != nil {
			t.Fatal(err)
		}
		entry := deps.Installed{Name: name, Version: "1.2.3", Path: filepath.ToSlash(filepath.Join(name, "1.2.3", name+suffix)), BinarySHA256: hash, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
		if err = store.JSON(filepath.Join(managedRoot, "bin", name, "current.json"), entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.JSON(filepath.Join(managedRoot, "sekscan.json"), portable); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(t.TempDir(), "portable-after")
	if err := os.Rename(managedRoot, moved); err != nil {
		t.Fatal(err)
	}
	relocatedOutput := filepath.Join(t.TempDir(), "portable-report")
	portableArgs := []string{"scan", "--project", "test-project", "dir:" + filepath.Join(root, "testdata", "project"), "--config", filepath.Join(moved, "sekscan.json"), "--offline", "--out", relocatedOutput}
	stdout.Reset()
	stderr.Reset()
	if code = Run(context.Background(), portableArgs, &stdout, &stderr); code != 1 {
		t.Fatal("relocated scan", code, stderr.String())
	}
	result, err := report.Load(filepath.Join(relocatedOutput, "results.json"))
	if err != nil || !result.Complete {
		t.Fatal("relocated incomplete", err)
	}
	for _, engine := range result.Engines {
		if engine.Executable != "" && !strings.HasPrefix(engine.Executable, filepath.Join(moved, "bin")+string(os.PathSeparator)) {
			t.Fatal("nonportable execution", engine.Executable)
		}
	}
	// Managed subprocesses must scan directories outside both cwd and workspace.
	outside := filepath.Join(t.TempDir(), "Sekura DesignMCP")
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "target-marker.txt"), []byte("outside-target-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	// Target metadata is untrusted and must not replace workspace configuration.
	if err := os.WriteFile(filepath.Join(outside, "sekscan.json"), []byte("INVALID UNTRUSTED CONFIG"), 0600); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(outside)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := t.TempDir()
	for _, name := range []string{"syft", "grype", "trivy", "gitleaks"} {
		b, err := os.ReadFile(filepath.Join(root, "testdata", "fixtures", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if name == "syft" {
			var doc map[string]any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			doc["source"].(map[string]any)["metadata"].(map[string]any)["path"] = canonical
			b, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(fixtures, name+".json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.JSON(filepath.Join(fixtures, "expected-target.json"), map[string]string{"target": canonical}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEKSCAN_FIXTURE_DIR", fixtures)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
	}{
		{"absolute", []string{"scan", "dir:" + outside}},
		{"target_first_trailing_separator", []string{"dir:" + outside + string(filepath.Separator)}},
	}
	if relative, relErr := filepath.Rel(cwd, outside); relErr == nil {
		cases = append(cases, struct {
			name string
			args []string
		}{"relative_with_spaces", []string{"scan", "dir:" + relative}})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "report")
			args := append(append([]string{}, test.args...), "--project", "directory-routing", "--config", filepath.Join(moved, "sekscan.json"), "--home", moved, "--offline", "--gitleaks", "--no-store", "--out", output)
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), args, &stdout, &stderr); code != 1 {
				t.Fatalf("code=%d %s %s", code, stdout.String(), stderr.String())
			}
			r, err := report.Load(filepath.Join(output, "results.json"))
			if err != nil || !r.Complete || r.Target.Value != canonical || r.ProjectKey != "directory-routing" {
				t.Fatalf("wrong target/report: %+v %v", r, err)
			}
			if !strings.Contains(stderr.String(), "scan target resolved") {
				t.Fatal("missing resolved target diagnostic")
			}
			for _, engine := range r.Engines {
				if engine.Status == "skipped" && !engine.Required {
					continue
				} // No applicable source for conditional analyzers.
				if engine.Status != "completed" || !strings.HasPrefix(engine.Executable, filepath.Join(moved, "bin")+string(filepath.Separator)) {
					t.Fatalf("unmanaged or incomplete scanner %+v", engine)
				}
			}
		})
	}
}
func TestOutputOwnership(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "keep.txt"), []byte("keep"), 0600)
	if _, e := prepareOutput(d); e == nil {
		t.Fatal("overwrote unrelated directory")
	}
	clean := filepath.Join(t.TempDir(), "report")
	cleanup, e := prepareOutput(clean)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = prepareOutput(clean); e == nil {
		t.Fatal("concurrent output lock accepted")
	}
	cleanup()
}
