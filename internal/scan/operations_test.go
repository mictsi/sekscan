package scan

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/model"
	"sekscan/internal/runner"
	"sekscan/internal/store"
)

func TestSyftExclusionsAreTargetRelative(t *testing.T) {
	want := []string{"./.git", "./.git/**", "./security-report", "./security-report/**"}
	for _, kind := range []string{"dir", "rootfs"} {
		if got := syftExclusions(kind, []string{".git", "security-report", "./.git", ".", "../escape"}); !reflect.DeepEqual(got, want) {
			t.Fatal(kind, got)
		}
	}
	if got := syftExclusions("image", []string{"tmp"}); !reflect.DeepEqual(got, []string{"/tmp", "/tmp/**"}) {
		t.Fatal(got)
	}
}
func TestActionlintParserAndPrivacy(t *testing.T) {
	good := []byte(`{"sekscan_actionlint":1,"findings":[{"kind":"expression","message":"SECRET_SENTINEL","filepath":".github/workflows/a.yml","line":3}]}`)
	out, err := ParseActionlint(good)
	if err != nil || len(out) != 1 || out[0].RuleID != "actionlint:expression" {
		t.Fatal(out, err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("source message leaked")
	}
	for _, raw := range []string{`{"sekscan_actionlint":1,"findings":[]}`, `{"sekscan_actionlint":1,"findings":null}`} {
		out, err = ParseActionlint([]byte(raw))
		if err != nil || len(out) != 0 {
			t.Fatal(out, err)
		}
	}
	for _, raw := range []string{``, `{}`, `[]`, `{"sekscan_actionlint":1}`, `{"sekscan_actionlint":2,"findings":[]}`, `{"sekscan_actionlint":1,"findings":[{}]}`} {
		if _, err = ParseActionlint([]byte(raw)); err == nil {
			t.Fatal("accepted invalid output", raw)
		}
	}
}

type actionExecutor struct {
	target string
	called bool
}

func (x *actionExecutor) Run(_ context.Context, r runner.Request) (runner.Result, error) {
	if len(r.Args) == 1 && r.Args[0] == "-version" {
		return runner.Result{Stdout: []byte("actionlint 1.2.3")}, nil
	}
	x.called = true
	for _, must := range []string{"-config-file", "-shellcheck=", "-pyflakes=", "-format", actionlintFormat, "--"} {
		found := false
		for _, arg := range r.Args {
			if arg == must {
				found = true
			}
		}
		if !found {
			return runner.Result{}, io.ErrUnexpectedEOF
		}
	}
	rel, _ := filepath.Rel(r.Dir, filepath.Join(x.target, ".github", "workflows", "ci.yml"))
	b, _ := json.Marshal(map[string]any{"sekscan_actionlint": 1, "findings": []any{map[string]any{"kind": "expression", "filepath": rel, "line": 5, "message": "SECRET_SENTINEL"}}})
	return runner.Result{Stdout: b, ExitCode: 1}, nil
}
func TestActionlintControlledInvocation(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	target := t.TempDir()
	wd := filepath.Join(target, ".github", "workflows")
	os.MkdirAll(wd, 0700)
	os.WriteFile(filepath.Join(wd, "ci.yml"), []byte("name: fixture"), 0600)
	m := deps.NewConfigured("", c)
	exe := filepath.Join(c.Paths.Bin, "actionlint", "1.2.3", "actionlint")
	if m.GOOS == "windows" {
		exe += ".exe"
	}
	os.MkdirAll(filepath.Dir(exe), 0700)
	os.WriteFile(exe, []byte("fake"), 0700)
	hash, _ := store.SHA256(exe)
	store.JSON(filepath.Join(c.Paths.Bin, "actionlint", "current.json"), deps.Installed{Name: "actionlint", Version: "1.2.3", BinarySHA256: hash})
	x := &actionExecutor{target: target}
	m.Executor = x
	s := Scanner{Config: c, Deps: m, Executor: x, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r := &model.Report{}
	temp := t.TempDir()
	os.WriteFile(filepath.Join(temp, "empty.yaml"), []byte("{}"), 0600)
	s.runActionlint(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: target}}, temp, nil, time.Second, 1<<20)
	if !x.called || len(r.Engines) != 1 || r.Engines[0].Status != "completed" || len(r.Findings) != 1 {
		t.Fatal(r)
	}
	if r.Findings[0].Locations[0].Path != filepath.Join(wd, "ci.yml") {
		t.Fatal("relative location was not resolved")
	}
	x.called = false
	r = &model.Report{}
	s.Config.Exclude = []string{".github"}
	s.runActionlint(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: target}}, temp, nil, time.Second, 1<<20)
	if x.called || r.Engines[0].Status != "skipped" {
		t.Fatal("excluded workflow scanned")
	}
}
func TestDiagnosticStderrOptIn(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	s := Scanner{Config: c, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.saveDiagnostics("syft", []byte("sensitive test fixture"))
	if _, err := os.Stat(c.Paths.Logs); !os.IsNotExist(err) {
		t.Fatal("diagnostics written by default")
	}
	s.Config.DiagnosticStderr = true
	s.saveDiagnostics("syft", []byte("sensitive test fixture"))
	entries, err := os.ReadDir(c.Paths.Logs)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
}
