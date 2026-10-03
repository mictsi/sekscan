package scan

import (
	"bytes"
	"context"
	"fmt"
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
	"sekscan/internal/policy"
	"sekscan/internal/runner"
	"sekscan/internal/store"
)

func TestGoInputApplicability(t *testing.T) {
	for _, tc := range []struct {
		name, target         string
		files, exclude, want []string
	}{
		{"typescript", "", []string{"package.json", "src/app.ts"}, nil, nil},
		{"metadata only", "", []string{"go.mod", "go.sum", "src/app.ts"}, nil, nil},
		{"metadata with dependency sources", "", []string{"go.mod", "node_modules/tool/main.go", "vendor/lib/lib.go", ".venv/test.go"}, nil, nil},
		{"only excluded source", "", []string{"go.mod", "src/main.go"}, []string{"src"}, nil},
		{"ignored Go package paths", "", []string{"go.mod", "testdata/example.go", ".hidden/main.go", "_fixtures/sample.go", "_main.go", ".main.go"}, nil, nil},
		{"source without module", "", []string{"main.go", "package.json"}, nil, nil},
		{"go library", "", []string{"go.mod", "pkg/lib.go"}, nil, []string{"."}},
		{"test sources still identify Go", "", []string{"go.mod", "lib_test.go"}, nil, []string{"."}},
		{"platform constraints do not conceal Go", "", []string{"go.mod", "main_windows.go"}, nil, []string{"."}},
		{"mixed language", "", []string{"package.json", "app.ts", "service/go.mod", "service/cmd/main.go"}, nil, []string{"service"}},
		{"empty parent with nested Go", "", []string{"go.mod", "app.ts", "service/go.mod", "service/main.go"}, nil, []string{"service"}},
		{"two Go modules", "", []string{"go.mod", "lib.go", "service/go.mod", "service/main.go"}, nil, []string{".", "service"}},
		{"module marker exclusion is boundary", "", []string{"go.mod", "service/go.mod", "service/main.go"}, []string{"service/go.mod"}, nil},
		{"exclude module", "", []string{"package.json", "service/go.mod", "service/main.go"}, []string{"service"}, nil},
		{"selected JS subtree must not see Go sibling", "frontend", []string{"frontend/app.ts", "backend/go.mod", "backend/main.go"}, nil, nil},
		{"no parent module search outside target", "frontend", []string{"go.mod", "frontend/helper.go"}, nil, nil},
		{"nested action Go module", "", []string{".github/actions/check/go.mod", ".github/actions/check/main.go"}, nil, []string{".github/actions/check"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, p := range tc.files {
				writeInput(t, root, p)
			}
			target := filepath.Join(root, tc.target)
			got, err := selectInputs(context.Background(), model.Target{Kind: "dir", Value: target}, "go-modules", tc.exclude)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{}
			for _, p := range tc.want {
				want = append(want, filepath.Join(root, p))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v; want %v", got, want)
			}
		})
	}
}

func TestGoInputSymlinksAndCancellation(t *testing.T) {
	for _, name := range []string{"module link", "source link"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeInput(t, root, "go.mod")
			writeInput(t, root, "main.go")
			p := "main.go"
			if name == "module link" {
				p = "go.mod"
			}
			if err := os.Remove(filepath.Join(root, p)); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), p)
			if err := os.WriteFile(outside, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, p)); err != nil {
				t.Skip("symlink unavailable:", err)
			}
			if _, err := selectInputs(context.Background(), model.Target{Kind: "dir", Value: root}, "go-modules", nil); err == nil {
				t.Fatal("matching link concealed")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := selectInputs(ctx, model.Target{Kind: "dir", Value: t.TempDir()}, "go-modules", nil); err == nil {
		t.Fatal("cancel ignored")
	}
}

type neverGoExecutor struct{ calls int }

func (x *neverGoExecutor) Run(context.Context, runner.Request) (runner.Result, error) {
	x.calls++
	return runner.Result{}, fmt.Errorf("unexpected Go invocation")
}

func TestNonGoChecksSkipBeforePrerequisitesAndDoNotFailPolicy(t *testing.T) {
	for _, withMetadata := range []bool{false, true} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("go.mod=%t legacy_extension=%t", withMetadata, custom), func(t *testing.T) {
				c := config.Default()
				c.ResolvePaths(t.TempDir())
				root := t.TempDir()
				writeInput(t, root, "src/app.ts")
				if withMetadata {
					writeInput(t, root, "go.mod")
				}
				if custom {
					c.Extensions = []config.Extension{{Name: "govulncheck", Tool: "govulncheck", Targets: []string{"dir"}, Required: true}, {Name: "gosec", Tool: "gosec", Targets: []string{"dir"}, Required: true}}
				}
				x := &neverGoExecutor{}
				manager := deps.NewConfigured("", c)
				manager.Executor = x
				var log bytes.Buffer
				s := Scanner{Config: c, Deps: manager, Executor: x, Logger: slog.New(slog.NewTextHandler(&log, nil))}
				r := &model.Report{}
				for _, e := range c.EffectiveExtensions() {
					if e.Name != "govulncheck" && e.Name != "gosec" {
						continue
					}
					s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}}, t.TempDir(), "", e, nil, time.Second, 1<<20)
				}
				if x.calls != 0 || len(r.Engines) != 2 {
					t.Fatal(x.calls, r.Engines)
				}
				for _, e := range r.Engines {
					if e.Status != "skipped" || e.Required || !strings.Contains(e.Error, "Not applicable") {
						t.Fatal(e)
					}
				}
				policy.Apply(r, c, nil, time.Now())
				if !r.Complete || r.ExitCode != 0 {
					t.Fatalf("not-applicable checks failed assessment: %+v", r)
				}
				if strings.Contains(log.String(), "level=ERROR") {
					t.Fatal(log.String())
				}
				tools, err := ToolsForTarget(context.Background(), c, model.Target{Kind: "dir", Value: root})
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range tools {
					if n == "go" || n == "gosec" || n == "govulncheck" {
						t.Fatal("non-Go runtime selected:", tools)
					}
				}
			})
		}
	}
}

func TestGoOperationalDirectoryExclusionsMatchPlanning(t *testing.T) {
	root := t.TempDir()
	c := config.Default()
	c.ResolvePaths(root)
	for _, p := range []string{"package.json", "src/main.ts", "bin/sdk/go.mod", "bin/sdk/main.go", "cache/modules/go.mod", "cache/modules/lib.go", "logs/go.mod", "logs/main.go", "data/fixture/go.mod", "data/fixture/main.go", "output/go.mod", "output/main.go"} {
		writeInput(t, root, p)
	}
	// Configure an output exclusion for planning; invocation also excludes its output.
	c.Exclude = append(c.Exclude, "output")
	tools, err := ToolsForTarget(context.Background(), c, model.Target{Kind: "dir", Value: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range tools {
		if n == "go" || n == "govulncheck" || n == "gosec" {
			t.Fatal(tools)
		}
	}
	x := &neverGoExecutor{}
	m := deps.NewConfigured("", c)
	m.Executor = x
	s := Scanner{Config: c, Deps: m, Executor: x, Logger: slog.Default()}
	r := &model.Report{}
	for _, e := range c.EffectiveExtensions() {
		if e.Name == "gosec" {
			s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}, Output: filepath.Join(root, "output")}, t.TempDir(), "", e, nil, time.Second, 1<<20)
		}
	}
	if len(r.Engines) != 1 || r.Engines[0].Status != "skipped" || x.calls != 0 {
		t.Fatal(r.Engines, x.calls)
	}
}

// A genuine analyzer failure stays incomplete. Never classify an exit code or
// missing checksum message as proof that a selected module is not Go.
type failingGoExecutor struct{}

func (failingGoExecutor) Run(_ context.Context, q runner.Request) (runner.Result, error) {
	if len(q.Args) == 1 {
		return runner.Result{Stdout: []byte("gosec 1.2.3")}, nil
	}
	return runner.Result{}, fmt.Errorf("Go module metadata or checksums are incomplete for read-only analysis")
}
func TestApplicableGoFailureStaysIncompleteAndLogsModule(t *testing.T) {
	root := t.TempDir()
	writeInput(t, root, "go.mod")
	writeInput(t, root, "main.go")
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := deps.NewConfigured("", c)
	for _, name := range []string{"go", "gosec"} {
		src := t.TempDir()
		entry := name
		if name == "go" {
			entry = "bin/go"
		}
		writeInput(t, src, entry)
		if _, err := m.ImportBundle(context.Background(), name, "1.2.3", src, entry, nil); err != nil {
			t.Fatal(err)
		}
	}
	m.Executor = failingGoExecutor{}
	var logs bytes.Buffer
	s := Scanner{Config: c, Deps: m, Executor: failingGoExecutor{}, Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	r := &model.Report{}
	for _, e := range c.EffectiveExtensions() {
		if e.Name == "gosec" {
			s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}}, t.TempDir(), "", e, nil, time.Second, 1<<20)
		}
	}
	policy.Apply(r, c, nil, time.Now())
	if r.Complete || r.ExitCode != 2 || r.Engines[0].Status != "failed" {
		t.Fatal(r)
	}
	if !strings.Contains(logs.String(), "Go module selected") || !strings.Contains(logs.String(), root) {
		t.Fatal(logs.String())
	}
	// Detection/analysis must not repair the project by writing metadata.
	b, err := store.Read(filepath.Join(root, "go.mod"), 100)
	if err != nil || string(b) != "test" {
		t.Fatal(string(b), err)
	}
	if _, err = os.Stat(filepath.Join(root, "go.sum")); !os.IsNotExist(err) {
		t.Fatal("metadata mutated", err)
	}
}

func TestNotApplicableGoDoesNotResolveOldFindings(t *testing.T) {
	c := config.Default()
	old := &model.Report{ConfigHash: c.Hash(), Findings: []model.Finding{{ID: "previous-go-finding", Fingerprint: "go-fingerprint", Category: "code", Observations: []model.Observation{{Engine: "govulncheck"}}}}}
	r := &model.Report{ConfigHash: c.Hash(), Engines: []model.EngineRun{{Name: "govulncheck", Status: "skipped", Required: false, Checks: []string{"code"}, Error: "Not applicable"}}}
	policy.Apply(r, c, old, time.Now())
	if !r.Complete || len(r.Resolved) != 0 || !strings.Contains(strings.Join(r.Warnings, "\n"), "not reverified") {
		t.Fatalf("not-applicable Go check misrepresented as remediation: %+v", r)
	}
}
