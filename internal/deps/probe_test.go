package deps

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sekscan/internal/config"
	"sekscan/internal/runner"
)

type probeExecutor func(context.Context, runner.Request) (runner.Result, error)

func (f probeExecutor) Run(c context.Context, q runner.Request) (runner.Result, error) {
	return f(c, q)
}

func TestGovulncheckVersionProbeLocalSchema(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	seedRuntime(t, m, "govulncheck")
	var probe string
	m.Executor = probeExecutor(func(_ context.Context, q runner.Request) (runner.Result, error) {
		if len(q.Args) != 3 || q.Args[0] != "-db" || q.Args[2] != "-version" {
			t.Fatalf("args=%v", q.Args)
		}
		u, err := url.Parse(q.Args[1])
		if err != nil || u.Scheme != "file" {
			t.Fatal(u, err)
		}
		probe = filepath.FromSlash(u.Path)
		if m.GOOS == "windows" && len(probe) > 2 && probe[0] == '\\' {
			probe = probe[1:]
		}
		// Match upstream local-client schema discovery, not merely the probe flags.
		for _, name := range []string{"modules.json", "vulns.json", "db.json"} {
			if _, err = os.Stat(filepath.Join(probe, "index", name)); err != nil {
				return runner.Result{}, fmt.Errorf("unrecognized vulndb format")
			}
		}
		b, _ := os.ReadFile(filepath.Join(probe, "index", "modules.json"))
		if string(b) != "[]" {
			t.Fatal("not empty probe-only database")
		}
		return runner.Result{Stdout: []byte("Scanner: govulncheck@v1.2.3")}, nil
	})
	s := m.Inspect(context.Background(), "govulncheck", c.Tools["govulncheck"])
	if s.Error != "" || s.Version != "1.2.3" {
		t.Fatal(s)
	}
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Fatal("probe not cleaned up")
	}
	if _, err := os.Stat(filepath.Join(c.Paths.Cache, "govulncheck")); !os.IsNotExist(err) {
		t.Fatal("version probe populated real scan DB")
	}
}

func TestVersionProbePrivateDiagnostics(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	seedRuntime(t, m, "govulncheck")
	m.Executor = probeExecutor(func(_ context.Context, q runner.Request) (runner.Result, error) {
		return runner.Result{ExitCode: 1, Stderr: []byte("SECRET_SENTINEL")}, fmt.Errorf("scanner execution failed")
	})
	for _, enabled := range []bool{false, true} {
		if enabled {
			m.DiagnosticDir = c.Paths.Logs
		}
		s := m.Inspect(context.Background(), "govulncheck", c.Tools["govulncheck"])
		if !strings.Contains(s.Error, "version probe failed") || strings.Contains(s.Error, "SECRET_SENTINEL") {
			t.Fatal(s)
		}
		files, _ := filepath.Glob(filepath.Join(c.Paths.Logs, "govulncheck-version-stderr-*.private.log"))
		if !enabled && len(files) != 0 {
			t.Fatal("diagnostics not opt-in")
		}
		if enabled {
			if len(files) != 1 {
				t.Fatal(files)
			}
			b, _ := os.ReadFile(files[0])
			if string(b) != "SECRET_SENTINEL" {
				t.Fatal("diagnostics missing")
			}
		}
	}
}

func TestWarmGoModuleIncludesTransitiveGraph(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	seedRuntime(t, m, "go")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/app\ngo 1.23\n"), 0600); err != nil {
		t.Fatal(err)
	}
	warmed := false
	m.Executor = probeExecutor(func(_ context.Context, q runner.Request) (runner.Result, error) {
		if len(q.Args) == 1 && q.Args[0] == "version" {
			return runner.Result{Stdout: []byte("go version go1.2.3 linux/amd64")}, nil
		}
		if strings.Join(q.Args, " ") != "mod download all" || q.Dir != dir {
			t.Fatalf("unexpected command: %+v", q)
		}
		env := strings.Join(q.Env, "\n")
		if !strings.Contains(env, "GOMODCACHE="+filepath.Join(c.Paths.Cache, "go/mod")) || !strings.Contains(env, "GOSUMDB=sum.golang.org") || !strings.Contains(env, "GOTOOLCHAIN=local") {
			t.Fatal("incorrect preparation environment")
		}
		warmed = true
		return runner.Result{}, nil
	})
	if err := m.WarmGoModule(context.Background(), dir); err != nil || !warmed {
		t.Fatal(err, warmed)
	}
}
