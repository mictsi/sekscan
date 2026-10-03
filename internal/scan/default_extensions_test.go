package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/model"
	"sekscan/internal/runner"
	"sekscan/internal/scannerdb"
	"sekscan/internal/store"
	"strings"
	"testing"
	"time"
)

func writeInput(t *testing.T, root, path string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestDefaultExtensionSelectors(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"Dockerfile", "docker/API.Dockerfile", "docker/Dockerfile.dev", "Containerfile", "a/go.mod", "a/main.go", "b/go.mod", "b/pkg/lib.go", ".github/workflows/ci.yml", "actions/test/action.yaml", "src/main.py", "node_modules/a/Dockerfile", "vendor/foo/go.mod", "excluded/Dockerfile"} {
		writeInput(t, root, p)
	}
	for _, tc := range []struct {
		selector string
		count    int
	}{{"dockerfiles", 4}, {"go-modules", 2}, {"workflows", 2}, {"source", 1}} {
		t.Run(tc.selector, func(t *testing.T) {
			inputs, err := selectInputs(context.Background(), model.Target{Kind: "dir", Value: root}, tc.selector, []string{"excluded"})
			if err != nil || len(inputs) != tc.count {
				t.Fatal(inputs, err)
			}
		})
	}
	inputs, err := selectInputs(context.Background(), model.Target{Kind: "image", Value: "test:tag"}, "all", nil)
	if err != nil || len(inputs) != 1 {
		t.Fatal(inputs, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = selectInputs(ctx, model.Target{Kind: "dir", Value: root}, "source", nil); err == nil {
		t.Fatal("cancel ignored")
	}
	if err = os.Symlink(filepath.Join(root, "Dockerfile"), filepath.Join(root, "Dockerfile.link")); err == nil {
		if _, err = selectInputs(context.Background(), model.Target{Kind: "dir", Value: root}, "dockerfiles", nil); err == nil {
			t.Fatal("matching symlink accepted")
		}
	}
}
func TestExtendedParserCompletenessAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		count      int
		bad        bool
	}{
		{"hadolint", `[{"code":"DL3007","level":"warning","file":"Dockerfile","line":1,"message":"SECRET_SENTINEL"}]`, 1, false},
		{"hadolint", `[]`, 0, false}, {"hadolint", `{}`, 0, true}, {"hadolint", `[{"code":"DL1000","level":"error","file":"Dockerfile","line":1}]`, 1, true},
		{"gosec", `{"Golang errors":{},"Issues":[{"severity":"HIGH","rule_id":"G101","file":"main.go","line":"1-3","details":"SECRET_SENTINEL"}],"Stats":{"files":1,"lines":3}}`, 1, false},
		{"gosec", `{"Golang errors":{"main.go":[{}]},"Issues":[],"Stats":{"files":1}}`, 0, true},
		{"gosec", `{"Golang errors":{},"Issues":[],"Stats":{"files":0}}`, 0, true},
		{"gosec", `{"Issues":[],"Stats":{"files":1}}`, 0, true},
	} {
		t.Run(fmt.Sprint(tc.name, tc.count, tc.bad, len(tc.body)), func(t *testing.T) {
			var f []model.Finding
			var err error
			if tc.name == "hadolint" {
				f, err = ParseHadolint([]byte(tc.body))
			} else {
				f, err = ParseGosec([]byte(tc.body))
			}
			if (err != nil) != tc.bad || len(f) != tc.count {
				t.Fatal(f, err)
			}
			b, _ := json.Marshal(f)
			if strings.Contains(string(b), "SECRET_SENTINEL") {
				t.Fatal("source text leaked")
			}
		})
	}
	if _, err := ParseSARIF([]byte(`{"version":"2.1.0","runs":[{"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[{"level":"error"}]}],"results":[]}]}`), "custom-sast"); err == nil {
		t.Fatal("SARIF execution error ignored")
	}
}

type defaultExecutor struct {
	calls      []runner.Request
	failSecond bool
}

func (x *defaultExecutor) Run(_ context.Context, q runner.Request) (runner.Result, error) {
	if len(q.Args) == 1 {
		return runner.Result{Stdout: []byte("tool 1.2.3")}, nil
	}
	x.calls = append(x.calls, q)
	if x.failSecond && len(x.calls) == 2 {
		return runner.Result{}, fmt.Errorf("fixture failure")
	}
	input := q.Args[len(q.Args)-1]
	b, _ := json.Marshal([]map[string]any{{"code": "DL3007", "level": "warning", "file": input, "line": 1, "message": "SECRET_SENTINEL"}})
	return runner.Result{Stdout: b}, nil
}
func TestHadolintDefaultControlledInvocationAndPartialFailure(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	root := t.TempDir()
	writeInput(t, root, "Dockerfile")
	writeInput(t, root, "docker/Dockerfile.dev")
	m := deps.NewConfigured("", c)
	exe := filepath.Join(c.Paths.Bin, "hadolint", "1.2.3", "hadolint")
	if m.GOOS == "windows" {
		exe += ".exe"
	}
	os.MkdirAll(filepath.Dir(exe), 0700)
	os.WriteFile(exe, []byte("fixture"), 0700)
	hash, _ := store.SHA256(exe)
	store.JSON(filepath.Join(c.Paths.Bin, "hadolint", "current.json"), deps.Installed{Name: "hadolint", Version: "1.2.3", BinarySHA256: hash})
	x := &defaultExecutor{}
	m.Executor = x
	s := Scanner{Config: c, Deps: m, Executor: x, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	e := c.EffectiveExtensions()[0]
	r := &model.Report{}
	s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}}, t.TempDir(), "", e, nil, time.Second, 1<<20)
	if len(x.calls) != 2 || r.Engines[0].Status != "completed" || len(r.Findings) != 2 {
		t.Fatal(r, x.calls)
	}
	for _, q := range x.calls {
		if q.Dir == root || !reflect.DeepEqual(q.SuccessCodes, []int{0}) || !strings.Contains(strings.Join(q.Args, " "), "--disable-ignore-pragma") {
			t.Fatal(q)
		}
	}
	x.calls = nil
	x.failSecond = true
	r = &model.Report{}
	s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}}, t.TempDir(), "", e, nil, time.Second, 1<<20)
	if r.Engines[0].Status != "failed" || len(r.Findings) != 1 || !r.Engines[0].Required {
		t.Fatal(r)
	}
}
func TestDefaultExtensionsIrrelevantVersusMissing(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	s := Scanner{Config: c, Deps: deps.NewConfigured("", c), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	root := t.TempDir()
	e := c.EffectiveExtensions()[0]
	r := &model.Report{}
	s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}}, t.TempDir(), "", e, nil, time.Second, 1<<20)
	if r.Engines[0].Status != "skipped" || r.Engines[0].Required {
		t.Fatal(r)
	}
	writeInput(t, root, "Dockerfile")
	r = &model.Report{}
	s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}}, t.TempDir(), "", e, nil, time.Second, 1<<20)
	if r.Engines[0].Status != "failed" || !r.Engines[0].Required {
		t.Fatal(r)
	}
	tools, err := ToolsForTarget(context.Background(), c, model.Target{Kind: "image", Value: "a:latest"})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range tools {
		if n == "hadolint" || n == "go" {
			t.Fatal(tools)
		}
	}
}

type extensionTestTransport func(*http.Request) (*http.Response, error)

func (f extensionTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type selectedExtensionExecutor struct {
	name, root string
	calls      []runner.Request
}

func (x *selectedExtensionExecutor) Run(_ context.Context, q runner.Request) (runner.Result, error) {
	if len(q.Args) == 1 || (len(q.Args) == 3 && q.Args[2] == "-version") {
		return runner.Result{Stdout: []byte("Scanner: govulncheck@v1.2.3")}, nil
	}
	x.calls = append(x.calls, q)
	input := filepath.Join(x.root, "app.py")
	if x.name == "zizmor" {
		input, _ = filepath.Rel(x.root, q.Args[len(q.Args)-1])
		input = filepath.ToSlash(input)
	}
	if x.name == "gosec" || x.name == "govulncheck" {
		input = filepath.Join(q.Dir, "main.go")
	}
	loc := map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": input}, "region": map[string]any{"startLine": 1}}}
	item := map[string]any{"ruleId": "TEST001", "level": "warning", "message": map[string]any{"text": "SECRET_SENTINEL"}, "locations": []any{loc}}
	b, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{"results": []any{item}, "invocations": []any{map[string]any{"executionSuccessful": true}}}}})
	if x.name == "gosec" {
		b, _ = json.Marshal(map[string]any{"Golang errors": map[string]any{}, "Issues": []any{map[string]any{"severity": "HIGH", "rule_id": "G101", "file": input, "line": "1", "details": "SECRET_SENTINEL"}}, "Stats": map[string]any{"files": 1}})
	}
	for i, a := range q.Args {
		if (a == "-out" || a == "--sarif-output" || a == "--output") && i+1 < len(q.Args) {
			return runner.Result{}, os.WriteFile(q.Args[i+1], b, 0600)
		}
	}
	return runner.Result{Stdout: b}, nil
}
func TestAllDefaultExtensionInvocations(t *testing.T) {
	for _, name := range []string{"zizmor", "gosec", "govulncheck"} {
		t.Run(name, func(t *testing.T) {
			c := config.Default()
			c.ResolvePaths(t.TempDir())
			root := t.TempDir()
			for _, p := range []string{"app.py", "go.mod", "main.go", "nested/go.mod", "nested/main.go", ".github/workflows/ci.yml"} {
				writeInput(t, root, p)
			}
			m := deps.NewConfigured("", c)
			for _, tool := range []string{name, "go"} {
				src := t.TempDir()
				entry := tool
				if runtime.GOOS == "windows" {
					entry += ".exe"
				}
				if tool == "go" {
					entry = "bin/go"
					if runtime.GOOS == "windows" {
						entry += ".exe"
					}
				}
				bundlePath := filepath.Join(src, filepath.FromSlash(entry))
				os.MkdirAll(filepath.Dir(bundlePath), 0700)
				os.WriteFile(bundlePath, []byte("fixture"), 0700)
				if _, err := m.ImportBundle(context.Background(), tool, "1.2.3", src, entry, nil); err != nil {
					t.Fatal(err)
				}
			}
			if name == "govulncheck" {
				var archive bytes.Buffer
				z := zip.NewWriter(&archive)
				for path, body := range map[string]string{"index/db.json": `{"modified":"2026-01-01T00:00:00Z"}`, "index/modules.json": `[{"path":"stdlib","vulns":[{"id":"GO-2026-1000"}]}]`, "index/vulns.json": `[{"id":"GO-2026-1000"}]`, "ID/GO-2026-1000.json": `{"id":"GO-2026-1000","affected":[]}`} {
					f, _ := z.Create(path)
					f.Write([]byte(body))
				}
				z.Close()
				client := &http.Client{Transport: extensionTestTransport(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive.Bytes())), Header: make(http.Header)}, nil
				})}
				if err := scannerdb.UpdateGovulncheck(context.Background(), c, client); err != nil {
					t.Fatal(err)
				}
			}
			x := &selectedExtensionExecutor{name: name, root: root}
			m.Executor = x
			s := Scanner{Config: c, Deps: m, Executor: x, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			env, err := m.Environment(true)
			if err != nil {
				t.Fatal(err)
			}
			r := &model.Report{}
			for _, e := range c.EffectiveExtensions() {
				if e.Name == name {
					s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}, Offline: true}, t.TempDir(), "", e, env, time.Second, 1<<20)
				}
			}
			want := 1
			if name == "gosec" || name == "govulncheck" {
				want = 2
			}
			if len(r.Engines) != 1 || r.Engines[0].Status != "completed" || len(x.calls) != want || len(r.Findings) != want {
				t.Fatalf("report=%+v engines=%+v calls=%d", r, r.Engines, len(x.calls))
			}
			b, _ := json.Marshal(r.Findings)
			if strings.Contains(string(b), "SECRET_SENTINEL") {
				t.Fatal("message leak")
			}
			for _, q := range x.calls {
				args := strings.Join(q.Args, " ")
				env := strings.Join(q.Env, "\n")
				if name == "govulncheck" && !strings.Contains(args, "-db file:///") {
					t.Fatal(q.Args)
				}
				if name == "gosec" || name == "govulncheck" {
					if !strings.Contains(env, "GOPROXY=off") || !strings.Contains(env, "GOROOT="+filepath.Join(c.Paths.Bin, "go", "1.2.3")) {
						t.Fatal("Go not isolated")
					}
				}

				if name == "zizmor" && (!strings.Contains(args, "--offline") || !strings.Contains(args, "--no-config")) {
					t.Fatal(q.Args)
				}
			}
		})
	}
}
