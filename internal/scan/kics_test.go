package scan

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/model"
	"sekscan/internal/runner"
)

const kicsReport = `{"kics_version":"2.1.20","files_scanned":1,"files_parsed":1,"files_failed_to_scan":0,"queries_total":10,"queries_failed_to_execute":0,"queries_failed_to_compute_similarity_id":0,"total_counter":1,"queries":[{"query_id":"rule-1","severity":"CRITICAL","description":"SECRET_SENTINEL","files":[{"file_name":"kics-input/main.tf","line":3,"actual_value":"SECRET_SENTINEL"}]}]}`

func TestKICSParsing(t *testing.T) {
	f, err := ParseKICS([]byte(kicsReport))
	if err != nil || len(f) != 1 || f[0].Severity != "critical" {
		t.Fatal(f, err)
	}
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("source value leaked")
	}
	for _, field := range []string{"files_failed_to_scan", "queries_failed_to_execute", "queries_failed_to_compute_similarity_id"} {
		t.Run(field, func(t *testing.T) {
			f, err := ParseKICS([]byte(strings.Replace(kicsReport, `"`+field+`":0`, `"`+field+`":1`, 1)))
			if err == nil || len(f) != 1 {
				t.Fatal("partial failure lost", f, err)
			}
		})
	}
	for _, body := range []string{`{}`, `null`, strings.Replace(kicsReport, `"queries_total":10`, `"queries_total":0`, 1), strings.Replace(kicsReport, `"total_counter":1`, `"total_counter":2`, 1), strings.Replace(kicsReport, `"CRITICAL"`, `"unknown"`, 1)} {
		if _, err := ParseKICS([]byte(body)); err == nil {
			t.Fatal("invalid coverage accepted", body)
		}
	}
	_, err = ParseKICS([]byte(`{"kics_version":"2.1.20","files_scanned":0,"files_parsed":0,"files_failed_to_scan":0,"queries_total":0,"queries_failed_to_execute":0,"queries_failed_to_compute_similarity_id":0,"total_counter":0,"queries":[]}`))
	if !errors.Is(err, errKICSNotApplicable) {
		t.Fatal(err)
	}
}

func TestKICSInputSnapshotAndLocations(t *testing.T) {
	root, temp, bundle := t.TempDir(), t.TempDir(), t.TempDir()
	for _, name := range []string{"main.tf", "nested/config.yaml", "package.json", "src/main.go", "vendor/bad.tf", "excluded/bad.tf"} {
		writeInput(t, root, name)
	}
	inputs, err := selectInputs(context.Background(), model.Target{Kind: "dir", Value: root}, "iac", []string{"excluded"})
	if err != nil || len(inputs) != 3 {
		t.Fatal(inputs, err)
	}
	for _, name := range []string{"queries", "libraries"} {
		os.MkdirAll(filepath.Join(bundle, "assets", name), 0700)
	}
	args, stage, err := kicsArguments(context.Background(), root, temp, filepath.Join(bundle, "kics"), filepath.Join(temp, "kics-0.json"), inputs, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(stage, "vendor", "bad.tf")); !os.IsNotExist(err) {
		t.Fatal("excluded file copied")
	}
	for _, want := range []string{"--disable-full-descriptions", "--disable-secrets", "--enable-openapi-refs=false", "--ignore-on-exit results", "--output-name kics-0.json"} {
		if !strings.Contains(strings.Join(args, " "), want) {
			t.Fatal(args)
		}
	}
	p, err := kicsLocation(root, temp, stage, inputs, "kics-input/main.tf")
	if err != nil || p != filepath.Join(root, "main.tf") {
		t.Fatal(p, err)
	}
	for _, bad := range []string{"../main.tf", "kics-input/absent.tf", filepath.Join(root, "main.tf"), "https://example.com/main.tf"} {
		if _, err = kicsLocation(root, temp, stage, inputs, bad); err == nil {
			t.Fatal("escaped location accepted", bad)
		}
	}
	if err = os.Symlink(filepath.Join(root, "main.tf"), filepath.Join(root, "link.tf")); err == nil {
		if _, err = selectInputs(context.Background(), model.Target{Kind: "dir", Value: root}, "iac", nil); err == nil {
			t.Fatal("matching symlink accepted")
		}
	}
}

type kicsExecutor struct {
	t     *testing.T
	body  string
	calls int
}

func (x *kicsExecutor) Run(_ context.Context, q runner.Request) (runner.Result, error) {
	if len(q.Args) == 1 {
		return runner.Result{Stdout: []byte("KICS 2.1.20")}, nil
	}
	x.calls++
	if !strings.Contains(strings.Join(q.Env, "\n"), "DISABLE_CRASH_REPORT=0") {
		x.t.Fatal("crash reporting not disabled")
	}
	var dir, name string
	for i, a := range q.Args {
		if a == "--output-path" {
			dir = q.Args[i+1]
		}
		if a == "--output-name" {
			name = q.Args[i+1]
		}
	}
	return runner.Result{}, os.WriteFile(filepath.Join(dir, name), []byte(x.body), 0600)
}

func TestKICSExtension(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	bundle := t.TempDir()
	for _, name := range []string{"kics", "assets/queries/test/query.rego", "assets/libraries/common.rego"} {
		writeInput(t, bundle, name)
	}
	entry := "kics"
	if os.PathSeparator == '\\' {
		entry += ".exe"
		writeInput(t, bundle, entry)
	}
	m := deps.NewConfigured("", c)
	if _, err := m.ImportBundle(context.Background(), "kics", "2.1.20", bundle, entry, nil); err != nil {
		t.Fatal(err)
	}
	x := &kicsExecutor{t: t, body: kicsReport}
	m.Executor = x
	s := Scanner{Config: c, Deps: m, Executor: x, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	root := t.TempDir()
	writeInput(t, root, "main.tf")
	var ext config.Extension
	for _, e := range c.EffectiveExtensions() {
		if e.Name == "kics" {
			ext = e
		}
	}
	for _, fail := range []bool{false, true} {
		if fail {
			x.body = strings.Replace(kicsReport, `"queries_failed_to_execute":0`, `"queries_failed_to_execute":1`, 1)
		}
		r := &model.Report{}
		s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}, Offline: true}, t.TempDir(), "", ext, nil, time.Minute, 1<<20)
		want := "completed"
		if fail {
			want = "failed"
		}
		if r.Engines[0].Status != want || len(r.Findings) != 1 || r.Findings[0].Locations[0].Path != filepath.Join(root, "main.tf") {
			t.Fatal(r.Engines, r.Findings)
		}
	}
}

// Optional acceptance test uses an independently downloaded, verified native
// bundle. Normal tests never download or execute an upstream scanner.
func TestKICSLive(t *testing.T) {
	bundle := os.Getenv("SEKSCAN_KICS_TEST_BUNDLE")
	if bundle == "" {
		t.Skip("set SEKSCAN_KICS_TEST_BUNDLE to a verified KICS 2.1.20 bundle")
	}
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := deps.NewConfigured("", c)
	entry := "kics"
	if os.PathSeparator == '\\' {
		entry += ".exe"
	}
	if _, err := m.ImportBundle(context.Background(), "kics", "2.1.20", bundle, entry, nil); err != nil {
		t.Fatal(err)
	}
	s := Scanner{Config: c, Deps: m, Executor: runner.OSExecutor{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "main.tf"), []byte("resource \"aws_s3_bucket\" \"bad\" {\n bucket = \"test-kics\"\n acl = \"public-read\"\n}\n"), 0600)
	env, err := m.Environment(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range c.EffectiveExtensions() {
		if e.Name == "kics" {
			r := &model.Report{}
			s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}, Offline: true}, t.TempDir(), "", e, env, time.Minute, 16<<20)
			if r.Engines[0].Status != "completed" || len(r.Findings) == 0 {
				t.Fatal(r.Engines, r.Findings)
			}
			for _, f := range r.Findings {
				if f.Locations[0].Path != filepath.Join(root, "main.tf") {
					t.Fatal(f)
				}
			}
			os.Remove(filepath.Join(root, "main.tf"))
			os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"example","version":"1.0.0"}`), 0600)
			r = &model.Report{}
			s.runExtension(context.Background(), r, Options{Target: model.Target{Kind: "dir", Value: root}, Offline: true}, t.TempDir(), "", e, env, time.Minute, 16<<20)
			if r.Engines[0].Status != "skipped" || r.Engines[0].Required {
				t.Fatal(r.Engines)
			}
		}
	}
}
