package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sekscan/internal/config"
	"sekscan/internal/dbstore"
	"sekscan/internal/report"
	"sekscan/internal/source"
	"sekscan/internal/store"
	"strings"
	"testing"
)

func batchFixture(t *testing.T) (string, string) {
	t.Helper()
	cleanRuntimeEnv(t)
	home := t.TempDir()
	root, _ := filepath.Abs("../..")
	bin := filepath.Join(home, "fixture")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "./internal/testsupport/fakescanner/main.go")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	data, e := os.ReadFile(bin)
	if e != nil {
		t.Fatal(e)
	}
	c := config.Default()
	// This fixture isolates repository acquisition, not Go analyzer installation.
	c.Checks.Govulncheck = false
	c.Checks.Gosec = false
	c.Portable = false
	c.Project.Key = "must-not-replace-batch-project"
	c.Storage.Path = filepath.Join(home, "data", "history.db")
	for _, name := range []string{"syft", "grype", "trivy", "gitleaks"} {
		p := filepath.Join(home, name)
		if runtime.GOOS == "windows" {
			p += ".exe"
		}
		if e := os.WriteFile(p, data, 0700); e != nil {
			t.Fatal(e)
		}
		c.Tools[name] = config.Tool{Path: p, Version: "1.2.3"}
	}
	cfg := filepath.Join(home, "sekscan.json")
	if e := store.JSON(cfg, c); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SEKSCAN_FIXTURE_DIR", filepath.Join(root, "testdata", "fixtures"))
	return cfg, home
}
func TestBatchCLIContinuesAndPersists(t *testing.T) {
	if testing.Short() {
		t.Skip("external fixtures")
	}
	cfg, home := batchFixture(t)
	local := filepath.Join(home, "source with spaces")
	os.Mkdir(local, 0700)
	os.WriteFile(filepath.Join(local, "sekscan.json"), []byte("DO NOT TRUST THIS"), 0600)
	manifest := filepath.Join(home, "projects.json")
	os.WriteFile(manifest, []byte(`{"version":1,"projects":[{"project":"missing","path":"absent"},{"project":"local-app","path":"source with spaces"}]}`), 0600)
	var out, errs bytes.Buffer
	dest := filepath.Join(home, "reports")
	args := []string{"batch", manifest, "--config", cfg, "--out", dest, "--json"}
	if code := Run(context.Background(), args, &out, &errs); code != 2 {
		t.Fatal(code, out.String(), errs.String())
	}
	var result batchResult
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e, out.String())
	}
	if result.Completed != 2 || result.Incomplete != 1 || result.Failed != 1 || result.Items[0].RunID == "" || result.Items[1].Project != "local-app" {
		t.Fatal(result)
	}
	r, e := report.Load(filepath.Join(dest, result.ID, result.Items[1].ReportDir, "results.json"))
	if e != nil || r.ProjectKey != "local-app" || r.BatchID != result.ID || r.Target.Value != local || !r.Complete {
		t.Fatal(r, e)
	}
	c, e := config.Load(cfg)
	if e != nil {
		t.Fatal(e)
	}
	db, e := dbstore.Open(context.Background(), c.Storage)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	page, e := db.ProjectPage(context.Background(), dbstore.Filter{Namespace: "default", Limit: 10})
	if e != nil || page.Total != 2 {
		t.Fatal(page, e)
	}
	out.Reset()
	errs.Reset()
	if code := Run(context.Background(), append(args, "--fail-fast"), &out, &errs); code != 2 {
		t.Fatal(code)
	}
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.Skipped != 1 || result.Completed != 1 || result.Items[1].Status != "skipped" {
		t.Fatal(result)
	}
	out.Reset()
	errs.Reset()
	if code := Run(context.Background(), append(args, "--dry-run"), &out, &errs); code != 0 || !strings.Contains(out.String(), "\"valid\":true") {
		t.Fatal(code, out.String(), errs.String())
	}
	if strings.Contains(out.String(), "running") || strings.Contains(errs.String(), "scanner started") {
		t.Fatal("dry run scanned")
	}
}

type githubTestTransport func(*http.Request) (*http.Response, error)

func (f githubTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestGitHubCLIProvenanceAndOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("external fixtures")
	}
	cfg, home := batchFixture(t)
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"root/go.mod": "module test\ngo 1.23\n", "root/sekscan.json": "UNTRUSTED INVALID CONFIG"} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	sha := strings.Repeat("a", 40)
	calls := 0
	t.Setenv("PRIVATE_GH_TOKEN_SENTINEL", "SECRET_SENTINEL_CREDENTIAL")
	client := &source.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var b []byte
		if strings.Contains(r.URL.Path, "/commits/") {
			b = []byte(`{"sha":"` + sha + `"}`)
		} else if strings.Contains(r.URL.Path, "/tarball/") {
			b = archive.Bytes()
		} else {
			b = []byte(`{"default_branch":"main"}`)
		}
		if r.Header.Get("Authorization") != "Bearer SECRET_SENTINEL_CREDENTIAL" {
			t.Fatal("missing token")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b)), Request: r}, nil
	})}
	ctx := context.WithValue(context.Background(), sourceClientKey{}, client)
	var out, errs bytes.Buffer
	dest := filepath.Join(home, "remote-reports")
	args := []string{"github", "https://github.com/Org/Repo", "--config", cfg, "--token-env", "PRIVATE_GH_TOKEN_SENTINEL", "--out", dest, "--json"}
	if code := Run(ctx, args, &out, &errs); code != 1 {
		t.Fatal(code, out.String(), errs.String())
	}
	var result batchResult
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e, out.String())
	}
	item := result.Items[0]
	r, e := report.Load(filepath.Join(dest, result.ID, item.ReportDir, "results.json"))
	if e != nil || r.Source == nil || r.Source.Revision != sha || r.ProjectKey != "org/repo" || r.Revision != sha || r.Branch != "main" || r.Target.Value != "https://github.com/org/repo" || !r.Complete {
		t.Fatal(r, e)
	}
	if strings.Contains(out.String()+errs.String(), "SECRET_SENTINEL_CREDENTIAL") {
		t.Fatal("leaked credential")
	}
	oldCalls := calls
	out.Reset()
	errs.Reset()
	if code := Run(ctx, append(args, "--offline", "--ref", sha), &out, &errs); code != 1 {
		t.Fatal(code, errs.String())
	}
	if calls != oldCalls {
		t.Fatal("offline acquisition performed HTTP")
	}
	out.Reset()
	errs.Reset()
	if code := Run(ctx, append(args, "--offline", "--ref", "main"), &out, &errs); code != 2 {
		t.Fatal(code)
	}
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.Items[0].RunID == "" || result.Incomplete != 1 {
		t.Fatal(result)
	}
}
func TestBatchSchemaAndDryRunCLI(t *testing.T) {
	cleanRuntimeEnv(t)
	for _, args := range [][]string{{"batch", "schema"}, {"github:Org/Repo", "--dry-run"}, {"github", "Org/Repo", "--project", "explicit", "--dry-run"}} {
		var out, errs bytes.Buffer
		args = append(args, "--home", t.TempDir(), "--no-config")
		if code := Run(context.Background(), args, &out, &errs); code != 0 || !json.Valid(out.Bytes()) {
			t.Fatal(args, code, out.String(), errs.String())
		}
	}
	for _, args := range [][]string{{"github", "Org/Repo", "--token-env", "bad-name", "--dry-run"}, {"batch"}, {"github", "https://evil.test/o/r", "--dry-run"}} {
		var out, errs bytes.Buffer
		if code := Run(context.Background(), append(args, "--home", t.TempDir(), "--no-config"), &out, &errs); code != 2 {
			t.Fatal(fmt.Sprint(args), code)
		}
	}
}

func TestInventoryBatchWithoutHistoryRetainsIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("external fixtures")
	}
	cfg, home := batchFixture(t)
	local := filepath.Join(home, "repo")
	if err := os.Mkdir(local, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(home, "inventory.json")
	data := `{"version":1,"defaults":{"inventory_only":true,"no_store":true},"projects":[{"project":"inventory-project","path":"repo"}]}`
	if err := os.WriteFile(manifest, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	dest := filepath.Join(home, "reports")
	code := Run(context.Background(), []string{"batch", manifest, "--config", cfg, "--out", dest, "--json"}, &out, &errs)
	if code != 0 {
		t.Fatal(code, out.String(), errs.String())
	}
	var result batchResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	r, err := report.Load(filepath.Join(dest, result.ID, result.Items[0].ReportDir, "results.json"))
	if err != nil || r.ProjectKey != "inventory-project" || r.Namespace != "default" || r.BatchID != result.ID {
		t.Fatal(r, err)
	}
	if _, err = os.Stat(filepath.Join(home, "data", "history.db")); !os.IsNotExist(err) {
		t.Fatal("no-store created history", err)
	}
}

func TestPlanningDoesNotLoadOrCreateWorkspace(t *testing.T) {
	cleanRuntimeEnv(t)
	home := filepath.Join(t.TempDir(), "not-created")
	manifest := filepath.Join(t.TempDir(), "projects.json")
	if err := os.WriteFile(manifest, []byte(`{"version":1,"projects":[{"repo_url":"org/repo"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"batch", "schema"}, {"batch", "validate", manifest}, {"batch", manifest, "--dry-run"}, {"github", "org/repo", "--dry-run"}} {
		var out, errs bytes.Buffer
		args = append(args, "--home", home, "--config", filepath.Join(home, "missing.json"))
		if code := Run(context.Background(), args, &out, &errs); code != 0 {
			t.Fatal(args, code, errs.String())
		}
		if _, err := os.Stat(home); !os.IsNotExist(err) {
			t.Fatal("planning created workspace", err)
		}
	}
}
