package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sekscan/internal/config"
	"sekscan/internal/dbstore"
	"sekscan/internal/report"
	"sekscan/internal/server"
	"sekscan/internal/store"
)

func cleanRuntimeEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "TF_BUILD", "SEKSCAN_CONFIG"} {
		t.Setenv(k, "")
	}
}
func TestWorkspaceStorageHistoryCLI(t *testing.T) {
	cleanRuntimeEnv(t)
	ctx := context.Background()
	home := t.TempDir()
	call := func(args ...string) string {
		t.Helper()
		var out, err bytes.Buffer
		args = append(args, "--home", home)
		if code := Run(ctx, args, &out, &err); code != 0 {
			t.Fatalf("%v -> %d %s", args, code, err.String())
		}
		return out.String()
	}
	call("init")
	call("config", "validate")
	call("storage", "migrate")
	call("storage", "status")
	fixture, err := report.Load(filepath.Join("..", "..", "examples", "demo-report", "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The published demo now has its own immutable project identity. Create a
	// test-owned report rather than attempting to rename that imported report.
	fixture.ProjectKey, fixture.Namespace = "test-service", config.Default().Project.Namespace
	input := t.TempDir()
	if err := store.JSON(filepath.Join(input, "results.json"), fixture); err != nil {
		t.Fatal(err)
	}
	call("storage", "import", input, "--project", "test-service")
	call("storage", "import", input, "--project", "test-service")
	var page dbstore.Page[dbstore.ScanEntry]
	if e := json.Unmarshal([]byte(call("history", "list", "--json")), &page); e != nil || len(page.Items) != 1 {
		t.Fatal(page, e)
	}
	dest := filepath.Join(t.TempDir(), "export")
	call("history", "export", page.Items[0].ID, "--out", dest)
	r, e := report.Load(filepath.Join(dest, "results.json"))
	if e != nil || r.ProjectKey != "test-service" {
		t.Fatal(r, e)
	}
	// Export + re-import must not reorder/mutate the immutable snapshot.
	call("storage", "import", dest, "--project", "test-service")
	logs, _ := filepath.Glob(filepath.Join(home, "logs", "*.jsonl"))
	if len(logs) < 8 {
		t.Fatal("missing command logs", logs)
	}
	for _, p := range logs {
		b, _ := os.ReadFile(p)
		for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
			if !json.Valid(line) {
				t.Fatal("not JSONL", string(line))
			}
		}
	}
}
func TestHistoryHTTPIsolationAndEscaping(t *testing.T) {
	ctx := context.Background()
	c := config.Default()
	c.Storage.Path = filepath.Join(t.TempDir(), "db.sqlite")
	db, e := dbstore.Open(ctx, c.Storage)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	r, e := report.Load("../../examples/demo-report/results.json")
	if e != nil {
		t.Fatal(e)
	}
	p := config.Project{Namespace: c.Project.Namespace, Key: `<script>alert(1)</script>`}
	r.Namespace = p.Namespace
	r.ProjectKey = p.Key
	if e = db.Save(ctx, p, r, []dbstore.Artifact{{Name: "sbom.cdx.json", Content: []byte(`{"bomFormat":"CycloneDX"}`)}}); e != nil {
		t.Fatal(e)
	}
	other := *r
	other.ID = "other-tenant-id"
	other.Namespace = "private"
	if e = db.Save(ctx, config.Project{Namespace: "private", Key: p.Key}, &other, nil); e != nil {
		t.Fatal(e)
	}
	handler := server.SecureHandler("127.0.0.1:8080", historyHandler(db, c))
	fetch := func(path, method, host, origin string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, nil)
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	page := fetch("/?tab=projects", "GET", "127.0.0.1:8080", "")
	if page.Code != 200 || strings.Contains(page.Body.String(), `<script>alert(1)</script>`) || !strings.Contains(page.Body.String(), "&lt;script&gt;") {
		t.Fatal(page.Code, page.Body.String())
	}
	for _, tt := range []struct {
		path, method, host, origin string
		code                       int
	}{
		{"/api/scans", "GET", "127.0.0.1:8080", "", 200},
		{"/scans/" + r.ID, "GET", "127.0.0.1:8080", "", 200},
		{"/scans/" + r.ID + "/results.json", "GET", "127.0.0.1:8080", "", 200},
		{"/scans/" + r.ID + "/artifacts/sbom.cdx.json", "GET", "127.0.0.1:8080", "", 200},
		{"/scans/other-tenant-id", "GET", "127.0.0.1:8080", "", 404},
		{"/?offset=-1", "GET", "127.0.0.1:8080", "", 400},
		{"/", "GET", "evil.invalid", "", 403}, {"/", "GET", "127.0.0.1:8080", "https://evil.invalid", 403}, {"/", "POST", "127.0.0.1:8080", "", 405},
	} {
		w := fetch(tt.path, tt.method, tt.host, tt.origin)
		if w.Code != tt.code {
			t.Fatal(tt, w.Code, w.Body.String())
		}
	}
	w := fetch("/api/scans?namespace=private", "GET", "127.0.0.1:8080", "")
	if strings.Contains(w.Body.String(), other.ID) {
		t.Fatal("namespace override leaked report")
	}
}
func TestRequiredStorageFailurePreservesReportFailure(t *testing.T) {
	c := config.Default()
	c.Storage.Path = t.TempDir() // Directory, not a database file.
	r, e := report.Load("../../examples/demo-report/results.json")
	if e != nil {
		t.Fatal(e)
	}
	persistReport(context.Background(), c, r, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if r.Complete || r.ExitCode != 2 || r.Status != "incomplete" || len(r.Warnings) == 0 {
		t.Fatal(r)
	}
	c.Storage.Required = false
	r.Status = "passed"
	r.Complete = true
	r.ExitCode = 0
	persistReport(context.Background(), c, r, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !r.Complete || r.ExitCode != 0 {
		t.Fatal("optional persistence changed gate")
	}
}
func TestSessionLogsRotate(t *testing.T) {
	dir := t.TempDir()
	l, e := newSessionLog(dir)
	if e != nil {
		t.Fatal(e)
	}
	l.size = 10 << 20
	if _, e = l.Write([]byte("{\"message\":\"rotated\"}\n")); e != nil {
		t.Fatal(e)
	}
	l.Close()
	names, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(names) != 2 {
		t.Fatal(names)
	}
}
