package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/dbstore"
	"sekscan/internal/report"
	"sekscan/internal/store"
)

func filterFixture(t *testing.T) (*dbstore.Store, config.Config) {
	t.Helper()
	c := config.Default()
	c.Storage.Path = filepath.Join(t.TempDir(), "history.db")
	db, err := openReady(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fixture, err := report.Load("../../examples/demo-report/results.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"service-0", "service-1", "Sekura & Design/%_"} {
		for i := 0; i < 4; i++ {
			r := *fixture
			r.ID = fmt.Sprintf("%s-run%d", strings.NewReplacer(" ", "", "&", "", "/", "", "%", "", "_", "").Replace(project), i)
			r.ProjectKey, r.Namespace, r.Branch = project, c.Project.Namespace, "main"
			r.StartedAt = time.Date(2026, 9, i+1, 0, 0, 0, 0, time.UTC)
			r.FinishedAt = r.StartedAt.Add(time.Second)
			if err := db.Save(context.Background(), config.Project{Namespace: r.Namespace, Key: r.ProjectKey}, &r,
				[]dbstore.Artifact{{Name: "sbom.cdx.json", Content: []byte(`{"bomFormat":"CycloneDX"}`)}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return db, c
}
func filterFetch(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

func TestProjectFilterHTTP(t *testing.T) {
	db, c := filterFixture(t)
	h := historyHandler(db, c)
	for _, key := range []string{"service-0", "Sekura & Design/%_"} {
		t.Run(key, func(t *testing.T) {
			query := url.Values{"project": {key}, "page_size": {"2"}, "page": {"2"}}
			w := filterFetch(h, "/api/scans?"+query.Encode())
			var p dbstore.Page[dbstore.ScanEntry]
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != 200 || p.Total != 4 || len(p.Items) != 2 {
				t.Fatalf("%s: %v", w.Body.String(), err)
			}
			for _, run := range p.Items {
				if run.Project != key {
					t.Fatal("wrong project", run)
				}
			}
			query.Del("page")
			w = filterFetch(h, "/api/projects?"+query.Encode())
			var projects dbstore.Page[dbstore.ProjectEntry]
			if err := json.Unmarshal(w.Body.Bytes(), &projects); err != nil || projects.Total != 1 || projects.Items[0].Key != key {
				t.Fatalf("%s %v", w.Body.String(), err)
			}
		})
	}
	for _, key := range []string{"service", "absent", "' OR 1=1--"} {
		w := filterFetch(h, "/api/scans?"+url.Values{"project": {key}}.Encode())
		var p dbstore.Page[dbstore.ScanEntry]
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != 200 || p.Total != 0 || len(p.Items) != 0 {
			t.Fatal("filter widened", w.Body.String(), err)
		}
	}
	for _, path := range []string{"/api/scans?project=a&project=b", "/scans/service-0-run0?project=a&project=a", "/?project=%20trailing", "/?project=" + strings.Repeat("x", 257)} {
		if w := filterFetch(h, path); w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/scans/service-1-run0?project=service-0", "/scans/service-1-run0/results.json?project=service-0", "/scans/service-1-run0/artifacts/sbom.cdx.json?project=service-0"} {
		if w := filterFetch(h, path); w.Code != 404 {
			t.Fatal("wrong-project run exposed", path, w.Code)
		}
	}
	w := filterFetch(h, "/projects?project=service-0&branch=main&page_size=2&tab=runs")
	next := regexp.MustCompile(`<a href="([^"]+)" rel="next"`).FindStringSubmatch(w.Body.String())
	if len(next) != 2 {
		t.Fatal("no next page", w.Body.String())
	}
	u, err := url.Parse(html.UnescapeString(next[1]))
	if err != nil || u.Query().Get("project") != "service-0" || u.Query().Get("branch") != "main" || u.Query().Get("page") != "2" {
		t.Fatal("filter lost during paging", next, err)
	}
	if !strings.Contains(w.Body.String(), "data-project-filter") {
		t.Fatal("missing visible selector")
	}
	w = filterFetch(h, "/api/trends?project=service-0")
	var trend dbstore.TrendResult
	if err := json.Unmarshal(w.Body.Bytes(), &trend); err != nil || trend.Total != 4 {
		t.Fatal(w.Body.String(), err)
	}
	for _, p := range trend.Points {
		if p.Project != "service-0" {
			t.Fatal("mixed-project trend")
		}
	}
	if w := filterFetch(h, "/api/compare?base=service-1-run0&head=service-1-run3&project=service-0"); w.Code != 400 {
		t.Fatal("wrong-project comparison accepted", w.Code)
	}
	w = filterFetch(h, "/compare?base=service-0-run0&head=service-0-run3&page_size=2")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "project=service-0") {
		t.Fatal("inferred comparison project not retained", w.Code)
	}
}

func TestFixedProjectHistory(t *testing.T) {
	db, c := filterFixture(t)
	h := historyHandlerForProject(db, c, "service-0")
	for _, path := range []string{"/api/projects", "/api/scans", "/api/trends", "/api/scans?project=", "/api/scans?project=service-0"} {
		w := filterFetch(h, path)
		if w.Code != 200 || strings.Contains(w.Body.String(), "service-1") || !strings.Contains(w.Body.String(), "service-0") {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	w := filterFetch(h, "/")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "readonly") || !strings.Contains(w.Body.String(), "History is filtered to project") {
		t.Fatal("fixed selection not visible", w.Body.String())
	}
	for _, path := range []string{"/api/projects?project=service-1", "/projects?project=service-1", "/compare?base=service-1-run0&head=service-1-run3"} {
		if w := filterFetch(h, path); w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/scans/service-1-run0", "/scans/service-1-run0/results.json", "/scans/service-1-run0/artifacts/sbom.cdx.json"} {
		if w := filterFetch(h, path); w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	if w := filterFetch(h, "/scans/service-0-run0/results.json"); w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestProjectFilterCLI(t *testing.T) {
	cleanRuntimeEnv(t)
	_, c := filterFixture(t)
	cfg := filepath.Join(filepath.Dir(c.Storage.Path), "sekscan.json")
	if err := store.JSON(cfg, c); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"projects", "list", "trends"} {
		var out, errs bytes.Buffer
		args := []string{"history", action, "--project", "service-0", "--json", "--config", cfg, "--page-size", "2"}
		if code := Run(context.Background(), args, &out, &errs); code != 0 || strings.Contains(out.String(), "service-1") || !strings.Contains(out.String(), "service-0") {
			t.Fatal(action, code, out.String(), errs.String())
		}
	}
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"serve", "report-directory", "--project", "service-0", "--config", cfg}, &out, &errs); code != 2 || !strings.Contains(errs.String(), "cannot be combined with a report directory") {
		t.Fatal(code, errs.String())
	}
}

func TestTargetFirstCLI(t *testing.T) {
	cleanRuntimeEnv(t)
	for _, kind := range []string{"dir", "rootfs", "image", "docker-archive", "oci-archive", "oci-layout", "sbom"} {
		t.Run(kind, func(t *testing.T) {
			var out, errs bytes.Buffer
			if code := Run(context.Background(), []string{kind + ":missing", "--help"}, &out, &errs); code != 0 || !strings.Contains(errs.String(), "required project name") {
				t.Fatal(code, errs.String())
			}
			out.Reset()
			errs.Reset()
			args := []string{kind + ":missing", "--no-config", "--home", t.TempDir(), "--no-store"}
			if code := Run(context.Background(), args, &out, &errs); code != 2 || !strings.Contains(errs.String(), "project is required") {
				t.Fatal(code, errs.String())
			}
			if args[0] != kind+":missing" {
				t.Fatal("modified caller args")
			}
		})
	}
	var out, errs bytes.Buffer
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if code := Run(context.Background(), []string{"dir:" + missing, "--project", "project", "--home", t.TempDir(), "--no-config"}, &out, &errs); code != 2 || !strings.Contains(errs.String(), "resolve scan target:") || strings.Contains(errs.String(), "scanner started") {
		t.Fatal(code, errs.String())
	}
}
