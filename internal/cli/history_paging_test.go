package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/dbstore"
	"sekscan/internal/report"
)

func TestMissingProjectStopsScanBeforeExecution(t *testing.T) {
	cleanRuntimeEnv(t)
	for _, extra := range [][]string{nil, {"--no-store"}, {"--inventory-only"}} {
		var out, errs bytes.Buffer
		args := append([]string{"scan", "dir:.", "--home", t.TempDir(), "--no-config"}, extra...)
		code := Run(context.Background(), args, &out, &errs)
		if code != 2 || !strings.Contains(errs.String(), "project is required") || strings.Contains(errs.String(), "scanner started") {
			t.Fatal(code, out.String(), errs.String())
		}
	}
	for _, value := range []string{"", " ", "bad\nname", " trailing", strings.Repeat("x", 257)} {
		if e := config.RequireProject(config.Project{Key: value}); e == nil {
			t.Fatal("invalid project", value)
		}
	}
	if e := config.RequireProject(config.Project{Key: "Payments API"}); e != nil {
		t.Fatal(e)
	}
}
func TestHistoryPagesAndComparisonEndpoints(t *testing.T) {
	ctx := context.Background()
	c := config.Default()
	c.Storage.Path = filepath.Join(t.TempDir(), "history.db")
	db, e := openReady(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	fixture, e := report.Load("../../examples/demo-report/results.json")
	if e != nil {
		t.Fatal(e)
	}
	for project := 0; project < 2; project++ {
		for i := 0; i < 4; i++ {
			r := *fixture
			r.ID = fmt.Sprintf("p%d-run%d", project, i)
			r.ProjectKey = fmt.Sprintf("service-%d", project)
			r.Namespace = c.Project.Namespace
			r.StartedAt = time.Date(2026, 9, i+1, 0, 0, 0, 0, time.UTC)
			r.FinishedAt = r.StartedAt.Add(time.Second)
			r.Branch = "main"
			if e = db.Save(ctx, config.Project{Namespace: r.Namespace, Key: r.ProjectKey}, &r, nil); e != nil {
				t.Fatal(e)
			}
		}
	}
	h := historyHandler(db, c)
	fetch := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	for _, path := range []string{"/", "/projects?project=service-0&page_size=2", "/compare?base=p0-run0&head=p0-run3&page_size=2", "/compare?base=p0-run0&head=p0-run3&view=components", "/assets/history.js", "/assets/history.css"} {
		w := fetch(path)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	root := fetch("/?tab=projects&page_size=1")
	if !strings.Contains(root.Body.String(), "Projects") || !strings.Contains(root.Body.String(), "rel=\"next\"") {
		t.Fatal(root.Body.String())
	}
	var page dbstore.Page[dbstore.ScanEntry]
	w := fetch("/api/scans?project=service-0&page=2&page_size=2")
	if e = json.Unmarshal(w.Body.Bytes(), &page); e != nil || page.Total != 4 || len(page.Items) != 2 || page.HasNext || page.Items[0].ID != "p0-run1" {
		t.Fatal(page, e, w.Body.String())
	}
	for _, path := range []string{"/?page=0", "/?page_size=201", "/?page=100001&page_size=200", "/?offset=-1", "/?page_size=1&page_size=2", "/projects", "/api/trends", "/compare?base=p0-run0&head=p1-run1", "/compare?base=p0-run3&head=p0-run1", "/compare?base=p0-run0&head=p0-run0"} {
		w := fetch(path)
		if w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	w = fetch("/api/compare?base=p0-run0&head=p0-run3&page_size=2")
	var result struct {
		Page dbstore.Page[json.RawMessage] `json:"page"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &result); e != nil || len(result.Page.Items) != 2 || result.Page.Total < 3 {
		t.Fatal(w.Body.String(), e)
	}
	w = fetch("/api/projects?namespace=private")
	if !strings.Contains(w.Body.String(), "service-0") {
		t.Fatal("namespace was not constrained")
	}
	q := url.Values{"base": {"p0-run0"}, "head": {"p0-run3"}, "q": {"<script>alert(1)</script>"}}
	w = fetch("/compare?" + q.Encode())
	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("XSS")
	}
}
