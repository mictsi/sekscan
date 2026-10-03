package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"sekscan/internal/dbstore"
	"sekscan/internal/store"
)

func TestPortfolioViewsAndScope(t *testing.T) {
	db, c := filterFixture(t)
	h := historyHandler(db, c)
	for _, tc := range []struct{ path, have, absent string }{
		{"/", "id=\"portfolio-projects\"", "id=\"projects-table\""},
		{"/?tab=projects", "id=\"projects-table\"", "id=\"chart-findings\""},
		{"/?tab=runs", "id=\"runs-table\"", "id=\"portfolio-projects\""},
		{"/projects?project=service-0", "id=\"tab-panel\"", "id=\"runs-table\""},
		{"/projects?project=service-0&tab=runs", "id=\"runs-table\"", "id=\"window-incomplete\""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := filterFetch(h, tc.path)
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, tc.have) || strings.Contains(body, tc.absent) {
				t.Fatal(w.Code, body)
			}
		})
	}
	for _, path := range []string{"/api/portfolio?days=7", "/api/portfolio?days=7&tab=projects"} {
		w := filterFetch(h, path)
		var p dbstore.PortfolioResult
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != 200 || p.Current.Projects != 3 || len(p.Points) != 7 {
			t.Fatal(path, w.Code, p, err)
		}
	}
	locked := historyHandlerForProject(db, c, "service-0")
	w := filterFetch(locked, "/api/portfolio?days=7")
	var p dbstore.PortfolioResult
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Current.Projects != 1 {
		t.Fatal(p, err)
	}
	for _, path := range []string{"/api/portfolio?project=service-1", "/api/portfolio?days=91", "/api/portfolio?status=passed", "/?tab=invalid", "/?tab=runs&tab=overview", "/projects?project=service-0&tab=findings"} {
		if w := filterFetch(locked, path); w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/assets/sekura.css", "/assets/ui.js"} {
		w := filterFetch(h, path)
		if w.Code != 200 || len(w.Body.Bytes()) == 0 {
			t.Fatal(path, w.Code)
		}
	}
	w = filterFetch(h, "/scans/service-0-run0")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "data-history-project") || !strings.Contains(w.Body.String(), "--sk-color-surface-base") {
		t.Fatal("stored report not using shared design", w.Code)
	}
}
func TestTabLinksRemoveHiddenFilters(t *testing.T) {
	p := historyPage{Mode: "projects", Tab: "runs", URLPath: "/", RawQuery: "status=passed&kind=dir&from=2026-09-01&branch=main&q=revision&page=3", Project: "service-0"}
	u, _ := url.Parse(p.TabLink("overview"))
	q := u.Query()
	if q.Get("status") != "" || q.Get("q") != "" || q.Get("page") != "" || q.Get("branch") != "main" || q.Get("project") != "service-0" {
		t.Fatal(q)
	}
	u, _ = url.Parse(p.TabLink("projects"))
	q = u.Query()
	if q.Get("kind") != "" || q.Get("from") != "" || q.Get("branch") != "" {
		t.Fatal("hidden filters retained", q)
	}
}
func TestPortfolioCLIUsesAllProjectsByDefault(t *testing.T) {
	cleanRuntimeEnv(t)
	_, c := filterFixture(t)
	c.Project.Key = "service-0" // Configuration does not implicitly hide other projects.
	cfg := filepath.Join(filepath.Dir(c.Storage.Path), "sekscan.json")
	if err := store.JSON(cfg, c); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args     []string
		projects int
	}{
		{nil, 3}, {[]string{"--project", "service-0"}, 1},
	} {
		var out, errs bytes.Buffer
		args := append([]string{"history", "portfolio", "--json", "--days", "7", "--config", cfg}, tc.args...)
		if code := Run(context.Background(), args, &out, &errs); code != 0 {
			t.Fatal(code, errs.String())
		}
		var p dbstore.PortfolioResult
		if err := json.Unmarshal(out.Bytes(), &p); err != nil || p.Current.Projects != tc.projects {
			t.Fatal(p, err)
		}
	}
}
