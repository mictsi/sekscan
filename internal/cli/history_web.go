package cli

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"sekscan/internal/config"
	"sekscan/internal/dbstore"
	"sekscan/internal/history"
	"sekscan/internal/report"
	"sekscan/internal/server"
	"sekscan/internal/ui"
)

//go:embed historyweb/*
var historyAssets embed.FS
var historyTemplate = template.Must(template.New("history.html").Funcs(template.FuncMap{
	"shell": historyShell,
	"short": func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	},
	"signed":     func(n int) string { return fmt.Sprintf("%+d", n) },
	"json":       func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) },
	"projectURL": func(p string) string { return "/projects?" + url.Values{"project": {p}}.Encode() },
	"scanURL": func(id, project string) string {
		return "/scans/" + url.PathEscape(id) + "?" + url.Values{"project": {project}}.Encode()
	},
	"stateLabel": func(s string) string {
		if s == "resolved" {
			return "No longer reported"
		}
		return s
	},
}).ParseFS(historyAssets, "historyweb/history.html"))

type pageNav struct {
	Total, Number, Count, Size, Start, End int
	First, Previous, Next, Last            string
}
type historyPage struct {
	Namespace, Driver, Mode, Title, Project, Query, Branch, Status, Kind, From, To string
	Size, TrendLimit                                                               int
	Pager                                                                          pageNav
	Projects                                                                       dbstore.Page[dbstore.ProjectEntry]
	Runs                                                                           dbstore.Page[dbstore.ScanEntry]
	Trends                                                                         dbstore.TrendResult
	Comparison                                                                     *history.Result
	Changes                                                                        dbstore.Page[history.Change]
	Components                                                                     dbstore.Page[history.ComponentChange]
	Base, Head, View, State, Severity, Category                                    string
	ChartData                                                                      template.JS
	LockedProject                                                                  string
	Tab, URLPath, RawQuery, PortfolioError                                         string
	Days                                                                           int
	Portfolio                                                                      dbstore.PortfolioResult
}

// historyShell and the report renderer use the same escaped presentation template.
func historyShell(p historyPage) (template.HTML, error) {
	o := ui.ShellOptions{Project: p.Project, Namespace: p.Namespace, Driver: p.Driver}
	o.Breadcrumbs = []ui.Crumb{{Label: "Portfolio", URL: "/"}}
	switch p.Mode {
	case "runs":
		o.Active = "project-" + p.Tab
		label := "Dashboard"
		if p.Tab == "runs" {
			label = "Runs"
		}
		o.Breadcrumbs = append(o.Breadcrumbs, ui.Crumb{Label: p.Project, URL: o.ProjectURL(), Project: true}, ui.Crumb{Label: label})
	case "compare":
		o.Active, o.OpenLabel, o.OpenURL = "compare", "Run comparison", p.URLPath+"?"+p.RawQuery
		o.Breadcrumbs = append(o.Breadcrumbs, ui.Crumb{Label: p.Project, URL: o.ProjectURL(), Project: true}, ui.Crumb{Label: "Compare runs"})
	default:
		o.Active = "portfolio"
		if p.Tab == "projects" {
			o.Active = "projects"
			o.Breadcrumbs = append(o.Breadcrumbs, ui.Crumb{Label: "Projects"})
		}
		if p.Tab == "runs" {
			o.Active = "all-runs"
			o.Breadcrumbs = append(o.Breadcrumbs, ui.Crumb{Label: "All runs"})
		}
		if o.Active == "portfolio" {
			o.Breadcrumbs[0].URL = ""
		}
	}
	return ui.Shell(o)
}

// TabLink preserves scope and selection while resetting table pagination.
func (p historyPage) TabLink(tab string) string {
	q, _ := url.ParseQuery(p.RawQuery)
	q.Set("tab", tab)
	q.Del("page")
	q.Del("offset")
	if p.Project != "" {
		q.Set("project", p.Project)
	}
	if p.Base != "" {
		q.Set("base", p.Base)
	}
	if p.Head != "" {
		q.Set("head", p.Head)
	}
	if p.Mode == "compare" {
		q.Del("state")
		q.Del("severity")
		q.Del("category")
		q.Del("q")
		q.Set("view", "findings")
		if tab == "components" {
			q.Set("view", "components")
		}
	}
	if (p.Mode == "projects" || p.Mode == "runs") && tab == "overview" {
		q.Del("status")
	}
	if p.Mode == "projects" {
		if tab == "projects" {
			for _, key := range []string{"branch", "kind", "status", "from", "to", "days"} {
				q.Del(key)
			}
		}
		if tab != p.Tab && (p.Tab == "runs" || tab == "runs") {
			q.Del("q")
		}
	}
	return p.URLPath + "?" + q.Encode()
}
func (p historyPage) PortfolioAPI() string {
	q, _ := url.ParseQuery(p.RawQuery)
	q.Del("tab")
	q.Del("status")
	return "/api/portfolio?" + q.Encode()
}
func validTab(q url.Values, def string, choices ...string) (string, error) {
	if len(q["tab"]) > 1 {
		return "", fmt.Errorf("duplicate tab")
	}
	tab := q.Get("tab")
	if tab == "" {
		tab = def
	}
	for _, v := range choices {
		if tab == v {
			return tab, nil
		}
	}
	return "", fmt.Errorf("unknown tab")
}
func jsonScript(v any) template.JS { b, _ := json.Marshal(v); return template.JS(b) } // encoding/json HTML-escapes <, >, &, U+2028/2029.
func projectFilter(q url.Values) (string, error) {
	if len(q["project"]) > 1 {
		return "", fmt.Errorf("duplicate project filter")
	}
	project := q.Get("project")
	if project != "" {
		if err := config.RequireProject(config.Project{Key: project}); err != nil {
			return "", fmt.Errorf("invalid project filter: %w", err)
		}
	}
	return project, nil
}

func pageFilter(q url.Values, ns string) (dbstore.Filter, error) {
	if _, err := projectFilter(q); err != nil {
		return dbstore.Filter{}, err
	}
	size, err := queryInt(q, "page_size", 25, 1, 200)
	if err != nil {
		return dbstore.Filter{}, err
	}
	page, err := queryInt(q, "page", 1, 1, 100001)
	if err != nil {
		return dbstore.Filter{}, err
	}
	offset := (page - 1) * size
	if q.Get("offset") != "" {
		if q.Get("page") != "" {
			return dbstore.Filter{}, fmt.Errorf("use page or offset, not both")
		}
		offset, err = queryInt(q, "offset", 0, 0, 100000)
		if err != nil {
			return dbstore.Filter{}, err
		}
	}
	if offset > 100000 {
		return dbstore.Filter{}, fmt.Errorf("pagination exceeds 100000 records; narrow the filters")
	}
	f := dbstore.Filter{Namespace: ns, Project: q.Get("project"), Query: q.Get("q"), Branch: q.Get("branch"), Status: q.Get("status"), TargetKind: q.Get("kind"), From: q.Get("from"), To: q.Get("to"), Limit: size, Offset: offset}
	return f, nil
}
func queryInt(q url.Values, key string, def, min, max int) (int, error) {
	if len(q[key]) > 1 {
		return 0, fmt.Errorf("duplicate %s", key)
	}
	raw := q.Get(key)
	if raw == "" {
		return def, nil
	}
	v, e := strconv.Atoi(raw)
	if e != nil || v < min || v > max {
		return 0, fmt.Errorf("%s must be %d..%d", key, min, max)
	}
	return v, nil
}
func navigation[T any](r *http.Request, p dbstore.Page[T]) pageNav {
	nav := pageNav{Total: p.Total, Number: p.Page, Count: p.PageCount, Size: p.PageSize}
	if len(p.Items) > 0 {
		nav.Start = p.Offset + 1
		nav.End = p.Offset + len(p.Items)
	}
	link := func(page int) string {
		q := r.URL.Query()
		q.Del("offset")
		q.Set("page", strconv.Itoa(page))
		q.Set("page_size", strconv.Itoa(p.PageSize))
		return r.URL.Path + "?" + q.Encode()
	}
	if p.HasPrevious {
		nav.First = link(1)
		nav.Previous = link(p.Page - 1)
	}
	if p.HasNext && p.Page*p.PageSize <= 100000 {
		nav.Next = link(p.Page + 1)
	}
	if p.HasNext && (p.PageCount-1)*p.PageSize <= 100000 {
		nav.Last = link(p.PageCount)
	}
	return nav
}
func slicePage[T any](items []T, size, offset int) dbstore.Page[T] {
	total := len(items)
	start := offset
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return dbstore.NewPage(items[start:end], total, size, offset)
}
func writeHistory(w http.ResponseWriter, page historyPage) {
	var b bytes.Buffer
	if e := historyTemplate.ExecuteTemplate(&b, "history.html", page); e != nil {
		http.Error(w, "render failed", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	_, _ = w.Write(b.Bytes())
}
func writeHistoryJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func loadComparison(ctx context.Context, db *dbstore.Store, namespace, baseID, headID, project string) (*history.Result, error) {
	if baseID == "" || headID == "" {
		return nil, fmt.Errorf("base and head run IDs are required")
	}
	base, e := db.Load(ctx, namespace, baseID)
	if e != nil {
		return nil, e
	}
	head, e := db.Load(ctx, namespace, headID)
	if e != nil {
		return nil, e
	}
	if project != "" && (base.ProjectKey != project || head.ProjectKey != project) {
		return nil, fmt.Errorf("selected runs do not belong to this project")
	}
	return history.Compare(base, head)
}
func validateChangeFilters(state, severity, category, query string) error {
	if len(query) > 256 || len(category) > 32 {
		return fmt.Errorf("comparison filters are too long")
	}
	switch state {
	case "", "new", "resolved", "changed", "unchanged", "unverified", "added", "removed":
	default:
		return fmt.Errorf("invalid change filter")
	}
	switch severity {
	case "", "critical", "high", "medium", "low", "info", "unknown":
	default:
		return fmt.Errorf("invalid severity")
	}
	return nil
}
func filterComponents(items []history.ComponentChange, state, q string) []history.ComponentChange {
	out := []history.ComponentChange{}
	for _, v := range items {
		if state != "" && v.State != state {
			continue
		}
		b, _ := json.Marshal(v)
		if q != "" && !strings.Contains(strings.ToLower(string(b)), strings.ToLower(q)) {
			continue
		}
		out = append(out, v)
	}
	return out
}
func historyHandler(db *dbstore.Store, c config.Config) http.Handler {
	return historyHandlerForProject(db, c, "")
}

// The optional fixed project is a local presentation filter, not an authorization
// or multi-tenant boundary. Database permissions remain the operator's control.
func historyHandlerForProject(db *dbstore.Store, c config.Config, lockedProject string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			name := strings.TrimPrefix(r.URL.Path, "/assets/")
			if name != "history.js" && name != "history.css" && name != "sekura.css" && name != "ui.js" {
				historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
				return
			}
			b, e := historyAssets.ReadFile("historyweb/" + name)
			if name == "sekura.css" {
				b = []byte(ui.CSS)
				e = nil
			}
			if name == "ui.js" {
				b = []byte(ui.JS)
				e = nil
			}
			if e != nil {
				historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
				return
			}
			ct := "text/css; charset=utf-8"
			if strings.HasSuffix(name, ".js") {
				ct = "text/javascript; charset=utf-8"
			}
			w.Header().Set("Content-Type", ct)
			_, _ = w.Write(b)
			return
		}
		q := r.URL.Query()
		selectedProject, err := projectFilter(q)
		if err != nil {
			historyError(w, r, c, err.Error(), 400)
			return
		}
		if lockedProject != "" {
			if selectedProject != "" && selectedProject != lockedProject {
				historyError(w, r, c, "this history server is filtered to a different project", 400)
				return
			}
			selectedProject = lockedProject
			q.Set("project", selectedProject)
			r = r.Clone(r.Context())
			r.URL.RawQuery = q.Encode()
		}
		if strings.HasPrefix(r.URL.Path, "/scans/") {
			serveStoredScan(w, r, db, c)
			return
		}
		f, e := pageFilter(q, c.Project.Namespace)
		if e != nil {
			historyError(w, r, c, e.Error(), 400)
			return
		}
		page := historyPage{URLPath: r.URL.Path, RawQuery: q.Encode(), LockedProject: lockedProject, Namespace: c.Project.Namespace, Driver: c.Storage.Driver, Project: f.Project, Query: f.Query, Branch: f.Branch, Status: f.Status, Kind: f.TargetKind, From: f.From, To: f.To, Size: f.Limit}
		switch r.URL.Path {
		case "/", "/api/projects", "/api/portfolio":
			page.Mode = "projects"
			page.Title = "Security portfolio"
			page.Tab, e = validTab(q, "overview", "overview", "projects", "runs")
			if e != nil {
				historyError(w, r, c, e.Error(), 400)
				return
			}
			page.Days, e = queryInt(q, "days", 30, 1, 90)
			if e != nil {
				historyError(w, r, c, e.Error(), 400)
				return
			}
			if r.URL.Path == "/api/portfolio" {
				page.Tab = "overview"
			}
			if r.URL.Path == "/api/projects" || page.Tab == "projects" {
				page.Projects, e = db.ProjectPage(r.Context(), f)
				if e != nil {
					historyError(w, r, c, e.Error(), 400)
					return
				}
				if r.URL.Path == "/api/projects" {
					writeHistoryJSON(w, page.Projects)
					return
				}
				page.Pager = navigation(r, page.Projects)
			} else if page.Tab == "runs" && r.URL.Path != "/api/portfolio" {
				page.Runs, e = db.ScanPage(r.Context(), f)
				if e != nil {
					historyError(w, r, c, e.Error(), 400)
					return
				}
				page.Pager = navigation(r, page.Runs)
			} else {
				page.Portfolio, e = db.Portfolio(r.Context(), f, page.Days)
				if e != nil {
					if r.URL.Path == "/api/portfolio" {
						historyError(w, r, c, e.Error(), 400)
						return
					}
					page.PortfolioError = e.Error()
				} else {
					page.ChartData = jsonScript(page.Portfolio)
				}
				if r.URL.Path == "/api/portfolio" {
					writeHistoryJSON(w, page.Portfolio)
					return
				}
			}
			writeHistory(w, page)
		case "/projects", "/api/scans", "/api/trends":
			if r.URL.Path != "/api/scans" && f.Project == "" {
				historyError(w, r, c, "project is required", 400)
				return
			}
			page.Mode = "runs"
			page.Tab, e = validTab(q, "overview", "overview", "runs")
			if e != nil {
				historyError(w, r, c, e.Error(), 400)
				return
			}
			page.Title = f.Project
			page.Runs, e = db.ScanPage(r.Context(), f)
			if e != nil {
				historyError(w, r, c, e.Error(), 400)
				return
			}
			if r.URL.Path == "/api/scans" {
				writeHistoryJSON(w, page.Runs)
				return
			}
			page.TrendLimit, e = queryInt(q, "trend_limit", 50, 1, 200)
			if e != nil {
				historyError(w, r, c, e.Error(), 400)
				return
			}
			page.Trends, e = db.Trends(r.Context(), f, page.TrendLimit)
			if e != nil {
				historyError(w, r, c, e.Error(), 400)
				return
			}
			if r.URL.Path == "/api/trends" {
				writeHistoryJSON(w, page.Trends)
				return
			}
			page.Base = q.Get("base")
			page.Head = q.Get("head")
			if len(page.Trends.Points) >= 2 && page.Base == "" && page.Head == "" {
				n := len(page.Trends.Points)
				page.Base = page.Trends.Points[n-2].ID
				page.Head = page.Trends.Points[n-1].ID
			}
			page.Pager = navigation(r, page.Runs)
			page.ChartData = jsonScript(page.Trends)
			writeHistory(w, page)
		case "/compare", "/api/compare":
			page.Mode = "compare"
			page.Title = "Run comparison"
			page.Base = q.Get("base")
			page.Head = q.Get("head")
			page.View = q.Get("view")
			defaultTab := "overview"
			if page.View == "components" {
				defaultTab = "components"
			} else if page.View == "findings" {
				defaultTab = "findings"
			}
			page.Tab, e = validTab(q, defaultTab, "overview", "findings", "components")
			if e != nil {
				historyError(w, r, c, e.Error(), 400)
				return
			}
			if q.Get("tab") != "" {
				if page.Tab == "components" {
					page.View = "components"
				} else {
					page.View = "findings"
				}
			}
			page.State = q.Get("state")
			page.Severity = q.Get("severity")
			page.Category = q.Get("category")
			if page.View != "" && page.View != "findings" && page.View != "components" {
				historyError(w, r, c, "invalid comparison view", 400)
				return
			}
			if e = validateChangeFilters(page.State, page.Severity, page.Category, page.Query); e != nil {
				historyError(w, r, c, e.Error(), 400)
				return
			}
			page.Comparison, e = loadComparison(r.Context(), db, c.Project.Namespace, page.Base, page.Head, f.Project)
			if e != nil {
				if errors.Is(e, dbstore.ErrNotFound) {
					historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
				} else {
					historyError(w, r, c, e.Error(), 400)
				}
				return
			}
			page.Project = page.Comparison.Project
			// Keep inferred project identity in pagination URLs as well.
			q.Set("project", page.Project)
			r = r.Clone(r.Context())
			r.URL.RawQuery = q.Encode()
			if page.View == "components" {
				page.Components = slicePage(filterComponents(page.Comparison.Components, page.State, page.Query), f.Limit, f.Offset)
				page.Pager = navigation(r, page.Components)
			} else {
				page.Changes = slicePage(history.FilterChanges(page.Comparison.Changes, page.State, page.Severity, page.Category, page.Query), f.Limit, f.Offset)
				page.Pager = navigation(r, page.Changes)
			}
			// Do not serialize all diff rows in a paginated response or chart payload.
			metadata := *page.Comparison
			metadata.Changes = nil
			metadata.Components = nil
			if r.URL.Path == "/api/compare" {
				if page.View == "components" {
					writeHistoryJSON(w, map[string]any{"comparison": metadata, "page": page.Components})
				} else {
					writeHistoryJSON(w, map[string]any{"comparison": metadata, "page": page.Changes})
				}
				return
			}
			page.ChartData = jsonScript(metadata)
			writeHistory(w, page)
		default:
			historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
		}
	})
}
func serveStoredScan(w http.ResponseWriter, r *http.Request, db *dbstore.Store, c config.Config) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "scans" {
		historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
		return
	}
	snapshot, e := db.Load(r.Context(), c.Project.Namespace, parts[1])
	if e != nil {
		if errors.Is(e, dbstore.ErrNotFound) {
			historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
		} else {
			historyError(w, r, c, "stored report unavailable", 500)
		}
		return
	}
	if project := r.URL.Query().Get("project"); project != "" && snapshot.ProjectKey != project {
		historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
		return
	}
	if len(parts) == 3 && parts[2] == "results.json" {
		writeHistoryJSON(w, snapshot)
		return
	}
	if len(parts) == 4 && parts[2] == "artifacts" && dbstore.AllowedArtifact(parts[3]) {
		artifacts, e := db.Artifacts(r.Context(), c.Project.Namespace, snapshot.ID)
		if e != nil {
			historyError(w, r, c, "stored artifacts unavailable", 500)
			return
		}
		for _, a := range artifacts {
			if a.Name == parts[3] {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", `attachment; filename="`+a.Name+`"`)
				_, _ = w.Write(a.Content)
				return
			}
		}
		historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
		return
	}
	if len(parts) != 2 {
		historyError(w, r, c, "The requested page or scan could not be found.", http.StatusNotFound)
		return
	}
	html, e := report.HTMLWithHistory(snapshot)
	if e != nil {
		historyError(w, r, c, "render failed", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(html)
}
func serveHistory(ctx context.Context, c config.Config, address, project string, out io.Writer) error {
	db, e := openReady(ctx, c)
	if e != nil {
		return e
	}
	defer db.Close()
	return server.ServeDynamic(ctx, address, historyHandlerForProject(db, c, project), func(a string) {
		if project != "" {
			a += "/?" + url.Values{"project": {project}}.Encode()
		}
		fmt.Fprintln(out, "Project history:", a, "(Ctrl+C to stop)")
	})
}
