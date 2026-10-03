package cli

import (
	"net/http/httptest"
	"strings"
	"testing"

	"sekscan/internal/config"
)

func TestHistoryDesignErrors(t *testing.T) {
	for _, tc := range []struct {
		path   string
		status int
		html   bool
	}{
		{"/?page=0", 400, true}, {"/scans/absent", 404, true}, {"/api/scans?page=0", 400, false}, {"/scans/absent/results.json", 404, false}, {"/scans/absent/artifacts/sbom.cdx.json", 404, false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", tc.path, nil)
			historyError(w, r, config.Default(), `bad <script>alert("x")</script>`, tc.status)
			if w.Code != tc.status {
				t.Fatal(w.Code)
			}
			if tc.html {
				for _, marker := range []string{`data-sekura-version="3.0.2"`, `data-nav-trigger`, `role="alert"`, "&lt;script&gt;", "Return to portfolio"} {
					if !strings.Contains(w.Body.String(), marker) {
						t.Fatal("missing error page contract", marker)
					}
				}
				if strings.Contains(w.Body.String(), "<script>alert") {
					t.Fatal("error rendered as script")
				}
				if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
					t.Fatal("missing CSP")
				}
			} else if strings.Contains(w.Header().Get("Content-Type"), "text/html") || strings.Contains(w.Body.String(), "app-navigation") {
				t.Fatal("API error contract changed")
			}
		})
	}
	w := httptest.NewRecorder()
	historyError(w, httptest.NewRequest("GET", "/", nil), config.Default(), "password=do-not-display", 500)
	if strings.Contains(w.Body.String(), "do-not-display") || !strings.Contains(w.Body.String(), "application logs") {
		t.Fatal("internal error exposed")
	}
}

func TestHistorySurfacesUseSharedShell(t *testing.T) {
	db, c := filterFixture(t)
	h := historyHandler(db, c)
	for _, path := range []string{"/", "/?tab=projects", "/?tab=runs", "/projects?project=service-0", "/projects?project=service-0&tab=runs", "/compare?base=service-0-run0&head=service-0-run3", "/scans/service-0-run0"} {
		t.Run(path, func(t *testing.T) {
			w := filterFetch(h, path)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			body := w.Body.String()
			if strings.Count(body, `id="app-navigation"`) != 1 || strings.Count(body, `data-app-header`) < 1 {
				t.Fatal("missing or duplicate shared shell")
			}
			if !strings.Contains(body, `data-sekura-version="3.0.2"`) || !strings.Contains(body, `id="main" tabindex="-1"`) {
				t.Fatal("missing design version or focus target")
			}
		})
	}
	for _, path := range []string{"/?page=0", "/scans/does-not-exist"} {
		w := filterFetch(h, path)
		if w.Code < 400 || !strings.Contains(w.Body.String(), "Return to portfolio") {
			t.Fatal("actual page errors bypass shared design", path, w.Code)
		}
	}
}
