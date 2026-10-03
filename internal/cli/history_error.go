package cli

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"sekscan/internal/config"
	"sekscan/internal/ui"
)

var historyErrorTemplate = template.Must(template.New("history-error").ParseFS(historyAssets, "historyweb/error.html"))

// Keep API/asset error contracts unchanged; only browser pages receive the shell.
func historyError(w http.ResponseWriter, r *http.Request, c config.Config, message string, status int) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/assets/") || strings.HasSuffix(r.URL.Path, ".json") || strings.Contains(r.URL.Path, "/artifacts/") {
		http.Error(w, message, status)
		return
	}
	title := "Unable to open this view"
	if status == http.StatusBadRequest {
		title = "Check the request"
	}
	if status == http.StatusNotFound {
		title = "Page or scan not found"
	}
	if status >= 500 {
		message = "This view is temporarily unavailable. Check the local application logs and try again."
	}
	shell, err := ui.Shell(ui.ShellOptions{Namespace: c.Project.Namespace, Driver: c.Storage.Driver, Breadcrumbs: []ui.Crumb{{Label: "Portfolio", URL: "/"}, {Label: title}}})
	if err != nil {
		http.Error(w, "render failed", 500)
		return
	}
	var b bytes.Buffer
	value := struct {
		Shell          template.HTML
		Title, Message string
		Status         int
	}{shell, title, message, status}
	if err := historyErrorTemplate.ExecuteTemplate(&b, "error.html", value); err != nil {
		http.Error(w, "render failed", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
