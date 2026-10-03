// Package report renders portable, self-contained reports without external assets.
package report

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"sekscan/internal/model"
	"sekscan/internal/store"
	"sekscan/internal/ui"
)

//go:embed web/*
var assets embed.FS
var OutputFiles = []string{"results.json", "index.html", "findings.sarif", "junit.xml", "summary.md", "policy-results.json", "sbom.syft.json", "sbom.cdx.json", "sbom.spdx.json"}

func HTML(r *model.Report) ([]byte, error) { return renderHTML(r, false) }

// HTMLWithHistory uses the same renderer and presentation as portable reports,
// adding only links to the local history endpoints.
func HTMLWithHistory(r *model.Report) ([]byte, error) { return renderHTML(r, true) }
func renderHTML(r *model.Report, history bool) ([]byte, error) {
	raw, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	template, e := assets.ReadFile("web/index.html")
	if e != nil {
		return nil, e
	}
	css, e := assets.ReadFile("web/style.css")
	if e != nil {
		return nil, e
	}
	js, e := assets.ReadFile("web/app.js")
	if e != nil {
		return nil, e
	}
	css = append([]byte(ui.CSS+"\n"), css...)
	js = append([]byte(ui.JS+"\n"), js...)
	opts := ui.ShellOptions{Portable: !history, Active: "report", Namespace: r.Namespace}
	opts.Breadcrumbs = []ui.Crumb{{Label: "Portable report"}}
	if history {
		opts.Project = r.ProjectKey
		opts.Driver = "Stored report"
		opts.OpenLabel = "Scan report"
		opts.OpenURL = "/scans/" + url.PathEscape(r.ID) + "?" + url.Values{"project": {r.ProjectKey}}.Encode()
		opts.Breadcrumbs = []ui.Crumb{{Label: "Portfolio", URL: "/"}, {Label: r.ProjectKey, URL: opts.ProjectURL(), Project: true}, {Label: "Scan report"}}
	}
	shell, e := ui.Shell(opts)
	if e != nil {
		return nil, e
	}
	scriptHash := sha256.Sum256(js)
	styleHash := sha256.Sum256(css)
	html := string(template)
	replacements := []string{"@@CSS@@", string(css), "@@SCRIPT_HASH@@", base64.StdEncoding.EncodeToString(scriptHash[:]), "@@STYLE_HASH@@", base64.StdEncoding.EncodeToString(styleHash[:]), "@@JS@@", string(js), "@@DATA@@", string(raw), "@@SHELL@@", string(shell)}
	// JSON is escaped by encoding/json, including '<', '>' and '&'. Data is never executable.
	html = strings.NewReplacer(replacements...).Replace(html)
	return []byte(html), nil
}
func Write(dir string, r *model.Report) error {
	if e := store.JSON(filepath.Join(dir, "results.json"), r); e != nil {
		return e
	}
	html, e := HTML(r)
	if e != nil {
		return e
	}
	if e = store.Atomic(filepath.Join(dir, "index.html"), html, 0600); e != nil {
		return e
	}
	sarif := SARIF(r)
	if e = store.JSON(filepath.Join(dir, "findings.sarif"), sarif); e != nil {
		return e
	}
	decisions := []map[string]string{}
	for _, f := range r.Findings {
		decisions = append(decisions, map[string]string{"id": f.ID, "fingerprint": f.Fingerprint, "decision": f.Decision, "reason": f.DecisionReason, "exception": f.Exception})
	}
	if e = store.JSON(filepath.Join(dir, "policy-results.json"), map[string]any{"status": r.Status, "complete": r.Complete, "exit_code": r.ExitCode, "decisions": decisions}); e != nil {
		return e
	}
	junit, e := JUnit(r)
	if e != nil {
		return e
	}
	if e = store.Atomic(filepath.Join(dir, "junit.xml"), junit, 0600); e != nil {
		return e
	}
	return store.Atomic(filepath.Join(dir, "summary.md"), []byte(Markdown(r)), 0600)
}
func Markdown(r *model.Report) string {
	safe := func(s string) string { return strings.NewReplacer("\r", " ", "\n", " ", "`", "'", "|", "/").Replace(s) }
	b := &strings.Builder{}
	fmt.Fprintf(b, "# Security scan: %s\n\nTarget: `%s` (%s)  \nCompleted: %s  \nCoverage complete: %t  \nExit code: %d\n\n", r.Status, safe(r.Target.Value), r.Target.Kind, r.FinishedAt.Format("2006-01-02T15:04:05Z"), r.Complete, r.ExitCode)
	fmt.Fprintf(b, "| Components | Findings | Policy failures | Review required | Accepted |\n|---:|---:|---:|---:|---:|\n| %d | %d | %d | %d | %d |\n\n", r.Summary.Components, r.Summary.Findings, r.Summary.Failures, r.Summary.Reviews, r.Summary.Accepted)
	b.WriteString("## Engines\n\n| Engine | Version | Status |\n|---|---|---|\n")
	for _, e := range r.Engines {
		fmt.Fprintf(b, "| %s | %s | %s |\n", safe(e.Name), safe(e.Version), e.Status)
	}
	b.WriteString("\n## Coverage notes\n\n")
	for _, w := range r.Warnings {
		fmt.Fprintf(b, "- %s\n", safe(w))
	}
	b.WriteString("\nOpen `index.html` for the searchable dashboard. Raw secret values are omitted from built-in secret findings.\n")
	return b.String()
}
func SARIF(r *model.Report) map[string]any {
	rules := []map[string]any{}
	indexes := map[string]int{}
	results := []map[string]any{}
	for _, f := range r.Findings {
		if _, ok := indexes[f.RuleID]; !ok {
			indexes[f.RuleID] = len(rules)
			rules = append(rules, map[string]any{"id": f.RuleID, "shortDescription": map[string]string{"text": f.RuleID}, "properties": map[string]any{"tags": []string{"security", f.Category}}})
		}
		level := "note"
		if model.SeverityRank(f.Severity) >= 4 {
			level = "error"
		} else if model.SeverityRank(f.Severity) >= 2 {
			level = "warning"
		}
		text := f.Title + "\n" + f.Description + "\nPolicy: " + f.Decision + ". " + f.DecisionReason
		if len(f.FixedVersions) > 0 {
			text += "\nReported fixes: " + strings.Join(f.FixedVersions, ", ")
		}
		item := map[string]any{"ruleId": f.RuleID, "ruleIndex": indexes[f.RuleID], "level": level, "message": map[string]string{"text": text}, "partialFingerprints": map[string]string{"sekscan/v1": f.Fingerprint}, "properties": map[string]any{"category": f.Category, "scope": f.Scope, "decision": f.Decision, "component": f.Package}}
		locs := []map[string]any{}
		for _, l := range f.Locations {
			if l.Path == "" {
				continue
			}
			u := url.URL{Path: filepath.ToSlash(l.Path)}
			physical := map[string]any{"artifactLocation": map[string]string{"uri": u.String()}}
			if l.Line > 0 {
				physical["region"] = map[string]int{"startLine": l.Line}
			}
			locs = append(locs, map[string]any{"physicalLocation": physical})
		}
		if len(locs) > 0 {
			item["locations"] = locs
		}
		if f.Baseline == "new" {
			item["baselineState"] = "new"
		} else if f.Baseline == "existing" {
			item["baselineState"] = "unchanged"
		}
		if f.Decision == "accepted" {
			item["suppressions"] = []map[string]string{{"kind": "external", "status": "accepted", "justification": f.DecisionReason}}
		}
		results = append(results, item)
	}
	return map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []map[string]any{{"tool": map[string]any{"driver": map[string]any{"name": "sekscan", "version": r.AppVersion, "rules": rules}}, "invocations": []map[string]any{{"executionSuccessful": r.Complete}}, "results": results}}}
}

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Cases    []junitCase `xml:"testcase"`
}
type junitCase struct {
	Name    string        `xml:"name,attr"`
	Class   string        `xml:"classname,attr"`
	Failure *junitMessage `xml:"failure,omitempty"`
	Error   *junitMessage `xml:"error,omitempty"`
	Skipped *junitMessage `xml:"skipped,omitempty"`
}
type junitMessage struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func JUnit(r *model.Report) ([]byte, error) {
	suite := junitSuite{Name: "sekscan"}
	for _, f := range r.Findings {
		c := junitCase{Name: f.RuleID + " " + f.Package, Class: f.Category}
		if f.Decision == "fail" || (f.Decision == "review" && r.FailOnReview) {
			c.Failure = &junitMessage{Message: f.Decision, Text: f.Title + "\n" + f.DecisionReason}
			suite.Failures++
		}
		if f.Decision == "accepted" {
			c.Skipped = &junitMessage{Message: "accepted", Text: f.DecisionReason}
		}
		suite.Cases = append(suite.Cases, c)
	}
	for _, e := range r.Engines {
		c := junitCase{Name: e.Name, Class: "scan-health"}
		if e.Required && e.Status != "completed" {
			c.Error = &junitMessage{Message: "incomplete scan", Text: e.Error}
			suite.Errors++
		}
		suite.Cases = append(suite.Cases, c)
	}
	suite.Tests = len(suite.Cases)
	b, e := xml.MarshalIndent(suite, "", "  ")
	if e != nil {
		return nil, e
	}
	return append([]byte(xml.Header), b...), nil
}
func Load(path string) (*model.Report, error) {
	b, e := store.Read(path, 512<<20)
	if e != nil {
		return nil, e
	}
	var r model.Report
	if e = json.Unmarshal(b, &r); e != nil {
		return nil, e
	}
	if r.SchemaVersion != model.SchemaVersion {
		return nil, fmt.Errorf("unsupported report schema %q", r.SchemaVersion)
	}
	if r.ID == "" || r.Target.Kind == "" {
		return nil, fmt.Errorf("incomplete report metadata")
	}
	// Preserve ordering: reports are immutable database snapshots, not mutable views.

	return &r, nil
}
