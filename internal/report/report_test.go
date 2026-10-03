package report

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"sekscan/internal/model"
	"sekscan/internal/ui"
)

func sample() *model.Report {
	r := &model.Report{SchemaVersion: model.SchemaVersion, ID: "test", AppVersion: "test", Target: model.Target{Kind: "dir", Value: "demo"}, StartedAt: time.Now(), FinishedAt: time.Now(), Components: []model.Component{}, Engines: []model.EngineRun{{Name: "test", Status: "completed", Required: true}}, Findings: []model.Finding{{ID: "x", RuleID: "test-rule", Title: `</script><script>alert("XSS")</script>`, Severity: "high", Category: "code", Decision: "fail", Locations: []model.Location{{Path: "a b.go", Line: 2}}}}}
	r.Summarize(true)
	return r
}
func TestHTMLSafeAndSelfContained(t *testing.T) {
	b, e := HTML(sample())
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if strings.Contains(s, `</script><script>alert`) {
		t.Fatal("script injection")
	}
	if strings.Contains(s, "@@") {
		t.Fatal("unresolved template markers")
	}
	js, _ := assets.ReadFile("web/app.js")
	hash := sha256.Sum256(append([]byte(ui.JS+"\n"), js...))
	if !strings.Contains(s, "sha256-"+base64.StdEncoding.EncodeToString(hash[:])) {
		t.Fatal("missing CSP script hash")
	}
	if strings.Contains(string(js), "innerHTML") {
		t.Fatal("unsafe dynamic HTML")
	}
}
func TestExports(t *testing.T) {
	r := sample()
	raw, e := json.Marshal(SARIF(r))
	if e != nil || !json.Valid(raw) {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), "a%20b.go") {
		t.Fatal("SARIF URI not escaped")
	}
	b, e := JUnit(r)
	if e != nil {
		t.Fatal(e)
	}
	var suite junitSuite
	if e = xml.Unmarshal(b, &suite); e != nil || suite.Failures != 1 {
		t.Fatal(e, suite)
	}
	r.Engines[0].Status = "failed"
	r.Summarize(true)
	b, _ = JUnit(r)
	xml.Unmarshal(b, &suite)
	if suite.Errors != 1 {
		t.Fatal("incomplete scan not exposed as JUnit error")
	}
}

func TestAllowedReviewDoesNotBecomeJUnitFailure(t *testing.T) {
	r := sample()
	r.Findings = append(r.Findings, model.Finding{RuleID: "review-license", Category: "license", Decision: "review"})
	r.Summarize(false)
	b, err := JUnit(r)
	if err != nil {
		t.Fatal(err)
	}
	var suite junitSuite
	if err = xml.Unmarshal(b, &suite); err != nil || suite.Failures != 1 {
		t.Fatal(err, suite)
	}
}

func TestHistoryReportEscapesProjectAndSharesAssets(t *testing.T) {
	r := sample()
	r.ProjectKey = `x"><img src=x onerror=alert(1)>`
	b, err := HTMLWithHistory(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, `<img src=x`) || strings.Contains(s, "@@") || !strings.Contains(s, "data-history-project") || !strings.Contains(s, "--sk-color-surface-base") {
		t.Fatal("unsafe or incomplete history shell")
	}
	if strings.Contains(s, "https://fonts.") {
		t.Fatal("external assets")
	}
}

func TestReportDesignContract(t *testing.T) {
	for _, render := range []func(*model.Report) ([]byte, error){HTML, HTMLWithHistory} {
		r := sample()
		r.ProjectKey = "demo-project"
		b, err := render(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{`data-sekura-version="3.0.2"`, `id="main" tabindex="-1"`, `aria-labelledby="detail-title"`, `id="import-error"`, `sk-field-row`, `data-nav-trigger`} {
			if !strings.Contains(string(b), marker) {
				t.Fatal("missing report design contract", marker)
			}
		}
		css, _ := assets.ReadFile("web/style.css")
		hash := sha256.Sum256(append([]byte(ui.CSS+"\n"), css...))
		if !strings.Contains(string(b), "sha256-"+base64.StdEncoding.EncodeToString(hash[:])) {
			t.Fatal("updated styles not CSP-hashed")
		}
	}
}
