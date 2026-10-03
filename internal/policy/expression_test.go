package policy

import (
	"strings"
	"testing"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/model"
)

func TestSPDXExpressions(t *testing.T) {
	p := config.Default().Policy.Licenses
	p.Deny = []string{"GPL-3.0-only"}
	for _, test := range []struct {
		expression, want string
		invalid          bool
	}{
		{"MIT", "pass", false}, {"MIT OR GPL-3.0-only", "pass", false}, {"MIT AND GPL-3.0-only", "fail", false},
		{"MIT OR (Apache-2.0 AND GPL-3.0-only)", "pass", false}, {"(MIT OR Apache-2.0) AND GPL-3.0-only", "fail", false},
		{"LicenseRef-Private", "review", false}, {"NONE", "review", false}, {"NOASSERTION", "review", false},
		{"MIT WITH LLVM-exception", "review", false}, {"MIT AND", "review", true}, {"(MIT", "review", true}, {"MIT Apache-2.0", "review", true}, {"MIT & Apache-2.0", "review", true},
		{"MIT WITH", "review", true}, {"MIT OR OR Apache-2.0", "review", true}, {"MIT)", "review", true},
	} {
		t.Run(test.expression, func(t *testing.T) {
			got, _, err := EvaluateExpression(test.expression, p)
			if got != test.want || (err != nil) != test.invalid {
				t.Fatalf("got %s / %v, want %s invalid=%v", got, err, test.want, test.invalid)
			}
		})
	}
	p.Allow = append(p.Allow, "MIT WITH LLVM-exception")
	got, _, err := EvaluateExpression("MIT WITH LLVM-exception", p)
	if got != "pass" || err != nil {
		t.Fatal(got, err)
	}
	if _, _, err = EvaluateExpression(strings.Repeat("(", 100)+"MIT"+strings.Repeat(")", 100), p); err == nil {
		t.Fatal("accepted excessive nesting")
	}
}
func TestLicenseScopeAndConflict(t *testing.T) {
	p := config.Default().Policy.Licenses
	cs := []model.Component{
		{ID: "os", Name: "libc", Scope: "operating-system", Licenses: []model.LicenseEvidence{{Expression: "GPL-3.0-only", Source: "syft", Kind: "metadata"}}},
		{ID: "app", Name: "library", Scope: "application", Licenses: []model.LicenseEvidence{{Expression: "MIT", Source: "syft", Kind: "metadata"}, {Expression: "GPL-3.0-only", Source: "trivy", Kind: "detected"}}},
		{ID: "missing", Name: "missing-license", Scope: "application"},
		{ID: "unknown", Name: "unknown", Scope: "unknown", Licenses: []model.LicenseEvidence{{Expression: "MIT"}}},
	}
	findings := LicenseFindings(cs, p)
	if len(findings) != 3 {
		t.Fatalf("%d findings", len(findings))
	}
	if cs[0].LicenseDecision != "excluded" {
		t.Fatal("OS license included")
	}
	if findings[0].RuleID != "license-evidence-conflict" {
		t.Fatal(findings[0].RuleID)
	}
}
func TestScopeOverride(t *testing.T) {
	cs := []model.Component{{Name: "service", Scope: "unknown", Locations: []model.Location{{Path: "app/service"}}}}
	ApplyScopes(cs, []config.ScopeOverride{{PathPrefix: "app", Scope: "application"}})
	if cs[0].Scope != "application" {
		t.Fatal(cs)
	}
}
func TestDedupeAliasesAndVersions(t *testing.T) {
	cs := []model.Component{{ID: "a", Name: "x", Version: "1", Ecosystem: "npm", Scope: "application"}, {ID: "b", Name: "x", Version: "2", Ecosystem: "npm", Scope: "application"}}
	fs := []model.Finding{
		{Category: "vulnerability", ComponentID: "a", RuleID: "GHSA-demo", Aliases: []string{"CVE-2024-11111"}, Severity: "medium", Observations: []model.Observation{{Engine: "grype"}}},
		{Category: "vulnerability", ComponentID: "a", RuleID: "CVE-2024-11111", Severity: "high", Observations: []model.Observation{{Engine: "trivy"}}},
		{Category: "vulnerability", ComponentID: "b", RuleID: "CVE-2024-11111", Severity: "high"},
	}
	got := Deduplicate(fs, cs)
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
	for _, f := range got {
		if f.ComponentID == "a" && (f.RuleID != "CVE-2024-11111" || len(f.Observations) != 2 || f.Severity != "high") {
			t.Fatal(f)
		}
	}
}
func TestPolicyExceptionsAndBaseline(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c := config.Default()
	c.Exceptions = []config.Exception{{ID: "approved", Fingerprint: "fp", Reason: "Migration scheduled", Owner: "security", Expires: "2026-10-02"}}
	r := &model.Report{ConfigHash: c.Hash(), Findings: []model.Finding{{Fingerprint: "fp", Category: "vulnerability", Severity: "critical", Scope: "application"}}, Engines: []model.EngineRun{{Name: "grype", Status: "completed", Required: true, Checks: []string{"vulnerability"}}}}
	Apply(r, c, nil, now)
	if r.Findings[0].Decision != "accepted" || r.ExitCode != 0 {
		t.Fatal(r)
	}
	Apply(r, c, nil, now.Add(24*time.Hour))
	if r.Findings[0].Decision != "fail" || r.ExitCode != 1 {
		t.Fatal(r)
	}
	baseline := &model.Report{ConfigHash: c.Hash(), Findings: []model.Finding{{ID: "old", Fingerprint: "gone", Category: "vulnerability", Observations: []model.Observation{{Engine: "grype"}}}}}
	r.Engines[0].Status = "failed"
	Apply(r, c, baseline, now)
	if r.ExitCode != 2 || len(r.Resolved) != 0 {
		t.Fatal("incomplete scan resolved a finding")
	}
	r.Engines[0].Status = "completed"
	Apply(r, c, baseline, now)
	if len(r.Resolved) != 1 {
		t.Fatal("completed scan did not resolve finding")
	}
}
func FuzzSPDX(f *testing.F) {
	for _, s := range []string{"MIT", "MIT OR GPL-3.0-only", "((MIT))", "MIT WITH LLVM-exception", "AND", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, _, _ := EvaluateExpression(s, config.Default().Policy.Licenses)
		if d != "pass" && d != "fail" && d != "review" {
			t.Fatal(d)
		}
	})
}

func TestDisabledCheckDoesNotResolveBaseline(t *testing.T) {
	c := config.Default()
	previous := &model.Report{ConfigHash: c.Hash(), Findings: []model.Finding{{ID: "old-secret", Fingerprint: "old-secret", Category: "secret", Observations: []model.Observation{{Engine: "trivy"}}}}}
	current := &model.Report{ConfigHash: c.Hash(), Engines: []model.EngineRun{{Name: "trivy", Status: "completed", Required: true, Checks: []string{"license"}}}}
	Apply(current, c, previous, time.Now())
	if len(current.Resolved) != 0 {
		t.Fatal("disabled secret check resolved old secret")
	}
}
