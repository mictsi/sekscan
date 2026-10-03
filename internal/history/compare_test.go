package history

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sekscan/internal/model"
)

func comparisonFixture() (*model.Report, *model.Report) {
	makeFinding := func(fp string) model.Finding {
		return model.Finding{Fingerprint: fp, ID: fp, RuleID: "TEST-" + fp, Category: "vulnerability", Severity: "high", Package: "app", Version: "1.0", Decision: "fail", Observations: []model.Observation{{Engine: "grype"}}}
	}
	a := &model.Report{SchemaVersion: model.SchemaVersion, Namespace: "testing", ProjectKey: "payments", ID: "base", StartedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Target: model.Target{Kind: "dir", Value: "repo"}, Branch: "main", ConfigHash: "config", AppVersion: "test", Findings: []model.Finding{makeFinding("same"), makeFinding("change"), makeFinding("removed")}, Engines: []model.EngineRun{{Name: "grype", Version: "1", Status: "completed", Required: true, Checks: []string{"vuln"}}}}
	a.FinishedAt = a.StartedAt.Add(time.Second)
	a.Summarize(false)
	raw, _ := json.Marshal(a)
	b := new(model.Report)
	_ = json.Unmarshal(raw, b)
	b.ID = "head"
	b.StartedAt = b.StartedAt.Add(time.Hour)
	b.FinishedAt = b.StartedAt.Add(time.Second)
	b.Findings = b.Findings[:2]
	b.Findings[1].Severity = "critical"
	b.Findings[1].FixedVersions = []string{"1.1"}
	b.Findings = append(b.Findings, makeFinding("added"))
	b.Summarize(false)
	return a, b
}
func TestCompareFindingStates(t *testing.T) {
	a, b := comparisonFixture()
	r, e := Compare(a, b)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Comparable || r.Counts != (Counts{New: 1, Resolved: 1, Changed: 1, Unchanged: 1}) {
		t.Fatal(r.Counts, r.Warnings)
	}
	if r.Delta.BySeverity["critical"] != 1 || r.Delta.Findings != 0 {
		t.Fatal(r.Delta)
	}
	if r.Changes[0].State != "new" {
		t.Fatal("unstable ordering")
	}
	if len(FilterChanges(r.Changes, "changed", "critical", "vulnerability", "app")) != 1 {
		t.Fatal("filters")
	}
	before, _ := json.Marshal(b)
	_, _ = Compare(a, b)
	after, _ := json.Marshal(b)
	if string(before) != string(after) {
		t.Fatal("comparison mutated the report")
	}
}
func TestMissingFindingsRemainUnverifiedWithCoverageChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Report)
	}{
		{"incomplete", func(b *model.Report) { b.Engines[0].Status = "failed"; b.Summarize(false) }},
		{"configuration", func(b *model.Report) { b.ConfigHash = "new" }},
		{"disabled", func(b *model.Report) { b.Engines = nil; b.Summarize(false) }},
		{"native-config", func(b *model.Report) { b.Engines[0].ConfigSHA256 = "new" }},
		{"checks", func(b *model.Report) { b.Engines[0].Checks = []string{"secret"} }},
		{"branch", func(b *model.Report) { b.Branch = "feature" }},
		{"app-version", func(b *model.Report) { b.AppVersion = "next" }},
		{"scanner-version", func(b *model.Report) { b.Engines[0].Version = "next" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := comparisonFixture()
			tt.mutate(b)
			r, e := Compare(a, b)
			if e != nil || r.Counts.Resolved != 0 || r.Counts.Unverified != 1 || r.Comparable {
				t.Fatal(r, e)
			}
		})
	}
}
func TestRejectInvalidComparisonPairs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Report)
	}{
		{"project", func(r *model.Report) { r.ProjectKey = "other" }},
		{"namespace", func(r *model.Report) { r.Namespace = "private" }},
		{"kind", func(r *model.Report) { r.Target.Kind = "image" }},
		{"same-run", func(r *model.Report) { r.ID = "base" }},
		{"schema", func(r *model.Report) { r.SchemaVersion = "future" }},
		{"time", func(r *model.Report) { r.StartedAt = r.StartedAt.Add(-24 * time.Hour) }},
		{"duplicate", func(r *model.Report) { r.Findings = append(r.Findings, r.Findings[0]) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := comparisonFixture()
			tt.mutate(b)
			if _, e := Compare(a, b); e == nil {
				t.Fatal("accepted invalid pair")
			}
		})
	}
}
func TestComponentDiffAndAdvisoryWarnings(t *testing.T) {
	a, b := comparisonFixture()
	a.Components = []model.Component{{ID: "a", Name: "lib", Version: "1", PURL: "pkg:go/lib@1", Licenses: []model.LicenseEvidence{{Expression: "MIT"}}}}
	b.Components = []model.Component{{ID: "b", Name: "lib", Version: "1", PURL: "pkg:go/lib@1", Licenses: []model.LicenseEvidence{{Expression: "GPL-3.0-only"}}}, {ID: "new", Name: "added", Version: "2"}}
	a.Engines[0].Database = json.RawMessage(`{"built":"a"}`)
	b.Engines[0].Database = json.RawMessage(`{"built":"b"}`)
	r, e := Compare(a, b)
	if e != nil || r.ComponentCounts["changed"] != 1 || r.ComponentCounts["added"] != 1 {
		t.Fatal(r, e)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "database metadata differs") {
		t.Fatal("database changes not reported")
	}
	b.Components[0].Version = "2"
	r, e = Compare(a, b)
	if e != nil || r.ComponentCounts["removed"] != 1 || r.ComponentCounts["added"] != 2 {
		t.Fatal("versions incorrectly merged", r, e)
	}
}
func TestMissingUnattributedFindingIsNotAutomaticallyResolved(t *testing.T) {
	a, b := comparisonFixture()
	a.Findings[2].Category = "unknown"
	a.Findings[2].Observations = nil
	r, e := Compare(a, b)
	if e != nil || r.Counts.Unverified != 1 {
		t.Fatal(r, e)
	}
}
