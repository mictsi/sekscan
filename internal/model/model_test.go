package model

import "testing"

func TestSummaryDistinguishesIncompleteFromClean(t *testing.T) {
	r := &Report{Engines: []EngineRun{{Name: "required", Required: true, Status: "failed"}}}
	r.Summarize(true)
	if r.Complete || r.Status != "incomplete" || r.ExitCode != 2 {
		t.Fatal(r)
	}
	r.Engines[0].Status = "completed"
	r.Summarize(true)
	if !r.Complete || r.Status != "passed" || r.ExitCode != 0 {
		t.Fatal(r)
	}
	r.Findings = []Finding{{Category: "license", Severity: "medium", Decision: "review", Baseline: "new"}}
	r.Summarize(true)
	if r.ExitCode != 1 || r.Summary.Reviews != 1 {
		t.Fatal(r)
	}
	r.Summarize(false)
	if r.ExitCode != 0 {
		t.Fatal("review waiver ignored")
	}
}
