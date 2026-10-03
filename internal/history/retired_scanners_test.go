package history

import (
	"encoding/json"
	"sekscan/internal/model"
	"testing"
)

func TestRetiredScannerFindingsAreNotRemediated(t *testing.T) {
	a, b := comparisonFixture()
	a.Findings = []model.Finding{{ID: "old", Fingerprint: "old", RuleID: "semgrep/rule", Category: "code", Severity: "high", Observations: []model.Observation{{Engine: "semgrep"}}}}
	a.Engines = append(a.Engines, model.EngineRun{Name: "semgrep", Status: "completed", Required: true})
	b.Findings = nil
	before, _ := json.Marshal(a)
	result, err := Compare(a, b)
	if err != nil || result.Counts.Resolved != 0 || result.Counts.Unverified != 1 {
		t.Fatal(result, err)
	}
	after, _ := json.Marshal(a)
	if string(before) != string(after) {
		t.Fatal("historical evidence changed")
	}
}
