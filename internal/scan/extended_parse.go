package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"sekscan/internal/model"
	"sekscan/internal/runner"
)

var dockerRule = regexp.MustCompile(`^(DL|SC)[0-9]{4}$`)

func ParseHadolint(b []byte) ([]model.Finding, error) {
	var entries []struct {
		Code   string `json:"code"`
		Level  string `json:"level"`
		File   string `json:"file"`
		Line   int    `json:"line"`
		Column int    `json:"column"`
	}
	if trim := bytes.TrimSpace(b); len(trim) == 0 || trim[0] != '[' {
		return nil, fmt.Errorf("Hadolint must return a JSON findings array")
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("invalid Hadolint JSON")
	}
	out := []model.Finding{}
	parseFailed := false
	for _, e := range entries {
		if !dockerRule.MatchString(e.Code) || e.File == "" || e.Line < 1 {
			return out, fmt.Errorf("invalid Hadolint rule/location")
		}
		severity := ""
		switch e.Level {
		case "error":
			severity = "high"
		case "warning":
			severity = "medium"
		case "info":
			severity = "low"
		case "style", "ignore":
			severity = "info"
		default:
			return out, fmt.Errorf("unknown Hadolint level")
		}
		if e.Code == "DL1000" {
			parseFailed = true
		}
		out = append(out, model.Finding{Category: "misconfiguration", RuleID: "hadolint:" + e.Code, Scope: "application", Severity: severity, Title: "Dockerfile check " + e.Code, Description: "Inspect this rule at the indicated location. Source-bearing diagnostic text is omitted. Severity is a linter-to-policy mapping, not CVSS.", Locations: []model.Location{{Path: e.File, Line: e.Line}}, Observations: []model.Observation{{Engine: "hadolint", Severity: severity, SeveritySource: "sekscan Hadolint level mapping"}}})
	}
	if parseFailed {
		return out, fmt.Errorf("Hadolint could not parse a Dockerfile (DL1000); analysis is incomplete")
	}
	return out, nil
}

// Gosec's exit 1 includes both findings and processing errors. JSON's Golang errors
// and Stats must be checked even when -no-fail makes its process return zero.
func ParseGosec(b []byte) ([]model.Finding, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return nil, fmt.Errorf("invalid gosec JSON")
	}
	for _, key := range []string{"Golang errors", "Issues", "Stats"} {
		if _, ok := raw[key]; !ok {
			return nil, fmt.Errorf("gosec report missing %s", key)
		}
	}
	var errs map[string]json.RawMessage
	if json.Unmarshal(raw["Golang errors"], &errs) != nil {
		return nil, fmt.Errorf("invalid gosec processing errors")
	}
	var stats struct {
		Files int `json:"files"`
		Lines int `json:"lines"`
		Found int `json:"found"`
	}
	if json.Unmarshal(raw["Stats"], &stats) != nil || stats.Files < 0 {
		return nil, fmt.Errorf("invalid gosec statistics")
	}
	var entries []struct {
		Severity string `json:"severity"`
		Rule     string `json:"rule_id"`
		File     string `json:"file"`
		Line     string `json:"line"`
	}
	if json.Unmarshal(raw["Issues"], &entries) != nil {
		return nil, fmt.Errorf("invalid gosec issues")
	}
	out := []model.Finding{}
	for _, e := range entries {
		lineText, _, _ := strings.Cut(e.Line, "-")
		line, err := strconv.Atoi(lineText)
		if err != nil || line < 1 || e.Rule == "" || e.File == "" {
			return out, fmt.Errorf("invalid gosec issue location")
		}
		severity := model.NormalizeSeverity(e.Severity)
		out = append(out, model.Finding{Category: "code", RuleID: "gosec:" + e.Rule, Scope: "application", Severity: severity, Title: "Go security check " + e.Rule, Description: "Inspect the indicated rule and source location. Source snippets and diagnostic messages are not retained.", Locations: []model.Location{{Path: e.File, Line: line}}, Observations: []model.Observation{{Engine: "gosec", Severity: severity, SeveritySource: "gosec severity"}}})
	}
	for _, v := range errs {
		var entries []json.RawMessage
		if json.Unmarshal(v, &entries) != nil || len(entries) > 0 {
			hint := runner.GoFailureHint(raw["Golang errors"])
			if hint == "" {
				hint = "rerun with --diagnostic-stderr to save the Golang errors object in a private local log"
			}
			return out, fmt.Errorf("gosec reported package loading or processing errors; analysis is incomplete: %s", hint)
		}
	}
	if stats.Files == 0 {
		return out, fmt.Errorf("gosec did not analyze any Go files; review module dependencies, CGO and build constraints")
	}
	return out, nil
}
