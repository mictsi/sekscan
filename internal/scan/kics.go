package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sekscan/internal/config"
	"sekscan/internal/model"
	"sekscan/internal/store"
)

var errKICSNotApplicable = errors.New("KICS found no supported IaC in the selected candidates")

func kicsInput(name string) bool {
	name = strings.ToLower(name)
	switch filepath.Ext(name) {
	case ".tf", ".tfvars", ".yaml", ".yml", ".json", ".jsonc", ".template", ".proto":
		return true
	}
	return name == "dockerfile" || name == "containerfile" || strings.HasPrefix(name, "dockerfile.") || strings.HasPrefix(name, "containerfile.") || strings.HasSuffix(name, ".dockerfile") || strings.HasSuffix(name, ".containerfile")
}

// Scan a bounded snapshot of selected files, retaining relative paths for
// cross-file checks. Exclusions and symlinks cannot re-enter through recursive
// scanner discovery; target-local configuration is never loaded implicitly.
func kicsArguments(ctx context.Context, root, temp, executable, output string, inputs []string, native string) ([]string, string, error) {
	stage := filepath.Join(temp, "kics-input")
	if err := os.Mkdir(stage, 0700); err != nil {
		return nil, "", err
	}
	var total int64
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		if err := config.WithinDirectory(root, input); err != nil {
			return nil, "", err
		}
		st, err := os.Lstat(input)
		if err != nil || !st.Mode().IsRegular() {
			return nil, "", fmt.Errorf("KICS input is not a regular file")
		}
		// Match the scanner limit; silently skipped oversized files must not be a pass.
		if st.Size() > 5<<20 {
			return nil, "", fmt.Errorf("KICS input exceeds the 5 MiB scan limit")
		}
		total += st.Size()
		if total > 256<<20 {
			return nil, "", fmt.Errorf("KICS input snapshot exceeds 256 MiB; split the project")
		}
		b, err := store.Read(input, 5<<20)
		if err != nil {
			return nil, "", err
		}
		rel, _ := filepath.Rel(root, input)
		if err = store.Atomic(filepath.Join(stage, rel), b, 0600); err != nil {
			return nil, "", err
		}
	}
	assets := filepath.Join(filepath.Dir(executable), "assets")
	for _, sub := range []string{"queries", "libraries"} {
		p := filepath.Join(assets, sub)
		if err := config.WithinDirectory(filepath.Dir(executable), p); err != nil {
			return nil, "", err
		}
		st, err := os.Stat(p)
		if err != nil || !st.IsDir() {
			return nil, "", fmt.Errorf("KICS needs its matching local assets/%s; reinstall the full bundle", sub)
		}
	}
	if native == "" {
		native = filepath.Join(temp, "kics-config.json")
		if err := store.Atomic(native, []byte("{}"), 0600); err != nil {
			return nil, "", err
		}
	}
	args := []string{"scan", "--path", stage, "--config", native,
		"--queries-path", filepath.Join(assets, "queries"), "--libraries-path", filepath.Join(assets, "libraries"),
		"--report-formats", "json", "--output-path", filepath.Dir(output), "--output-name", filepath.Base(output),
		"--ignore-on-exit", "results", "--disable-full-descriptions", "--disable-secrets", "--enable-openapi-refs=false",
		"--exclude-gitignore", "--max-file-size", "5", "--no-progress", "--silent"}
	return args, stage, nil
}

func kicsLocation(root, cwd, stage string, inputs []string, raw string) (string, error) {
	p, err := localAnalyzerPath(raw)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	if err = config.WithinDirectory(stage, p); err != nil {
		return "", fmt.Errorf("KICS location is outside the input snapshot")
	}
	rel, _ := filepath.Rel(stage, p)
	original := filepath.Join(root, rel)
	for _, input := range inputs {
		if filepath.Clean(input) == filepath.Clean(original) {
			if err = config.WithinDirectory(root, original); err != nil {
				return "", err
			}
			return original, nil
		}
	}
	return "", fmt.Errorf("KICS location is not a selected input")
}

// ParseKICS retains native severity and explicitly checks coverage counters even
// when the process exits successfully. Resource values and snippets are omitted.
func ParseKICS(b []byte) ([]model.Finding, error) {
	var doc struct {
		Version       string `json:"kics_version"`
		Scanned       *int   `json:"files_scanned"`
		Parsed        *int   `json:"files_parsed"`
		Failed        *int   `json:"files_failed_to_scan"`
		Total         *int   `json:"queries_total"`
		FailedQueries *int   `json:"queries_failed_to_execute"`
		FailedIDs     *int   `json:"queries_failed_to_compute_similarity_id"`
		Count         *int   `json:"total_counter"`
		Queries       []struct {
			ID       string `json:"query_id"`
			Severity string `json:"severity"`
			Files    []struct {
				Name string `json:"file_name"`
				Line int    `json:"line"`
			} `json:"files"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("invalid KICS JSON")
	}
	if doc.Version == "" {
		return nil, fmt.Errorf("KICS report has no version")
	}
	for _, n := range []*int{doc.Scanned, doc.Parsed, doc.Failed, doc.Total, doc.FailedQueries, doc.FailedIDs, doc.Count} {
		if n == nil || *n < 0 {
			return nil, fmt.Errorf("KICS report has missing or invalid coverage counters")
		}
	}
	out := []model.Finding{}
	for _, q := range doc.Queries {
		if q.ID == "" || len(q.Files) == 0 {
			return out, fmt.Errorf("KICS result missing rule or files")
		}
		severity := strings.ToLower(q.Severity)
		switch severity {
		case "critical", "high", "medium", "low", "info":
		case "trace":
			severity = "info"
		default:
			return out, fmt.Errorf("unknown KICS severity")
		}
		for _, f := range q.Files {
			if f.Name == "" || f.Line < 1 {
				return out, fmt.Errorf("invalid KICS finding location")
			}
			out = append(out, model.Finding{Category: "misconfiguration", RuleID: "kics:" + q.ID, Scope: "application", Severity: severity,
				Title: "KICS check " + q.ID, Description: "Inspect the rule and indicated source location. Resource values and source snippets are omitted.",
				Locations: []model.Location{{Path: f.Name, Line: f.Line}}, Observations: []model.Observation{{Engine: "kics", Severity: severity, SeveritySource: "KICS query severity"}}})
		}
	}
	if *doc.Count != len(out) {
		return out, fmt.Errorf("KICS finding count does not match report")
	}
	if *doc.Failed != 0 || *doc.FailedQueries != 0 || *doc.FailedIDs != 0 {
		return out, fmt.Errorf("KICS reported file or query processing failures; analysis is incomplete")
	}
	if *doc.Scanned == 0 || *doc.Parsed == 0 || *doc.Total == 0 {
		if *doc.Scanned == 0 && *doc.Parsed == 0 && *doc.Total == 0 && len(out) == 0 {
			return out, errKICSNotApplicable
		}
		return out, fmt.Errorf("KICS did not analyze files with queries; review IaC applicability and local rule assets")
	}
	return out, nil
}
