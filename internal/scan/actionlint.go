package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/model"
	"sekscan/internal/runner"
	"sekscan/internal/store"
)

// The envelope distinguishes completed empty output from a missing report.
const actionlintFormat = `{"sekscan_actionlint":1,"findings":{{json .}}}`

func ParseActionlint(b []byte) ([]model.Finding, error) {
	var doc struct {
		Version  int             `json:"sekscan_actionlint"`
		Findings json.RawMessage `json:"findings"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.Version != 1 || len(doc.Findings) == 0 {
		return nil, fmt.Errorf("invalid actionlint JSON report")
	}
	var entries []struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
		File    string `json:"filepath"`
		Line    int    `json:"line"`
	}
	if json.Unmarshal(doc.Findings, &entries) != nil {
		return nil, fmt.Errorf("invalid actionlint findings")
	}
	out := []model.Finding{}
	for _, entry := range entries {
		if entry.Kind == "" || entry.File == "" || entry.Line < 1 {
			return nil, fmt.Errorf("actionlint finding is missing rule/location")
		}
		// Diagnostic messages can quote workflow source. Retain locations and
		// rule names, not the original snippet or message, in shared reports.
		out = append(out, model.Finding{
			Category: "misconfiguration", RuleID: "actionlint:" + entry.Kind,
			Scope: "application", Severity: "medium", Title: "GitHub Actions workflow: " + entry.Kind,
			Description:  "Workflow validation finding. Inspect the indicated rule and source location; source-bearing diagnostic text was omitted. Severity is sekscan's medium policy mapping, not a CVSS score.",
			Locations:    []model.Location{{Path: entry.File, Line: entry.Line}},
			Observations: []model.Observation{{Engine: "actionlint", Severity: "medium", SeveritySource: "sekscan workflow-validation mapping"}},
		})
	}
	return out, nil
}

func (s *Scanner) runActionlint(ctx context.Context, r *model.Report, o Options, temp string, env []string, timeout time.Duration, max int64) {
	er := model.EngineRun{Name: "actionlint", Status: "skipped", Checks: []string{"misconfig"}}
	defer func() { r.Engines = append(r.Engines, er) }()
	if o.Target.Kind != "dir" {
		er.Error = "Only applies to source directories"
		return
	}
	dir := filepath.Join(o.Target.Value, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		er.Error = "No .github/workflows directory"
		return
	}
	er.Required = true
	er.Status = "failed"
	if err != nil {
		er.Error = "Cannot read workflow directory"
		return
	}
	if err = config.WithinDirectory(o.Target.Value, dir); err != nil {
		er.Error = err.Error()
		return
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		name := filepath.Join(dir, entry.Name())
		excluded := false
		rel, _ := filepath.Rel(o.Target.Value, name)
		for _, prefix := range s.Config.Exclude {
			p := filepath.ToSlash(filepath.Clean(prefix))
			if filepath.ToSlash(rel) == p || strings.HasPrefix(filepath.ToSlash(rel), p+"/") {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		if err = config.WithinDirectory(o.Target.Value, name); err != nil {
			er.Error = err.Error()
			return
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			er.Error = "Workflow input is not a regular file"
			return
		}
		if info.Size() > 8<<20 {
			er.Error = "Workflow file exceeds 8 MiB limit"
			return
		}
		paths = append(paths, name)
	}
	if len(paths) == 0 {
		er.Status = "skipped"
		er.Required = false
		er.Error = "No non-excluded YAML workflows"
		return
	}
	if len(paths) > 1024 {
		er.Error = "Workflow count exceeds 1024; split the target"
		return
	}
	tool := s.Config.Tools["actionlint"]
	status := s.Deps.Inspect(ctx, "actionlint", tool)
	er.Version, er.Executable, er.ExecutableSHA256 = status.Version, status.Path, status.SHA256
	if status.Error != "" {
		er.Error = status.Error
		return
	}
	// Always pass an explicit trusted config so the target cannot load its own.
	cfg := filepath.Join(temp, "empty.yaml")
	if tool.NativeConfig != "" {
		cfg = tool.NativeConfig
		if _, err = store.Read(cfg, 4<<20); err != nil {
			er.Error = "Cannot read actionlint native config"
			return
		}
		er.ConfigSHA256, _ = store.SHA256(cfg)
	}
	args := []string{"-config-file", cfg}
	args = append(args, tool.ExtraArgs...)
	// Optional external linters are intentionally disabled: no hidden PATH/runtime dependency.
	args = append(args, "-shellcheck=", "-pyflakes=", "-format", actionlintFormat, "--")
	args = append(args, paths...)
	s.Logger.Info("scanner started", "engine", "actionlint", "version", status.Version)
	result, err := s.Executor.Run(ctx, runner.Request{Executable: status.Path, Args: s.Deps.CommandArgs("actionlint", s.Config.Tools["actionlint"], args), Dir: temp, Env: env, Timeout: timeout, MaxOutput: max, SuccessCodes: []int{0, 1}})
	er.DurationMS = result.Duration.Milliseconds()
	s.saveDiagnostics("actionlint", result.Stderr)
	if err == nil {
		var findings []model.Finding
		findings, err = ParseActionlint(result.Stdout)
		if err == nil {
			// Actionlint reports paths relative to its working directory.
			for i := range findings {
				for j := range findings[i].Locations {
					p := findings[i].Locations[j].Path
					if !filepath.IsAbs(p) {
						p = filepath.Join(temp, p)
					}
					if err = config.WithinDirectory(o.Target.Value, p); err != nil {
						break
					}
					findings[i].Locations[j].Path = p
				}
				if err != nil {
					break
				}
			}
			if err == nil {
				r.Findings = append(r.Findings, findings...)
			}
		}
	}
	if err != nil {
		er.Error = err.Error()
		s.Logger.Error("scanner failed", "engine", "actionlint", "error", er.Error)
	} else {
		er.Status = "completed"
	}
	s.Logger.Info("scanner finished", "engine", "actionlint", "status", er.Status)
}
