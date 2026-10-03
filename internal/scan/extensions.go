package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/model"
	"sekscan/internal/runner"
	"sekscan/internal/scannerdb"
	"sekscan/internal/store"
	"sekscan/internal/workspace"
)

func (s *Scanner) runExtension(ctx context.Context, r *model.Report, o Options, temp, sbom string, e config.Extension, env []string, timeout time.Duration, max int64) {
	category := e.Category
	if category == "" {
		category = "code"
	}
	check := category
	if check == "misconfiguration" {
		check = "misconfig"
	}
	er := model.EngineRun{Name: e.Name, Required: e.Required, Status: "skipped", Checks: []string{check}}
	defer func() {
		r.Engines = append(r.Engines, er)
		if er.Status == "failed" {
			s.Logger.Error("scanner failed", "engine", e.Name, "error", er.Error)
		}
		s.Logger.Info("scanner finished", "engine", e.Name, "status", er.Status, "reason", er.Error)
	}()
	applicable := false
	for _, target := range e.Targets {
		if target == o.Target.Kind {
			applicable = true
		}
	}
	if !applicable {
		er.Required = false
		er.Error = "Not applicable to this target type"
		return
	}
	additionalPaths := []string{}
	for _, p := range []string{o.Output, o.Cache} {
		if p != "" {
			abs, _ := filepath.Abs(p)
			additionalPaths = append(additionalPaths, abs)
		}
	}
	exclusions := analyzerExclusions(s.Config, o.Target, additionalPaths...)
	inputs, err := selectInputs(ctx, o.Target, e.When, exclusions)
	if err != nil {
		er.Status = "failed"
		er.Error = err.Error()
		return
	}
	if len(inputs) == 0 {
		er.Required = false
		er.Error = noAnalyzerInputsReason(e.When)
		return
	}
	s.Logger.Info("analyzer inputs selected", "engine", e.Name, "selector", e.When, "inputs", len(inputs))
	er.Status = "failed"
	if o.Offline && !e.Offline {
		er.Error = "Custom extension has not declared offline support; network behavior is uncontrolled"
		return
	}
	if e.Timeout != "" {
		timeout, _ = time.ParseDuration(e.Timeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if e.Tool != "" {
		st := s.Deps.Inspect(ctx, e.Tool, s.Config.Tools[e.Tool])
		if st.Error != "" {
			er.Error = st.Error
			return
		}
		e.Executable = st.Path
		er.Version = st.Version
		er.ExecutableSHA256 = st.SHA256
		if e.NativeConfig == "" {
			e.NativeConfig = s.Config.Tools[e.Tool].NativeConfig
		}
	}
	for _, name := range e.RequiresTools {
		st := s.Deps.Inspect(ctx, name, s.Config.Tools[name])
		if st.Error != "" {
			er.Error = "Required runtime " + name + ": " + st.Error
			return
		}
	}
	if e.Builtin && e.When == "go-modules" {
		// No dependency installation, network VCS, repository scripts, C compiler, or
		// automatic toolchain switching during analysis. Warm caches explicitly.
		env = runner.Merge(env, "GOFLAGS=-mod=readonly", "GOWORK=off", "GOPROXY=off", "GONOPROXY=none", "GOVCS=*:off", "GOTOOLCHAIN=local", "CGO_ENABLED=0")
		r.Warnings = append(r.Warnings, e.Name+" uses the prepared Go toolchain and dependency cache, with CGO disabled and each discovered module analyzed separately. Missing dependencies or unsupported build constraints cause incomplete coverage; no go generate/test/build scripts are executed.")
	}
	dbURL := ""
	if e.Builtin && e.Name == "govulncheck" {
		r.Warnings = append(r.Warnings, "govulncheck analyzes each selected Go module as ./...; discovery exclusions do not remove imported packages or individual files from Go call-graph analysis.")
		dbc := s.Config
		if o.Cache != "" {
			dbc.Paths.Cache = o.Cache
		}
		status := scannerdb.InspectGovulncheck(dbc)
		if status.State != "ready" {
			er.Error = status.Error
			return
		}
		er.Database, _ = json.Marshal(status)
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(status.Path)}
		if !strings.HasPrefix(u.Path, "/") {
			u.Path = "/" + u.Path
		}
		dbURL = u.String()
	}
	if e.Builtin && e.NativeConfig == "" {
		standard := map[string]string{"hadolint": "hadolint.yaml", "gosec": "gosec.json"}[e.Name]
		if standard != "" {
			e.NativeConfig = filepath.Join(temp, standard)
			b, readErr := workspace.ReadDefault(standard)
			if readErr != nil {
				er.Error = readErr.Error()
				return
			}
			if err = store.Atomic(e.NativeConfig, b, 0600); err != nil {
				er.Error = err.Error()
				return
			}
		}
	}
	if e.Builtin && e.NativeConfig != "" && (e.Name == "govulncheck" || e.Name == "zizmor") {
		er.Error = "This built-in adapter does not accept native_config; use its supported options or an explicit extension definition"
		return
	}
	if e.Builtin {
		r.Warnings = append(r.Warnings, e.Name+": source discovery excludes node_modules, vendor, .venv and .git directories as well as configured/workspace exclusions.")
	}
	if e.Builtin && e.Name == "zizmor" {
		r.Warnings = append(r.Warnings, "zizmor uses offline audits only; checks requiring GitHub API/network data are not performed.")
	}
	if e.NativeConfig != "" {
		if _, err = store.Read(e.NativeConfig, 4<<20); err != nil {
			er.Error = "Cannot read extension native configuration"
			return
		}
		er.ConfigSHA256, err = store.SHA256(e.NativeConfig)
		if err != nil {
			er.Error = err.Error()
			return
		}
	}
	executable, err := exec.LookPath(e.Executable)
	if err != nil {
		er.Error = "Extension executable not found"
		return
	}
	executable, _ = filepath.Abs(executable)
	er.Executable = executable
	if er.ExecutableSHA256 == "" {
		er.ExecutableSHA256, err = store.SHA256(executable)
		if err != nil {
			er.Error = err.Error()
			return
		}
	}
	if e.Tool == "" && len(e.VersionArgs) > 0 {
		v, err := s.Executor.Run(ctx, runner.Request{Executable: executable, Args: e.VersionArgs, Dir: temp, Env: env, Timeout: 15 * time.Second, MaxOutput: 1 << 20})
		if err != nil {
			er.Error = "Extension version probe failed"
			return
		}
		er.Version = deps.ExtractVersion(v.Stdout)
	}
	// Run one Dockerfile/workflow/module at a time. This avoids command-line limits
	// and lets us keep evidence from successful inputs when another input fails.
	groups := [][]string{inputs}
	if e.When == "go-modules" || e.When == "dockerfiles" || e.When == "workflows" {
		groups = nil
		for _, p := range inputs {
			groups = append(groups, []string{p})
		}
	}
	failures := 0
	firstError := ""
	totalBytes := int64(0)
	for i, group := range groups {
		if ctx.Err() != nil {
			failures++
			firstError = "Analyzer cancelled or timed out"
			break
		}
		cwd := temp
		if e.WorkingDirectory == "target" {
			cwd = o.Target.Value
		}
		if e.When == "go-modules" {
			cwd = group[0]
		}
		output := filepath.Join(temp, fmt.Sprintf("%s-%d.json", e.Name, i))
		args := []string{}
		for _, a := range e.Args {
			if a == "{inputs}" {
				args = append(args, group...)
				continue
			}
			if strings.Contains(a, "{native_config}") && e.NativeConfig == "" {
				er.Error = "Extension requires native_config"
				return
			}
			if strings.Contains(a, "{sbom}") {
				if _, err = os.Stat(sbom); err != nil {
					er.Error = "Required SBOM is unavailable"
					return
				}
			}
			if strings.Contains(a, "{govulndb}") && dbURL == "" {
				er.Error = "Local govulncheck database is unavailable"
				return
			}
			args = append(args, strings.NewReplacer("{native_config}", e.NativeConfig, "{target}", o.Target.Value, "{sbom}", sbom, "{output}", output, "{govulndb}", dbURL).Replace(a))
		}
		if e.Builtin && e.Name == "gosec" {
			for _, p := range exclusions {
				abs := filepath.Join(o.Target.Value, filepath.FromSlash(p))
				rel, _ := filepath.Rel(cwd, abs)
				if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					args = append([]string{"-exclude-dir=" + filepath.ToSlash(rel)}, args...)
				}
			}
		}
		if e.Tool != "" {
			if e.Builtin {
				if e.Name == "gosec" || e.Name == "govulncheck" {
					args = append(append([]string{}, s.Config.Tools[e.Tool].ExtraArgs...), args...)
				} else {
					args = beforeSeparator(args, s.Config.Tools[e.Tool].ExtraArgs)
				}
			}
			args, err = s.Deps.InvocationArgs(e.Tool, s.Config.Tools[e.Tool], args)
			if err != nil {
				er.Error = err.Error()
				return
			}
		}
		if e.When == "go-modules" {
			s.Logger.Info("Go module selected", "engine", e.Name, "module", group[0], "input", i+1, "inputs", len(groups))
		}
		s.Logger.Info("scanner started", "engine", e.Name, "version", er.Version, "input", i+1, "inputs", len(groups))
		result, runErr := s.Executor.Run(ctx, runner.Request{Executable: executable, Args: args, Dir: cwd, Env: env, Timeout: timeout, MaxOutput: max, SuccessCodes: e.SuccessCodes})
		er.DurationMS += result.Duration.Milliseconds()
		s.saveDiagnostics(e.Name, result.Stderr)
		if runErr == nil {
			b := result.Stdout
			if e.OutputSource != "stdout" {
				b, runErr = store.Read(output, max)
			}
			totalBytes += int64(len(b))
			if totalBytes > max {
				runErr = fmt.Errorf("combined analyzer output exceeds configured limit")
			}
			if runErr == nil {
				var findings []model.Finding
				switch e.Parser {
				case "hadolint-json":
					findings, runErr = ParseHadolint(b)
				case "gosec-json":
					findings, runErr = ParseGosec(b)
				default:
					findings, runErr = ParseSARIF(b, e.Name)
				}
				if runErr != nil && e.Parser == "gosec-json" {
					s.saveGosecDiagnostics(b)
				}
				for j := range findings {
					findings[j].Category = category
					if e.RedactMessages {
						findings[j].Title = e.Name + " check " + strings.TrimPrefix(findings[j].RuleID, e.Name+":")
						findings[j].Description = "Inspect the rule and indicated source locations. Source-bearing messages and snippets are omitted from shared reports."
					}
					if e.Builtin {
						for k := range findings[j].Locations {
							p, locationErr := analyzerLocation(e.Name, o.Target.Value, cwd, group, findings[j].Locations[k].Path)
							if locationErr != nil {
								if runErr == nil {
									runErr = locationErr
								}
								findings[j].Locations[k].Path = "[unresolved source location]"
							} else {
								findings[j].Locations[k].Path = p
							}
						}
					}
				}
				r.Findings = append(r.Findings, findings...)
			}
		}
		if runErr != nil {
			s.Logger.Error("analyzer invocation failed", "engine", e.Name, "input", i+1, "inputs", len(groups), "error", runErr.Error())
			failures++
			if firstError == "" {
				firstError = runErr.Error()
			}
		}
	}
	if failures > 0 {
		er.Error = fmt.Sprintf("%d analyzer invocation(s) failed: %s", failures, firstError)
		return
	}
	er.Status = "completed"
}
func beforeSeparator(args, extra []string) []string {
	for i, a := range args {
		if a == "--" {
			out := append([]string{}, args[:i]...)
			out = append(out, extra...)
			return append(out, args[i:]...)
		}
	}
	return append(args, extra...)
}
