package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/model"
	"sekscan/internal/policy"
	"sekscan/internal/runner"
	"sekscan/internal/store"
)

type Options struct {
	Source         *model.Source
	BatchID        string
	SourceComplete bool
	SourceWarnings []string
	DenyEnv        []string
	Target         model.Target
	Output         string
	Cache          string
	Offline        bool
	Baseline       *model.Report
	Revision       string
	AppVersion     string
}
type Scanner struct {
	Config   config.Config
	Deps     *deps.Manager
	Executor runner.Executor
	Logger   *slog.Logger
}

func (s *Scanner) Run(ctx context.Context, o Options) (*model.Report, error) {
	if e := s.Config.Validate(); e != nil {
		return nil, e
	}
	if o.Offline && o.Target.Kind == "image" {
		return nil, fmt.Errorf("offline image scans require a local archive or rootfs, not a registry/image reference")
	}
	if s.Config.Policy.OnlyNew && o.Baseline == nil {
		return nil, fmt.Errorf("only_new policy requires --baseline")
	}
	if o.Baseline != nil && o.Baseline.Target.Kind != o.Target.Kind {
		return nil, fmt.Errorf("baseline target kind differs from current target")
	}
	if s.Deps == nil {
		s.Deps = deps.NewConfigured("", s.Config)
	}
	if s.Executor == nil {
		s.Executor = runner.OSExecutor{}
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if o.Cache == "" {
		o.Cache = s.Config.Paths.Cache
		if o.Cache == "" {
			o.Cache = "cache"
		}
	}
	o.Cache, _ = filepath.Abs(o.Cache)
	if e := os.MkdirAll(o.Output, 0700); e != nil {
		return nil, e
	}
	temp, e := os.MkdirTemp("", "sekscan-work-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(temp)
	if e = store.Atomic(filepath.Join(temp, "empty.yaml"), []byte("{}\n"), 0600); e != nil {
		return nil, e
	}
	if e = store.Atomic(filepath.Join(temp, "ignore"), []byte{}, 0600); e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	r := &model.Report{SchemaVersion: model.SchemaVersion, AppVersion: o.AppVersion, ID: model.Hash(now.String(), o.Target.Value)[:24], StartedAt: now, Target: o.Target, Revision: o.Revision, ConfigHash: s.Config.Hash(), Components: []model.Component{}, Findings: []model.Finding{}, Resolved: []model.Finding{}, Engines: []model.EngineRun{}, Warnings: []string{}}
	r.Source, r.BatchID = o.Source, o.BatchID
	if o.Source != nil {
		status, message := "completed", ""
		if !o.SourceComplete {
			status, message = "failed", "Source acquisition has coverage gaps; inspect the coverage notes"
		}
		r.Engines = append(r.Engines, model.EngineRun{Name: "github-source", Status: status, Required: true, Checks: []string{"source"}, Error: message})
		r.Warnings = append(r.Warnings, o.SourceWarnings...)
	}
	r.Warnings = append(r.Warnings, s.Config.MigrationWarnings...)
	s.Deps.DenyEnv = append(s.Deps.DenyEnv, o.DenyEnv...)
	r.Warnings = append(r.Warnings, "Coverage is limited to artifacts visible to the scanners. No project builds or dependency installations were executed.", "License checks apply to application dependencies; results express organizational policy, not legal compatibility.")
	if o.Target.Kind == "dir" {
		r.Warnings = append(r.Warnings, "A directory scan does not inspect a built container image. Source analyzers cover only applicable inputs and configured rules; inspect Scan health for completed, skipped and failed checks.")
	}
	if o.Offline {
		r.Warnings = append(r.Warnings, "Offline mode disables supported scanner update/enrichment paths. It is not an operating-system network sandbox; enforce egress restrictions for a strict air gap.")
	}
	inventory := NewInventory()
	timeout, _ := time.ParseDuration(s.Config.Timeout)
	max := int64(s.Config.MaxOutputMB) << 20
	s.Deps.CacheDir = o.Cache
	s.Deps.MaxDBAge = s.Config.MaxDBAge
	env, e := s.Deps.Environment(o.Offline)
	if e != nil {
		return nil, e
	}
	env = runner.Without(env, s.Config.Storage.DSNEnv)
	if s.Config.Portable {
		r.Warnings = append(r.Warnings, "Portable execution uses workspace-managed binaries and isolated home/cache directories. Registry credentials and OS trust stores are external inputs; this is not a filesystem or network sandbox.")
	}
	s.Logger.Info("scanner workspace", "bin", s.Deps.Dir, "cache", o.Cache, "portable", s.Config.Portable, "offline", o.Offline)

	runTool := func(name string, checks []string, args []string, parse func([]byte) error) bool {
		tool := s.Config.Tools[name]
		status := s.Deps.Inspect(ctx, name, tool)
		er := model.EngineRun{Name: name, Version: status.Version, Executable: status.Path, ExecutableSHA256: status.SHA256, Status: "failed", Required: true, Checks: checks}
		if status.Error != "" {
			er.Error = status.Error
			r.Engines = append(r.Engines, er)
			s.Logger.Error("scanner unavailable", "engine", name, "error", status.Error)
			return false
		}
		var setupErr error
		args, er.ConfigSHA256, setupErr = configureInvocation(tool, args)
		if setupErr != nil {
			er.Error = setupErr.Error()
			r.Engines = append(r.Engines, er)
			return false
		}
		s.Logger.Info("scanner started", "engine", name, "version", status.Version)
		result, err := s.Executor.Run(ctx, runner.Request{Executable: status.Path, Args: s.Deps.CommandArgs(name, s.Config.Tools[name], args), Dir: temp, Env: env, Timeout: timeout, MaxOutput: max})
		er.DurationMS = result.Duration.Milliseconds()
		s.saveDiagnostics(name, result.Stderr)
		if err == nil {
			err = parse(result.Stdout)
		}
		if err == nil {
			er.Status = "completed"
		} else {
			er.Error = err.Error()
			s.Logger.Error("scanner failed", "engine", name, "error", err.Error())
		}
		r.Engines = append(r.Engines, er)
		s.Logger.Info("scanner finished", "engine", name, "status", er.Status)
		return err == nil
	}
	// Keep operational data out of scans; never exclude the entire target itself.
	for _, p := range []string{s.Config.Paths.Bin, s.Config.Paths.Cache, s.Config.Paths.Logs, s.Config.Paths.Data, s.Config.Storage.Path, s.Config.Storage.Path + "-wal", s.Config.Storage.Path + "-shm"} {
		if filepath.IsAbs(p) && (o.Target.Kind == "dir" || o.Target.Kind == "rootfs") {
			rel, err := filepath.Rel(o.Target.Value, p)
			if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				s.Config.Exclude = append(s.Config.Exclude, filepath.ToSlash(rel))
			}
		}
	}
	// Keep report output out of the scan, even on repeated scans of the same tree.
	exclusions := append([]string{}, s.Config.Exclude...)
	if o.Target.Kind == "dir" || o.Target.Kind == "rootfs" {
		outAbs, _ := filepath.Abs(o.Output)
		rel, err := filepath.Rel(o.Target.Value, outAbs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			exclusions = append(exclusions, filepath.ToSlash(rel))
		}
		cacheRel, err := filepath.Rel(o.Target.Value, o.Cache)
		if err == nil && cacheRel != ".." && !strings.HasPrefix(cacheRel, ".."+string(filepath.Separator)) {
			exclusions = append(exclusions, filepath.ToSlash(cacheRel))
		}
	}
	syftArgs := []string{"--config", filepath.Join(temp, "empty.yaml"), "scan"}
	if o.Target.Kind == "sbom" {
		syftArgs = []string{"--config", filepath.Join(temp, "empty.yaml"), "convert"}
	} else {
		for _, p := range syftExclusions(o.Target.Kind, exclusions) {
			syftArgs = append(syftArgs, "--exclude", p)
		}
	}
	nativeSBOM := filepath.Join(temp, "sbom.syft.json")
	syftArgs = append(syftArgs, "-o", "syft-json", "-o", "cyclonedx-json="+filepath.Join(temp, "sbom.cdx.json"), "-o", "spdx-json="+filepath.Join(temp, "sbom.spdx.json"))
	if o.Target.Kind == "rootfs" {
		syftArgs = append(syftArgs, "--override-default-catalogers", "image")
	}
	source := syftTarget(o.Target)
	if o.Target.Kind == "sbom" {
		source = o.Target.Value
	}
	syftArgs = append(syftArgs, "--", source)
	inventoryChecks := []string{"inventory", "sbom"}
	if s.Config.Checks.Licenses {
		inventoryChecks = append(inventoryChecks, "license")
	}
	inventoryOK := runTool("syft", inventoryChecks, syftArgs, func(b []byte) error {
		identity, err := ParseSyft(b, inventory)
		if err != nil {
			return err
		}
		if identity != "" {
			r.Target.Identity = identity
		}
		if err = store.Atomic(nativeSBOM, b, 0600); err != nil {
			return err
		}
		if err = store.Atomic(filepath.Join(o.Output, "sbom.syft.json"), b, 0600); err != nil {
			return err
		}
		for _, file := range []string{"sbom.cdx.json", "sbom.spdx.json"} {
			b, err = store.Read(filepath.Join(temp, file), max)
			if err != nil {
				return fmt.Errorf("SBOM export %s: %w", file, err)
			}
			if !json.Valid(b) {
				return fmt.Errorf("invalid %s export", file)
			}
			if err = store.Atomic(filepath.Join(o.Output, file), b, 0600); err != nil {
				return err
			}
		}
		return nil
	})
	if s.Config.Checks.Vulnerabilities {
		if inventoryOK {
			var database json.RawMessage
			runTool("grype", []string{"vulnerability"}, []string{"--config", filepath.Join(temp, "empty.yaml"), "-o", "json", "--", "sbom:" + nativeSBOM}, func(b []byte) error {
				findings, db, err := ParseGrype(b, inventory)
				if err != nil {
					return err
				}
				database = db
				r.Findings = append(r.Findings, findings...)
				return nil
			})
			r.Engines[len(r.Engines)-1].Database = database
		} else {
			r.Engines = append(r.Engines, model.EngineRun{Name: "grype", Status: "skipped", Required: true, Checks: []string{"vulnerability"}, Error: "Blocked by Syft failure: inventory/SBOM generation did not complete. Grype was not executed, so no database update or vulnerability matching was attempted. Run prepare --all --yes to prepare databases independently."})
		}
	} else {
		r.Engines = append(r.Engines, model.EngineRun{Name: "grype", Status: "skipped", Checks: []string{"vulnerability"}, Error: "Disabled in configuration"})
	}
	checks := []string{}
	if s.Config.Checks.Secrets {
		checks = append(checks, "secret")
	}
	if s.Config.Checks.Misconfigurations {
		checks = append(checks, "misconfig")
	}
	if s.Config.Checks.Licenses {
		checks = append(checks, "license")
	}
	if s.Config.Checks.TrivyVulnerabilities {
		checks = append(checks, "vuln")
	}
	if len(checks) > 0 {
		if o.Target.Kind == "sbom" {
			r.Engines = append(r.Engines, model.EngineRun{Name: "trivy", Status: "skipped", Required: s.Config.Checks.TrivyVulnerabilities, Checks: checks, Error: "SBOM-only mode has no file contents; use Grype for SBOM vulnerability matching"})
			r.Warnings = append(r.Warnings, "SBOM-only mode skips source/image secrets and configuration checks. License policies use the supplied SBOM evidence only.")
		} else {
			sub := "image"
			if o.Target.Kind == "dir" {
				sub = "filesystem"
			}
			if o.Target.Kind == "rootfs" {
				sub = "rootfs"
			}
			args := []string{sub, "--config", filepath.Join(temp, "empty.yaml"), "--cache-dir", filepath.Join(o.Cache, "trivy"), "--format", "json", "--scanners", strings.Join(checks, ","), "--exit-code", "0", "--no-progress", "--ignorefile", filepath.Join(temp, "ignore"), "--timeout", s.Config.Timeout}
			if s.Config.LicenseFull {
				args = append(args, "--license-full")
			}
			if o.Offline {
				args = append(args, "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update")
			}
			for _, p := range exclusions {
				args = append(args, "--skip-dirs", p, "--skip-files", p)
			}
			if sub == "image" {
				imageChecks := []string{}
				if s.Config.Checks.Secrets {
					imageChecks = append(imageChecks, "secret")
				}
				if s.Config.Checks.Misconfigurations {
					imageChecks = append(imageChecks, "misconfig")
				}
				if len(imageChecks) > 0 {
					args = append(args, "--image-config-scanners", strings.Join(imageChecks, ","))
				}
			}
			if o.Target.Kind == "docker-archive" || o.Target.Kind == "oci-archive" || o.Target.Kind == "oci-layout" {
				args = append(args, "--input", o.Target.Value)
			} else {
				args = append(args, "--", o.Target.Value)
			}
			runTool("trivy", checks, args, func(b []byte) error {
				findings, err := ParseTrivy(b, inventory)
				if err != nil {
					return err
				}
				r.Findings = append(r.Findings, findings...)
				return nil
			})
			if s.Config.Checks.TrivyVulnerabilities {
				metadata, err := store.Read(filepath.Join(o.Cache, "trivy", "db", "metadata.json"), 1<<20)
				er := &r.Engines[len(r.Engines)-1]
				if err == nil && !json.Valid(metadata) {
					err = fmt.Errorf("invalid database metadata JSON")
				}
				if err == nil {
					er.Database = metadata
					var db struct {
						UpdatedAt time.Time `json:"UpdatedAt"`
					}
					err = json.Unmarshal(metadata, &db)
					age, _ := time.ParseDuration(s.Config.MaxDBAge)
					if err == nil && (db.UpdatedAt.IsZero() || time.Since(db.UpdatedAt) > age || db.UpdatedAt.After(time.Now().Add(time.Hour))) {
						err = fmt.Errorf("Trivy vulnerability database age is unknown or outside configured limit")
					}
				}
				if err != nil {
					er.Status = "failed"
					er.Error = "Could not validate Trivy vulnerability database metadata: " + err.Error()
				}
			}
		}
	} else {
		r.Engines = append(r.Engines, model.EngineRun{Name: "trivy", Status: "skipped", Checks: []string{}, Error: "Disabled in configuration"})
	}
	if s.Config.Checks.Gitleaks {
		if o.Target.Kind != "dir" && o.Target.Kind != "rootfs" {
			r.Engines = append(r.Engines, model.EngineRun{Name: "gitleaks", Status: "skipped", Required: false, Checks: []string{"secret"}, Error: "Gitleaks integration requires a directory or rootfs target"})
		} else {
			conf := "title = \"sekscan managed policy\"\n[extend]\nuseDefault = true\n"
			if len(exclusions) > 0 {
				conf += "[allowlist]\ndescription = \"Explicit sekscan exclusions\"\npaths = [\n"
				for _, p := range exclusions {
					pattern := `(^|/)` + regexp.QuoteMeta(strings.TrimSuffix(filepath.ToSlash(p), "/")) + `(/|$)`
					encoded, _ := json.Marshal(pattern)
					conf += string(encoded) + ",\n"
				}
				conf += "]\n"
			}
			configPath := filepath.Join(temp, "gitleaks.toml")
			if e = store.Atomic(configPath, []byte(conf), 0600); e != nil {
				return nil, e
			}
			resultPath := filepath.Join(temp, "gitleaks.json")
			runTool("gitleaks", []string{"secret"}, []string{"dir", "--config", configPath, "--gitleaks-ignore-path", filepath.Join(temp, "ignore"), "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", resultPath, "--redact=100", "--exit-code", "0", "--no-banner", "--", o.Target.Value}, func(_ []byte) error {
				b, err := store.Read(resultPath, max)
				if err != nil {
					return err
				}
				findings, err := ParseGitleaks(b)
				if err == nil {
					r.Findings = append(r.Findings, findings...)
				}
				return err
			})
		}
	}
	if s.Config.Checks.Actionlint {
		s.runActionlint(ctx, r, o, temp, env, timeout, max)
	}
	for _, extension := range s.Config.EffectiveExtensions() {
		s.runExtension(ctx, r, o, temp, nativeSBOM, extension, env, timeout, max)
	}
	r.Components = inventory.Components
	relativeLocations(r)
	policy.ApplyScopes(r.Components, s.Config.ScopeOverrides)
	components := map[string]model.Component{}
	for _, c := range r.Components {
		components[c.ID] = c
	}
	for i := range r.Findings {
		if c, ok := components[r.Findings[i].ComponentID]; ok {
			r.Findings[i].Scope = c.Scope
		}
	}
	if s.Config.Checks.Licenses {
		r.Findings = append(r.Findings, policy.LicenseFindings(r.Components, s.Config.Policy.Licenses)...)
	}
	if len(r.Components) == 0 {
		r.Warnings = append(r.Warnings, "No packages were discovered. This is not evidence that the target has no dependencies.")
	}
	r.Findings = policy.Deduplicate(r.Findings, r.Components)
	r.FinishedAt = time.Now().UTC()
	policy.Apply(r, s.Config, o.Baseline, r.FinishedAt)
	if o.Source != nil {
		// Normalize source locations against the real checkout first, then replace the
		// ephemeral input path with a stable repository/subdirectory identity.
		r.Target.Value = o.Source.Repository
		if o.Source.Subdir != "" {
			r.Target.Value += "/" + o.Source.Subdir
		}
		r.Target.Identity = "github:" + r.Target.Value
	}
	return r, nil
}
