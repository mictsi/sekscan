package config

// DefaultChecks enables the source extensions only where their selectors apply.
// Explicit false values in an existing configuration remain authoritative.
func DefaultChecks() Checks {
	return Checks{Vulnerabilities: true, Licenses: true, Secrets: true, Misconfigurations: true,
		Gitleaks: true, Actionlint: true, Hadolint: true, Zizmor: true, Govulncheck: true, Gosec: true}
}
func DefaultTools() map[string]Tool {
	return map[string]Tool{
		"syft": {Version: "latest"}, "grype": {Version: "latest"}, "trivy": {Version: "latest"}, "gitleaks": {Version: "latest"},
		"actionlint":  {Version: "latest", VersionArgs: []string{"-version"}},
		"hadolint":    {Version: "latest", VersionArgs: []string{"--version"}},
		"zizmor":      {Version: "latest", VersionArgs: []string{"--version"}},
		"gosec":       {Version: "latest", VersionArgs: []string{"-version"}},
		"govulncheck": {Version: "latest", VersionArgs: []string{"-version"}},
		"go":          {Version: "latest", VersionArgs: []string{"version"}},
	}
}

// EffectiveExtensions keeps default activation independent of custom extensions.
// An explicit definition with the same name replaces the corresponding default;
// checks.NAME=false disables the catalog entry (not an explicit custom entry).
func (c Config) EffectiveExtensions() []Extension {
	out := []Extension{}
	add := func(enabled bool, e Extension) {
		if !enabled {
			return
		}
		e.Required, e.Builtin, e.RedactMessages = true, true, true
		e.Targets = []string{"dir"}
		e.Tool = e.Name
		e.SuccessCodes = []int{0}
		out = append(out, e)
	}
	add(c.Checks.Hadolint, Extension{Name: "hadolint", When: "dockerfiles", Parser: "hadolint-json", Category: "misconfiguration", Offline: true, OutputSource: "stdout", Args: []string{"--config", "{native_config}", "--format", "json", "--no-fail", "--no-color", "--disable-ignore-pragma", "--", "{inputs}"}})
	add(c.Checks.Zizmor, Extension{Name: "zizmor", When: "workflows", Category: "misconfiguration", Offline: true, OutputSource: "stdout", Args: []string{"--offline", "--no-config", "--strict-collection", "--format=sarif", "--", "{inputs}"}})
	add(c.Checks.Govulncheck, Extension{Name: "govulncheck", When: "go-modules", Category: "code", Offline: true, WorkingDirectory: "target", OutputSource: "stdout", RequiresTools: []string{"go"}, Args: []string{"-format=sarif", "-db", "{govulndb}", "./..."}})
	add(c.Checks.Gosec, Extension{Name: "gosec", When: "go-modules", Parser: "gosec-json", Category: "code", Offline: true, WorkingDirectory: "target", OutputSource: "file", RequiresTools: []string{"go"}, Args: []string{"-conf", "{native_config}", "-fmt=json", "-out", "{output}", "-no-fail", "./..."}})
	// Replacement is explicit and order-preserving; duplicates in custom input
	// are retained so Validate rejects them rather than silently picking one.
	seen := map[string]bool{}
	for _, e := range c.Extensions {
		if RemovedScannerExtension(e) {
			continue
		}
		// Older Go extension examples omitted the applicability selector. Keep
		// their command/parser/required settings but do not run them on non-Go
		// inputs. An explicitly supplied selector remains authoritative.
		if e.When == "" && (e.Name == "govulncheck" || e.Name == "gosec" || e.Tool == "govulncheck" || e.Tool == "gosec") {
			e.When = "go-modules"
		}
		replaced := false
		if !seen[e.Name] {
			for i := range out {
				if out[i].Name == e.Name {
					out[i] = e
					replaced = true
					break
				}
			}
		}
		if !replaced {
			out = append(out, e)
		}
		seen[e.Name] = true
	}
	return out
}
func containsTool(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}
