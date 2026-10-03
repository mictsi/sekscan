// Package config validates application settings and scanner definitions.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sekscan/internal/model"
)

type InstallRecipe struct {
	Repository string            `json:"repository"`
	Assets     map[string]string `json:"assets"` // OS/architecture -> release asset name template.
	Checksums  string            `json:"checksums"`
	Executable string            `json:"executable,omitempty"`
}
type Tool struct {
	CommandArgs  []string       `json:"command_args,omitempty"` // Prefix for a configured portable runtime.
	NativeConfig string         `json:"native_config,omitempty"`
	ExtraArgs    []string       `json:"extra_args,omitempty"`
	VersionArgs  []string       `json:"version_args,omitempty"`
	Install      *InstallRecipe `json:"install,omitempty"`
	Path         string         `json:"path,omitempty"`
	Version      string         `json:"version"`
	SHA256       string         `json:"sha256,omitempty"` // Optional independent archive pin.
}
type Checks struct {
	Hadolint             bool `json:"hadolint"`
	Zizmor               bool `json:"zizmor"`
	Govulncheck          bool `json:"govulncheck"`
	Gosec                bool `json:"gosec"`
	retiredSemgrep       bool // Decode-only migration marker; never serialized.
	Vulnerabilities      bool `json:"vulnerabilities"`
	Licenses             bool `json:"licenses"`
	Secrets              bool `json:"secrets"`
	Misconfigurations    bool `json:"misconfigurations"`
	TrivyVulnerabilities bool `json:"trivy_vulnerabilities"`
	Gitleaks             bool `json:"gitleaks"`
	Actionlint           bool `json:"actionlint"`
}
type LicensePolicy struct {
	Allow    []string `json:"allow"`
	Deny     []string `json:"deny"`
	Unlisted string   `json:"unlisted"`
	Unknown  string   `json:"unknown"`
	Conflict string   `json:"conflict"`
}
type Policy struct {
	FailAt              string        `json:"fail_at"`
	UnknownSeverity     string        `json:"unknown_severity"`
	FailOnReview        bool          `json:"fail_on_review"`
	OnlyNew             bool          `json:"only_new"`
	RequireFix          bool          `json:"require_fix"`
	VulnerabilityScopes []string      `json:"vulnerability_scopes"`
	Licenses            LicensePolicy `json:"licenses"`
}
type Exception struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	Package     string `json:"package,omitempty"`
	Reason      string `json:"reason"`
	Owner       string `json:"owner"`
	Expires     string `json:"expires"`
}
type ScopeOverride struct {
	PURL       string `json:"purl,omitempty"`
	Package    string `json:"package,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
	Scope      string `json:"scope"`
}
type Extension struct {
	When             string   `json:"when,omitempty"`   // go-modules, workflows, dockerfiles, source, or all.
	Parser           string   `json:"parser,omitempty"` // sarif, hadolint-json, gosec-json.
	Category         string   `json:"category,omitempty"`
	Offline          bool     `json:"offline,omitempty"` // Trusted assertion; not a network sandbox.
	RequiresTools    []string `json:"requires_tools,omitempty"`
	RedactMessages   bool     `json:"redact_messages,omitempty"`
	Builtin          bool     `json:"-"`
	Tool             string   `json:"tool,omitempty"`
	NativeConfig     string   `json:"native_config,omitempty"`
	WorkingDirectory string   `json:"working_directory,omitempty"` // isolated (default) or target directory
	OutputSource     string   `json:"output_source,omitempty"`     // file or stdout; parser is SARIF 2.1.0.
	Timeout          string   `json:"timeout,omitempty"`
	Name             string   `json:"name"`
	Executable       string   `json:"executable"`
	Args             []string `json:"args"`
	VersionArgs      []string `json:"version_args,omitempty"`
	Targets          []string `json:"targets"`
	SuccessCodes     []int    `json:"success_codes"`
	Required         bool     `json:"required"`
	// The extension writes SARIF to {output}; no shell interpolation is performed.
}
type Paths struct {
	Bin   string `json:"bin"`
	Cache string `json:"cache"`
	Logs  string `json:"logs"`
	Data  string `json:"data"`
}
type Storage struct {
	Enabled          bool   `json:"enabled"`
	Driver           string `json:"driver"`
	Path             string `json:"path,omitempty"`
	DSNEnv           string `json:"dsn_env,omitempty"`
	Required         bool   `json:"required"`
	AutoMigrate      bool   `json:"auto_migrate"`
	AllowInsecureTLS bool   `json:"allow_insecure_tls"`
	Timeout          string `json:"timeout"`
	MaxOpenConns     int    `json:"max_open_conns"`
	StoreArtifacts   bool   `json:"store_artifacts"`
	MaxArtifactMB    int    `json:"max_artifact_mb"`
}
type Project struct {
	Namespace  string `json:"namespace"`
	Key        string `json:"key,omitempty"`
	Name       string `json:"name,omitempty"`
	Repository string `json:"repository,omitempty"`
}
type Config struct {
	MigrationWarnings []string        `json:"-"`
	Portable          bool            `json:"portable"`
	DiagnosticStderr  bool            `json:"diagnostic_stderr"`
	WorkspaceRoot     string          `json:"-"`
	Paths             Paths           `json:"paths"`
	Storage           Storage         `json:"storage"`
	Project           Project         `json:"project"`
	Version           int             `json:"version"`
	Tools             map[string]Tool `json:"tools"`
	Checks            Checks          `json:"checks"`
	Policy            Policy          `json:"policy"`
	Exceptions        []Exception     `json:"exceptions"`
	ScopeOverrides    []ScopeOverride `json:"scope_overrides"`
	Exclude           []string        `json:"exclude"`
	Timeout           string          `json:"timeout"`
	MaxOutputMB       int             `json:"max_output_mb"`
	MaxDBAge          string          `json:"max_db_age"`
	LicenseFull       bool            `json:"license_full"`
	Extensions        []Extension     `json:"extensions"`
}

func Default() Config {
	return Config{
		Version: 2, Portable: true,
		Paths:   Paths{Bin: "bin", Cache: "cache", Logs: "logs", Data: "data"},
		Storage: Storage{Enabled: true, Driver: "sqlite", Path: "data/sekscan.db", DSNEnv: "SEKSCAN_DB_DSN", Required: true, AutoMigrate: true, Timeout: "30s", MaxOpenConns: 4, StoreArtifacts: true, MaxArtifactMB: 64},
		Project: Project{Namespace: "default"},
		Tools:   DefaultTools(),
		Checks:  DefaultChecks(),
		Policy: Policy{FailAt: "high", UnknownSeverity: "review", FailOnReview: true, VulnerabilityScopes: []string{"application", "operating-system", "unknown"}, Licenses: LicensePolicy{
			Allow: []string{"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "CC0-1.0"}, Deny: []string{}, Unlisted: "review", Unknown: "review", Conflict: "review",
		}},
		Exceptions: []Exception{}, ScopeOverrides: []ScopeOverride{}, Exclude: []string{".git", "security-report"}, Timeout: "15m", MaxOutputMB: 256, MaxDBAge: "120h", Extensions: []Extension{},
	}
}
func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, err
		}
		if len(b) > 4<<20 {
			return c, fmt.Errorf("configuration exceeds 4 MiB")
		}
		if trimmed := bytes.TrimSpace(b); len(trimmed) == 0 || trimmed[0] != '{' {
			return c, fmt.Errorf("configuration must be a JSON object")
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err = d.Decode(&c); err != nil {
			return c, fmt.Errorf("configuration: %w", err)
		}
		if err = d.Decode(new(any)); err != io.EOF {
			return c, fmt.Errorf("configuration must contain one JSON object")
		}
		c = c.WithoutSemgrep()
		// Shared schemas are administrator-managed unless migration is explicitly requested.
		var explicit struct {
			Storage struct {
				AutoMigrate *bool `json:"auto_migrate"`
			} `json:"storage"`
		}
		_ = json.Unmarshal(b, &explicit)
		if c.Storage.Driver != "sqlite" && explicit.Storage.AutoMigrate == nil {
			c.Storage.AutoMigrate = false
		}
		for n, t := range c.Tools {
			if t.Version == "" {
				t.Version = "latest"
				c.Tools[n] = t
			}
		}
		// Executables are resolved relative to the trusted config, not the scanned tree.
		root, _ := filepath.Abs(filepath.Dir(path))
		for n, t := range c.Tools {
			if t.NativeConfig != "" && !filepath.IsAbs(t.NativeConfig) {
				t.NativeConfig = filepath.Join(root, t.NativeConfig)
			}
			if t.Path != "" && !filepath.IsAbs(t.Path) {
				t.Path = filepath.Join(root, t.Path)
			}
			c.Tools[n] = t
		}
		for i := range c.Extensions {
			if p := c.Extensions[i].NativeConfig; p != "" && !filepath.IsAbs(p) {
				c.Extensions[i].NativeConfig = filepath.Join(root, p)
			}
			p := c.Extensions[i].Executable
			if strings.ContainsAny(p, "/\\") && !filepath.IsAbs(p) {
				c.Extensions[i].Executable = filepath.Join(root, p)
			}
		}
	}
	return c, c.Validate()
}
func (c Config) Hash() string {
	if c.WorkspaceRoot != "" {
		c = c.ForSave(c.WorkspaceRoot)
	}
	b, _ := json.Marshal(c)
	return model.Hash(string(b))
}

var safeName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var safeVersion = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

func ValidVersion(v string) bool { return v == "latest" || safeVersion.MatchString(v) }
func (c Config) Validate() error {
	if c.Version != 1 && c.Version != 2 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if model.SeverityRank(c.Policy.FailAt) == 0 && c.Policy.FailAt != "none" {
		return fmt.Errorf("policy.fail_at must be critical, high, medium, low, info, or none")
	}
	validDecision := func(s string) bool { return s == "pass" || s == "review" || s == "fail" }
	for _, s := range []string{c.Policy.Licenses.Unlisted, c.Policy.Licenses.Unknown, c.Policy.Licenses.Conflict, c.Policy.UnknownSeverity} {
		if !validDecision(s) {
			return fmt.Errorf("invalid policy decision %q", s)
		}
	}
	for _, s := range c.Policy.VulnerabilityScopes {
		if !validScope(s) {
			return fmt.Errorf("invalid scope %q", s)
		}
	}
	for _, p := range c.Exclude {
		clean := filepath.Clean(p)
		if p == "" || clean == "." || strings.ContainsAny(p, "*?[]\\") || filepath.IsAbs(p) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("exclusions must be target-relative paths without globs or backslashes: %q", p)
		}
	}
	if d, err := time.ParseDuration(c.Timeout); err != nil || d <= 0 {
		return fmt.Errorf("timeout must be a positive duration")
	}
	if d, err := time.ParseDuration(c.MaxDBAge); err != nil || d <= 0 {
		return fmt.Errorf("max_db_age must be a positive duration")
	}
	if c.MaxOutputMB < 1 || c.MaxOutputMB > 1024 {
		return fmt.Errorf("max_output_mb must be between 1 and 1024")
	}
	for n, t := range c.Tools {
		if !safeName.MatchString(n) {
			return fmt.Errorf("invalid tool name %q", n)
		}
		if err := validateTool(n, t); err != nil {
			return err
		}
		if !ValidVersion(t.Version) {
			return fmt.Errorf("invalid %s version %q", n, t.Version)
		}
		if t.SHA256 != "" && !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(t.SHA256) {
			return fmt.Errorf("invalid %s SHA256 pin", n)
		}
	}
	seen := map[string]bool{}
	for _, e := range c.Exceptions {
		if e.ID == "" || seen[e.ID] || e.Reason == "" || e.Owner == "" {
			return fmt.Errorf("exceptions require unique id, reason and owner")
		}
		seen[e.ID] = true
		if e.Fingerprint == "" && (e.RuleID == "" || e.Package == "") {
			return fmt.Errorf("exception %q needs a fingerprint or both rule_id and package", e.ID)
		}
		if _, err := time.Parse("2006-01-02", e.Expires); err != nil {
			return fmt.Errorf("exception %q needs expires in YYYY-MM-DD", e.ID)
		}
	}
	for _, s := range c.ScopeOverrides {
		if !validScope(s.Scope) || (s.PURL == "" && s.Package == "" && s.PathPrefix == "") {
			return fmt.Errorf("scope overrides need a selector and valid scope")
		}
	}
	seen = map[string]bool{"syft": true, "grype": true, "trivy": true, "gitleaks": true, "actionlint": true}
	for _, e := range c.EffectiveExtensions() {
		if !safeName.MatchString(e.Name) || seen[e.Name] || (e.Executable == "" && e.Tool == "") {
			return fmt.Errorf("extensions require unique safe names and an executable")
		}
		seen[e.Name] = true
		if e.Tool != "" {
			if _, ok := c.Tools[e.Tool]; !ok {
				return fmt.Errorf("extension %q references an undefined tool", e.Name)
			}
			if e.Executable != "" {
				return fmt.Errorf("extension must select tool or executable, not both")
			}
		}
		if e.When != "" && e.When != "all" && e.When != "source" && e.When != "go-modules" && e.When != "workflows" && e.When != "dockerfiles" {
			return fmt.Errorf("invalid extension when selector %q", e.When)
		}
		if e.Parser != "" && e.Parser != "sarif" && e.Parser != "hadolint-json" && e.Parser != "gosec-json" {
			return fmt.Errorf("invalid extension parser %q", e.Parser)
		}
		if e.Category != "" && e.Category != "code" && e.Category != "misconfiguration" && e.Category != "vulnerability" {
			return fmt.Errorf("invalid extension category")
		}
		for _, name := range e.RequiresTools {
			if _, ok := c.Tools[name]; !ok {
				return fmt.Errorf("extension %q requires undefined tool %q", e.Name, name)
			}
		}
		if e.Timeout != "" {
			if d, err := time.ParseDuration(e.Timeout); err != nil || d <= 0 {
				return fmt.Errorf("invalid extension timeout")
			}
		}
		if e.WorkingDirectory != "" && e.WorkingDirectory != "isolated" && e.WorkingDirectory != "target" {
			return fmt.Errorf("working_directory must be isolated or target")
		}
		if e.WorkingDirectory == "target" {
			for _, t := range e.Targets {
				if t != "dir" && t != "rootfs" {
					return fmt.Errorf("target working_directory requires directory targets")
				}
			}
		}
		if e.OutputSource != "" && e.OutputSource != "file" && e.OutputSource != "stdout" {
			return fmt.Errorf("output_source must be file or stdout")
		}
		if len(e.Targets) == 0 || len(e.SuccessCodes) == 0 {
			return fmt.Errorf("extension %q needs targets and success_codes", e.Name)
		}
		output := false
		for _, a := range e.Args {
			if strings.Contains(a, "{output}") {
				output = true
			}
		}
		if !output && e.OutputSource != "stdout" {
			return fmt.Errorf("extension %q must write SARIF to {output}", e.Name)
		}
		for _, t := range e.Targets {
			switch t {
			case "dir", "rootfs", "image", "docker-archive", "oci-archive", "oci-layout", "sbom":
			default:
				return fmt.Errorf("invalid extension target %q", t)
			}
		}
	}
	return c.validateWorkspace()
}
func validScope(s string) bool {
	return s == "application" || s == "operating-system" || s == "unknown"
}
func (c Config) RequiredTools() []string {
	out := []string{"syft"}
	if c.Checks.Vulnerabilities {
		out = append(out, "grype")
	}
	if c.Checks.Secrets || c.Checks.Misconfigurations || c.Checks.Licenses || c.Checks.TrivyVulnerabilities {
		out = append(out, "trivy")
	}
	if c.Checks.Gitleaks {
		out = append(out, "gitleaks")
	}
	if c.Checks.Actionlint {
		out = append(out, "actionlint")
	}
	for _, e := range c.EffectiveExtensions() {
		for _, n := range e.RequiresTools {
			if !containsTool(out, n) {
				out = append(out, n)
			}
		}
		if e.Tool != "" {
			found := false
			for _, n := range out {
				if n == e.Tool {
					found = true
				}
			}
			if !found {
				out = append(out, e.Tool)
			}
		}
	}
	return out
}
