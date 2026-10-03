// Package model defines the versioned, scanner-independent report format.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "1.0"

type Target struct {
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Identity string `json:"identity"`
}

type Location struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
}

type LicenseEvidence struct {
	Expression string     `json:"expression"`
	Source     string     `json:"source"`
	Kind       string     `json:"kind"` // declared, detected, or metadata
	Locations  []Location `json:"locations,omitempty"`
}

type Component struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Ecosystem       string            `json:"ecosystem"`
	PURL            string            `json:"purl,omitempty"`
	Scope           string            `json:"scope"`
	ScopeReason     string            `json:"scope_reason"`
	Locations       []Location        `json:"locations"`
	Licenses        []LicenseEvidence `json:"licenses"`
	LicenseDecision string            `json:"license_decision,omitempty"`
	LicenseReason   string            `json:"license_reason,omitempty"`
}

type Observation struct {
	Engine         string   `json:"engine"`
	Advisory       string   `json:"advisory,omitempty"`
	Severity       string   `json:"severity"`
	SeveritySource string   `json:"severity_source,omitempty"`
	FixedVersions  []string `json:"fixed_versions,omitempty"`
	URL            string   `json:"url,omitempty"`
}

type Finding struct {
	ID             string        `json:"id"`
	Fingerprint    string        `json:"fingerprint"`
	Category       string        `json:"category"`
	RuleID         string        `json:"rule_id"`
	Aliases        []string      `json:"aliases,omitempty"`
	ComponentID    string        `json:"component_id,omitempty"`
	Package        string        `json:"package,omitempty"`
	Version        string        `json:"version,omitempty"`
	Ecosystem      string        `json:"ecosystem,omitempty"`
	Scope          string        `json:"scope"`
	Severity       string        `json:"severity"`
	Title          string        `json:"title"`
	Description    string        `json:"description,omitempty"`
	Locations      []Location    `json:"locations"`
	FixedVersions  []string      `json:"fixed_versions,omitempty"`
	Observations   []Observation `json:"observations"`
	Decision       string        `json:"decision"` // pass, fail, review, accepted
	DecisionReason string        `json:"decision_reason,omitempty"`
	Baseline       string        `json:"baseline"` // new, existing, resolved, unverified
	Exception      string        `json:"exception,omitempty"`
}

type EngineRun struct {
	ConfigSHA256     string          `json:"native_config_sha256,omitempty"`
	Name             string          `json:"name"`
	Version          string          `json:"version,omitempty"`
	Executable       string          `json:"executable,omitempty"`
	ExecutableSHA256 string          `json:"executable_sha256,omitempty"`
	Status           string          `json:"status"` // completed, failed, skipped
	Required         bool            `json:"required"`
	Checks           []string        `json:"checks"`
	DurationMS       int64           `json:"duration_ms"`
	Error            string          `json:"error,omitempty"`
	Database         json.RawMessage `json:"database,omitempty"`
}

type Summary struct {
	Components int            `json:"components"`
	Findings   int            `json:"findings"`
	Failures   int            `json:"failures"`
	Reviews    int            `json:"reviews"`
	Accepted   int            `json:"accepted"`
	New        int            `json:"new"`
	Resolved   int            `json:"resolved"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
}

// Source records immutable acquisition provenance separately from the scanner's
// temporary filesystem input. Optional fields preserve compatibility with v1 reports.
type Source struct {
	Provider      string `json:"provider"`
	Repository    string `json:"repository"`
	RequestedRef  string `json:"requested_ref,omitempty"`
	ResolvedRef   string `json:"resolved_ref,omitempty"`
	Revision      string `json:"revision"`
	Subdir        string `json:"subdir,omitempty"`
	ArchiveSHA256 string `json:"archive_sha256,omitempty"`
}

type Report struct {
	Source        *Source     `json:"source,omitempty"`
	BatchID       string      `json:"batch_id,omitempty"`
	ProjectKey    string      `json:"project_key,omitempty"`
	Namespace     string      `json:"namespace,omitempty"`
	Branch        string      `json:"branch,omitempty"`
	SchemaVersion string      `json:"schema_version"`
	AppVersion    string      `json:"app_version"`
	ID            string      `json:"id"`
	StartedAt     time.Time   `json:"started_at"`
	FinishedAt    time.Time   `json:"finished_at"`
	Target        Target      `json:"target"`
	Revision      string      `json:"revision,omitempty"`
	ConfigHash    string      `json:"config_hash"`
	Complete      bool        `json:"complete"`
	Status        string      `json:"status"`
	ExitCode      int         `json:"exit_code"`
	FailOnReview  bool        `json:"fail_on_review"`
	Components    []Component `json:"components"`
	Findings      []Finding   `json:"findings"`
	Resolved      []Finding   `json:"resolved"`
	Engines       []EngineRun `json:"engines"`
	Warnings      []string    `json:"warnings"`
	Summary       Summary     `json:"summary"`
}

func Hash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func NormalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "moderate", "warning":
		return "medium"
	case "low":
		return "low"
	case "negligible", "info", "informational", "note", "none":
		return "info"
	default:
		return "unknown"
	}
}
func SeverityRank(s string) int {
	switch NormalizeSeverity(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
func Unique(values []string) []string {
	set := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if v != "" && !set[v] {
			set[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func (r *Report) Summarize(failReview bool) {
	r.FailOnReview = failReview
	r.Summary = Summary{Components: len(r.Components), Findings: len(r.Findings), Resolved: len(r.Resolved), BySeverity: map[string]int{}, ByCategory: map[string]int{}}
	r.Complete = true
	for _, e := range r.Engines {
		if e.Required && e.Status != "completed" {
			r.Complete = false
		}
	}
	for _, f := range r.Findings {
		r.Summary.BySeverity[f.Severity]++
		r.Summary.ByCategory[f.Category]++
		switch f.Decision {
		case "fail":
			r.Summary.Failures++
		case "review":
			r.Summary.Reviews++
		case "accepted":
			r.Summary.Accepted++
		}
		if f.Baseline == "new" {
			r.Summary.New++
		}
	}
	r.ExitCode = 0
	r.Status = "passed"
	if r.Summary.Failures > 0 || (failReview && r.Summary.Reviews > 0) {
		r.ExitCode = 1
		r.Status = "failed"
	}
	if !r.Complete {
		r.ExitCode = 2
		r.Status = "incomplete"
	}
}
