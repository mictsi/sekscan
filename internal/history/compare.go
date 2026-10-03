// Package history compares immutable report snapshots without rerunning policy or scanners.
package history

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"sekscan/internal/model"
)

type Run struct {
	ID        string        `json:"id"`
	StartedAt time.Time     `json:"started_at"`
	Status    string        `json:"status"`
	Complete  bool          `json:"complete"`
	Revision  string        `json:"revision"`
	Branch    string        `json:"branch"`
	Target    model.Target  `json:"target"`
	Summary   model.Summary `json:"summary"`
}
type Change struct {
	State       string         `json:"state"`
	Fingerprint string         `json:"fingerprint"`
	Category    string         `json:"category"`
	Severity    string         `json:"severity"`
	Rule        string         `json:"rule"`
	Package     string         `json:"package"`
	Before      *model.Finding `json:"before,omitempty"`
	After       *model.Finding `json:"after,omitempty"`
	Fields      []string       `json:"changed_fields"`
	Reason      string         `json:"reason,omitempty"`
}
type Counts struct {
	New        int `json:"new"`
	Resolved   int `json:"resolved"`
	Changed    int `json:"changed"`
	Unchanged  int `json:"unchanged"`
	Unverified int `json:"unverified"`
}
type ComponentChange struct {
	State   string           `json:"state"`
	Key     string           `json:"key"`
	Name    string           `json:"name"`
	Version string           `json:"version"`
	Before  *model.Component `json:"before,omitempty"`
	After   *model.Component `json:"after,omitempty"`
}
type Result struct {
	SchemaVersion   string            `json:"schema_version"`
	Namespace       string            `json:"namespace"`
	Project         string            `json:"project"`
	Base            Run               `json:"base"`
	Head            Run               `json:"head"`
	Comparable      bool              `json:"comparable"`
	Warnings        []string          `json:"warnings"`
	Counts          Counts            `json:"counts"`
	Changes         []Change          `json:"changes"`
	Components      []ComponentChange `json:"components"`
	ComponentCounts map[string]int    `json:"component_counts"`
	Delta           model.Summary     `json:"delta"`
}

func run(r *model.Report) Run {
	return Run{r.ID, r.StartedAt, r.Status, r.Complete, r.Revision, r.Branch, r.Target, r.Summary}
}
func checkName(s string) string {
	switch s {
	case "vuln", "vulnerabilities":
		return "vulnerability"
	case "misconfig", "misconfigurations":
		return "misconfiguration"
	case "licenses":
		return "license"
	case "secrets":
		return "secret"
	}
	return s
}
func checks(e model.EngineRun) []string {
	a := []string{}
	for _, v := range e.Checks {
		a = append(a, checkName(v))
	}
	return model.Unique(a)
}
func engineMap(r *model.Report) map[string]model.EngineRun {
	m := map[string]model.EngineRun{}
	for _, e := range r.Engines {
		m[e.Name] = e
	}
	return m
}
func sameJSON(a, b any) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(aa) == string(bb)
}
func (r *Result) compatibility(base, head *model.Report) {
	r.Comparable = base.Complete && head.Complete
	r.Warnings = []string{"Comparisons use stored snapshots, not rerun scanners. New findings may reflect new advisories, and 'no longer reported' does not prove a fix. Version changes create separate component/finding identities."}
	if !base.Complete || !head.Complete {
		r.Warnings = append(r.Warnings, "One or both runs are incomplete; missing findings are unverified, not resolved.")
	}
	if base.ConfigHash != head.ConfigHash {
		r.Comparable = false
		r.Warnings = append(r.Warnings, "Configuration hashes differ; policy, scope, exclusions, or workspace paths may differ. Missing findings are conservatively unverified.")
	}
	if base.Branch != head.Branch {
		r.Comparable = false
		r.Warnings = append(r.Warnings, "Branches differ; missing findings are unverified rather than treated as resolved.")
	}
	if base.Target.Value != head.Target.Value {
		r.Warnings = append(r.Warnings, "Target locations or references differ. Confirm these are revisions of the same application artifact, not unrelated scan inputs.")
	}
	if base.AppVersion != head.AppVersion {
		r.Comparable = false
		r.Warnings = append(r.Warnings, "sekscan versions differ; normalization may have changed. Missing findings are unverified.")
	}
	be, he := engineMap(base), engineMap(head)
	if len(be) != len(he) {
		r.Comparable = false
		r.Warnings = append(r.Warnings, "The scanner set changed; coverage is not identical.")
	}
	for _, name := range sortedKeys(be) {
		b := be[name]
		h, ok := he[name]
		if !ok {
			continue
		}
		if !reflect.DeepEqual(checks(b), checks(h)) || b.ConfigSHA256 != h.ConfigSHA256 || b.Required != h.Required {
			r.Comparable = false
			r.Warnings = append(r.Warnings, "Scanner checks or native configuration changed: "+name)
		}
		if b.Status != "completed" || h.Status != "completed" {
			r.Comparable = false
			r.Warnings = append(r.Warnings, "Scanner did not complete in both runs: "+name)
		}
		if b.Version != h.Version {
			r.Comparable = false
			r.Warnings = append(r.Warnings, "Scanner version changed: "+name+" ("+b.Version+" → "+h.Version+"); missing findings are unverified.")
		}
		if !sameJSON(b.Database, h.Database) {
			r.Warnings = append(r.Warnings, "Recorded scanner database metadata differs: "+name)
		}
	}
	for name := range be {
		if _, ok := he[name]; !ok {
			r.Comparable = false
		}
	}
}
func sortedKeys[V any](m map[string]V) []string {
	a := []string{}
	for k := range m {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}
func covers(r *model.Report, f model.Finding) bool {
	es := engineMap(r)
	if len(f.Observations) > 0 {
		for _, o := range f.Observations {
			e, ok := es[o.Engine]
			if !ok || e.Status != "completed" {
				return false
			}
		}
	}
	for _, e := range r.Engines {
		if e.Status != "completed" {
			continue
		}
		for _, c := range checks(e) {
			if c == f.Category || (f.Category == "license" && (c == "inventory" || c == "sbom")) {
				return true
			}
		}
	}
	return false
}
func findingFields(a, b model.Finding) []string {
	out := []string{}
	for _, v := range []struct{ name, a, b string }{{"severity", a.Severity, b.Severity}, {"decision", a.Decision, b.Decision}, {"decision_reason", a.DecisionReason, b.DecisionReason}, {"exception", a.Exception, b.Exception}, {"scope", a.Scope, b.Scope}, {"description", a.Description, b.Description}, {"title", a.Title, b.Title}} {
		if v.a != v.b {
			out = append(out, v.name)
		}
	}
	if !reflect.DeepEqual(model.Unique(a.FixedVersions), model.Unique(b.FixedVersions)) {
		out = append(out, "fixed_versions")
	}
	if !sameJSON(a.Locations, b.Locations) {
		out = append(out, "locations")
	}
	return out
}

// Compare rejects cross-project, cross-namespace, cross-target-kind, and reversed pairs.
// Missing findings only become resolved (no longer reported) with comparable coverage.
func Compare(base, head *model.Report) (*Result, error) {
	if base == nil || head == nil {
		return nil, fmt.Errorf("two reports are required")
	}
	if base.SchemaVersion != model.SchemaVersion || head.SchemaVersion != model.SchemaVersion {
		return nil, fmt.Errorf("comparison requires supported normalized report schemas")
	}
	if base.ProjectKey == "" || base.Namespace == "" || base.ProjectKey != head.ProjectKey || base.Namespace != head.Namespace {
		return nil, fmt.Errorf("comparison requires two runs from the same named project and namespace")
	}
	if base.ID == head.ID {
		return nil, fmt.Errorf("select two different runs")
	}
	if base.Target.Kind != head.Target.Kind {
		return nil, fmt.Errorf("cannot compare different target kinds; compare directory runs with directories or image runs with images")
	}
	if base.StartedAt.After(head.StartedAt) {
		return nil, fmt.Errorf("baseline must be the earlier run")
	}
	r := &Result{SchemaVersion: "1.0", Project: base.ProjectKey, Namespace: base.Namespace, Base: run(base), Head: run(head), Changes: []Change{}, Components: []ComponentChange{}, ComponentCounts: map[string]int{}}
	r.compatibility(base, head)
	bm, hm := map[string]model.Finding{}, map[string]model.Finding{}
	for _, f := range base.Findings {
		if f.Fingerprint == "" {
			return nil, fmt.Errorf("baseline contains a finding without a fingerprint")
		}
		if _, ok := bm[f.Fingerprint]; ok {
			return nil, fmt.Errorf("baseline has duplicate finding fingerprints")
		}
		bm[f.Fingerprint] = f
	}
	for _, f := range head.Findings {
		if f.Fingerprint == "" {
			return nil, fmt.Errorf("candidate contains a finding without a fingerprint")
		}
		if _, ok := hm[f.Fingerprint]; ok {
			return nil, fmt.Errorf("candidate has duplicate finding fingerprints")
		}
		hm[f.Fingerprint] = f
	}
	for _, fp := range sortedKeys(hm) {
		h := hm[fp]
		c := Change{State: "new", Fingerprint: fp, Category: h.Category, Severity: h.Severity, Rule: h.RuleID, Package: h.Package, After: &h, Fields: []string{}}
		if b, ok := bm[fp]; ok {
			c.Before = &b
			c.Fields = findingFields(b, h)
			c.State = "unchanged"
			if len(c.Fields) > 0 {
				c.State = "changed"
				r.Counts.Changed++
			} else {
				r.Counts.Unchanged++
			}
		} else {
			r.Counts.New++
		}
		r.Changes = append(r.Changes, c)
	}
	for _, fp := range sortedKeys(bm) {
		if _, ok := hm[fp]; ok {
			continue
		}
		b := bm[fp]
		c := Change{State: "unverified", Fingerprint: fp, Category: b.Category, Severity: b.Severity, Rule: b.RuleID, Package: b.Package, Before: &b, Fields: []string{}, Reason: "Coverage/configuration is not comparable; absence cannot establish resolution."}
		if r.Comparable && covers(head, b) {
			c.State = "resolved"
			c.Reason = "Not reported in the candidate under comparable recorded coverage; this is not proof of remediation."
			r.Counts.Resolved++
		} else {
			r.Counts.Unverified++
		}
		r.Changes = append(r.Changes, c)
	}
	order := map[string]int{"new": 0, "changed": 1, "unverified": 2, "resolved": 3, "unchanged": 4}
	sort.Slice(r.Changes, func(i, j int) bool {
		a, b := r.Changes[i], r.Changes[j]
		if order[a.State] != order[b.State] {
			return order[a.State] < order[b.State]
		}
		if a.Severity != b.Severity {
			return model.SeverityRank(a.Severity) > model.SeverityRank(b.Severity)
		}
		return a.Fingerprint < b.Fingerprint
	})
	r.Components = compareComponents(base.Components, head.Components, r.Comparable)
	for _, c := range r.Components {
		r.ComponentCounts[c.State]++
	}
	r.Delta = model.Summary{Components: head.Summary.Components - base.Summary.Components, Findings: head.Summary.Findings - base.Summary.Findings, Failures: head.Summary.Failures - base.Summary.Failures, Reviews: head.Summary.Reviews - base.Summary.Reviews, Accepted: head.Summary.Accepted - base.Summary.Accepted, BySeverity: map[string]int{}, ByCategory: map[string]int{}}
	for _, s := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		r.Delta.BySeverity[s] = head.Summary.BySeverity[s] - base.Summary.BySeverity[s]
	}
	for s, n := range head.Summary.ByCategory {
		r.Delta.ByCategory[s] = n - base.Summary.ByCategory[s]
	}
	for s, n := range base.Summary.ByCategory {
		if _, ok := r.Delta.ByCategory[s]; !ok {
			r.Delta.ByCategory[s] = -n
		}
	}
	return r, nil
}
func componentKey(c model.Component) string {
	return model.Hash(c.PURL, c.Name, c.Version, c.Ecosystem, c.Scope)
}
func componentEvidence(c model.Component) string {
	evidence := []string{c.LicenseDecision, c.LicenseReason}
	for _, l := range c.Licenses {
		evidence = append(evidence, l.Kind+"|"+l.Expression+"|"+l.Source)
	}
	sort.Strings(evidence)
	return strings.Join(evidence, "\x00")
}
func compareComponents(base, head []model.Component, comparable bool) []ComponentChange {
	bm, hm := map[string]model.Component{}, map[string]model.Component{}
	for _, c := range base {
		bm[componentKey(c)] = c
	}
	for _, c := range head {
		hm[componentKey(c)] = c
	}
	out := []ComponentChange{}
	for _, k := range sortedKeys(hm) {
		h := hm[k]
		c := ComponentChange{State: "added", Key: k, Name: h.Name, Version: h.Version, After: &h}
		if b, ok := bm[k]; ok {
			c.Before = &b
			c.State = "unchanged"
			if componentEvidence(b) != componentEvidence(h) {
				c.State = "changed"
			}
		}
		out = append(out, c)
	}
	for _, k := range sortedKeys(bm) {
		if _, ok := hm[k]; ok {
			continue
		}
		b := bm[k]
		state := "unverified"
		if comparable {
			state = "removed"
		}
		out = append(out, ComponentChange{State: state, Key: k, Name: b.Name, Version: b.Version, Before: &b})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.State != b.State {
			return a.State < b.State
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Key < b.Key
	})
	return out
}

// FilterChanges does not mutate the stored comparison. It is shared by CLI and HTTP paging.
func FilterChanges(all []Change, state, severity, category, query string) []Change {
	out := []Change{}
	q := strings.ToLower(query)
	for _, c := range all {
		if state != "" && state != c.State || severity != "" && severity != c.Severity || category != "" && category != c.Category {
			continue
		}
		if q != "" {
			raw, _ := json.Marshal(c)
			if !strings.Contains(strings.ToLower(string(raw)), q) {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
