package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/model"
)

func ApplyScopes(components []model.Component, overrides []config.ScopeOverride) {
	for i := range components {
		c := &components[i]
		for _, o := range overrides {
			if o.PURL != "" && o.PURL != c.PURL {
				continue
			}
			if o.Package != "" && o.Package != c.Name {
				continue
			}
			if o.PathPrefix != "" {
				match := false
				prefix := strings.TrimSuffix(strings.ReplaceAll(o.PathPrefix, "\\", "/"), "/")
				for _, l := range c.Locations {
					if l.Path == prefix || strings.HasPrefix(l.Path, prefix+"/") {
						match = true
					}
				}
				if !match {
					continue
				}
			}
			c.Scope = o.Scope
			c.ScopeReason = "Explicit scope override from selected configuration"
			break
		}
	}
}
func LicenseFindings(components []model.Component, p config.LicensePolicy) []model.Finding {
	findings := []model.Finding{}
	for i := range components {
		c := &components[i]
		if c.Scope == "operating-system" {
			c.LicenseDecision = "excluded"
			c.LicenseReason = "OS licenses are excluded from application license policy"
			continue
		}
		rule := "license-policy"
		decision := "pass"
		reason := "License expression satisfies configured policy"
		values := map[string]string{}
		invalid := false
		for _, e := range c.Licenses {
			d, canonical, err := EvaluateExpression(e.Expression, p)
			if err != nil {
				invalid = true
			}
			values[canonical] = d
		}
		switch {
		case c.Scope == "unknown":
			rule = "license-scope-unknown"
			decision = "review"
			reason = "Package ownership is unknown; confirm application scope before accepting license evidence"
		case len(c.Licenses) == 0:
			rule = "license-unknown"
			decision = p.Unknown
			reason = "No usable license evidence was discovered"
		case invalid:
			rule = "license-expression-invalid"
			decision = "review"
			reason = "License evidence is not a supported SPDX expression; review the original evidence"
		case len(values) > 1:
			rule = "license-evidence-ambiguous"
			decision = p.Conflict
			reason = "Multiple license expressions were reported; their AND/OR relationship is not established"
			kinds := map[string]bool{}
			for _, e := range c.Licenses {
				kinds[e.Kind] = true
			}
			if kinds["detected"] && (kinds["metadata"] || kinds["declared"]) {
				rule = "license-evidence-conflict"
				reason = "Detected license text and package metadata contain different expressions; human review required"
			}
		default:
			for _, v := range values {
				decision = v
			}
			if decision != "pass" {
				reason = "License expression does not satisfy the configured allow/deny policy without further review"
			}
		}
		c.LicenseDecision = decision
		c.LicenseReason = reason
		if decision == "pass" {
			continue
		}
		severity := "medium"
		if decision == "fail" {
			severity = "high"
		}
		observations := []model.Observation{}
		seen := map[string]bool{}
		for _, l := range c.Licenses {
			if !seen[l.Source] {
				seen[l.Source] = true
				observations = append(observations, model.Observation{Engine: l.Source, Severity: severity})
			}
		}
		findings = append(findings, model.Finding{Category: "license", RuleID: rule, ComponentID: c.ID, Package: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, Scope: c.Scope, Severity: severity, Title: rule + ": " + c.Name, Description: reason, Locations: c.Locations, Observations: observations, Decision: decision, DecisionReason: reason})
	}
	return findings
}
func componentKey(f model.Finding, components map[string]model.Component) string {
	if c, ok := components[f.ComponentID]; ok {
		if c.PURL != "" {
			return c.PURL + "|" + c.Version + "|" + c.Scope
		}
		return c.Ecosystem + "|" + c.Name + "|" + c.Version + "|" + c.Scope
	}
	return f.Ecosystem + "|" + f.Package + "|" + f.Version + "|" + f.Scope
}
func Deduplicate(findings []model.Finding, components []model.Component) []model.Finding {
	byComponent := map[string]model.Component{}
	for _, c := range components {
		byComponent[c.ID] = c
	}
	// Union-find joins only verified aliases supplied by a scanner for the same component.
	parent := make([]int, len(findings))
	for i := range parent {
		parent[i] = i
	}
	var root func(int) int
	root = func(i int) int {
		if parent[i] != i {
			parent[i] = root(parent[i])
		}
		return parent[i]
	}
	seen := map[string]int{}
	for i, f := range findings {
		aliases := append([]string{f.RuleID}, f.Aliases...)
		context := f.Category + "|" + componentKey(f, byComponent)
		if f.Category != "vulnerability" {
			for _, l := range f.Locations {
				context += fmt.Sprintf("|%s:%d", l.Path, l.Line)
			}
		}
		for _, alias := range aliases {
			key := context + "|" + alias
			if j, ok := seen[key]; ok {
				parent[root(i)] = root(j)
			} else {
				seen[key] = i
			}
		}
	}
	groups := map[int]*model.Finding{}
	order := []int{}
	for i, f := range findings {
		k := root(i)
		existing, ok := groups[k]
		if !ok {
			copy := f
			copy.Severity = model.NormalizeSeverity(copy.Severity)
			copy.Aliases = model.Unique(append(copy.Aliases, copy.RuleID))
			groups[k] = &copy
			order = append(order, k)
			continue
		}
		existing.Aliases = model.Unique(append(existing.Aliases, append(f.Aliases, f.RuleID)...))
		existing.FixedVersions = model.Unique(append(existing.FixedVersions, f.FixedVersions...))
		existing.Observations = append(existing.Observations, f.Observations...)
		if model.SeverityRank(f.Severity) > model.SeverityRank(existing.Severity) {
			existing.Severity = model.NormalizeSeverity(f.Severity)
		}
	}
	out := []model.Finding{}
	for _, k := range order {
		f := *groups[k]
		if f.Category == "vulnerability" {
			for _, a := range f.Aliases {
				if strings.HasPrefix(a, "CVE-") {
					f.RuleID = a
					break
				}
			}
		}
		parts := []string{f.Category, f.RuleID, componentKey(f, byComponent)}
		if f.Category != "vulnerability" {
			for _, l := range f.Locations {
				parts = append(parts, fmt.Sprintf("%s:%d", l.Path, l.Line))
			}
		}
		f.Fingerprint = model.Hash(parts...)
		f.ID = f.Fingerprint[:24]
		f.Baseline = "new"
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := model.SeverityRank(out[i].Severity), model.SeverityRank(out[j].Severity)
		if a == b {
			return out[i].Fingerprint < out[j].Fingerprint
		}
		return a > b
	})
	return out
}
func Apply(r *model.Report, c config.Config, baseline *model.Report, now time.Time) {
	old := map[string]model.Finding{}
	if baseline != nil {
		for _, f := range baseline.Findings {
			old[f.Fingerprint] = f
		}
		if baseline.ConfigHash != r.ConfigHash {
			r.Warnings = append(r.Warnings, "Baseline configuration differs; policy changes can affect the comparison")
		}
		r.Warnings = append(r.Warnings, "Baseline compares reported findings, not re-scanned artifacts; advisory database changes can produce new findings")
	}
	present := map[string]bool{}
	for i := range r.Findings {
		f := &r.Findings[i]
		present[f.Fingerprint] = true
		if _, ok := old[f.Fingerprint]; ok {
			f.Baseline = "existing"
		} else {
			f.Baseline = "new"
		}
		if f.Category != "license" {
			f.Decision = "pass"
			f.DecisionReason = "Below configured failure threshold"
			inScope := true
			if f.Category == "vulnerability" {
				inScope = false
				for _, s := range c.Policy.VulnerabilityScopes {
					if s == f.Scope {
						inScope = true
					}
				}
			}
			switch {
			case !inScope:
				f.DecisionReason = "Excluded from configured vulnerability scopes"
			case f.Severity == "unknown":
				f.Decision = c.Policy.UnknownSeverity
				f.DecisionReason = "Scanner did not establish a severity"
			case c.Policy.FailAt != "none" && model.SeverityRank(f.Severity) >= model.SeverityRank(c.Policy.FailAt):
				f.Decision = "fail"
				f.DecisionReason = "Meets configured severity threshold"
			}
			if f.Category == "vulnerability" && c.Policy.RequireFix && len(f.FixedVersions) == 0 {
				f.Decision = "pass"
				f.DecisionReason = "Policy only blocks vulnerabilities with reported fixes"
			}
		}
		if c.Policy.OnlyNew && f.Baseline == "existing" {
			f.Decision = "pass"
			f.DecisionReason = "Existing baseline finding; only_new policy is enabled"
		}
		for _, ex := range c.Exceptions {
			expires, _ := time.Parse("2006-01-02", ex.Expires)
			expires = expires.Add(24 * time.Hour)
			if !now.Before(expires) {
				continue
			}
			match := ex.Fingerprint != "" && ex.Fingerprint == f.Fingerprint
			if ex.Fingerprint == "" && ex.Package == f.Package {
				if ex.RuleID == f.RuleID {
					match = true
				}
				for _, a := range f.Aliases {
					if a == ex.RuleID {
						match = true
					}
				}
			}
			if match {
				f.Decision = "accepted"
				f.DecisionReason = ex.Reason
				f.Exception = ex.ID
				break
			}
		}
	}
	for _, ex := range c.Exceptions {
		expires, _ := time.Parse("2006-01-02", ex.Expires)
		if !now.Before(expires.Add(24 * time.Hour)) {
			r.Warnings = append(r.Warnings, "Expired exception is not applied: "+ex.ID)
		}
	}
	r.Summarize(c.Policy.FailOnReview)
	r.Resolved = []model.Finding{}
	// A failed or disabled scanner must not make historical findings look fixed.
	completed := map[string]map[string]bool{}
	for _, e := range r.Engines {
		if e.Status != "completed" {
			continue
		}
		completed[e.Name] = map[string]bool{}
		for _, check := range e.Checks {
			switch check {
			case "vuln":
				check = "vulnerability"
			case "misconfig":
				check = "misconfiguration"
			}
			completed[e.Name][check] = true
		}
	}
	for fp, f := range old {
		if present[fp] {
			continue
		}
		verified := r.Complete && len(f.Observations) > 0
		for _, o := range f.Observations {
			if !completed[o.Engine][f.Category] {
				verified = false
			}
		}
		if verified {
			f.Baseline = "resolved"
			r.Resolved = append(r.Resolved, f)
		} else {
			r.Warnings = append(r.Warnings, "A baseline finding was not reverified: "+f.ID)
		}
	}
	sort.Slice(r.Resolved, func(i, j int) bool { return r.Resolved[i].ID < r.Resolved[j].ID })
	r.Summarize(c.Policy.FailOnReview)
}
