package scan

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"sekscan/internal/model"
)

type Inventory struct {
	Components []model.Component
	Native     map[string]string
}

func NewInventory() *Inventory {
	return &Inventory{Components: []model.Component{}, Native: map[string]string{}}
}
func classify(eco string) (string, string) {
	switch strings.ToLower(eco) {
	case "deb", "dpkg", "rpm", "apk", "alpm", "portage", "linux-kernel", "alpine", "debian", "ubuntu", "redhat", "centos", "rocky", "suse", "photon", "wolfi", "chainguard", "amazon":
		return "operating-system", "OS package-manager provenance"
	case "npm", "yarn", "pnpm", "javascript", "go-module", "golang", "gobinary", "gomod", "rust-crate", "cargo", "rust", "python", "python-pkg", "python-package", "pypi", "pip", "pipenv", "poetry", "uv", "egg", "wheel", "gem", "ruby", "bundler", "java-archive", "java", "jar", "maven", "gradle", "dotnet", "nuget", "dotnet-deps", "dart-pub", "pub", "composer", "php-composer", "php", "swift", "cocoapods", "hex", "elixir", "conan", "cran", "r-package", "cpan", "perl":
		return "application", "Language package-manager provenance (review unusual ownership cases)"
	default:
		return "unknown", "No reliable application/OS ownership classification"
	}
}
func ecosystem(s string) string {
	switch strings.ToLower(s) {
	case "go-module", "gobinary", "gomod":
		return "golang"
	case "python-pkg", "python-package", "pypi", "pip", "pipenv", "poetry", "uv", "egg", "wheel":
		return "python"
	case "yarn", "pnpm", "javascript":
		return "npm"
	case "java-archive", "jar", "maven", "gradle":
		return "java"
	case "rust-crate", "cargo":
		return "rust"
	case "dotnet-deps", "nuget":
		return "dotnet"
	case "bundler", "gem":
		return "ruby"
	case "php-composer", "composer":
		return "php"
	default:
		return strings.ToLower(s)
	}
}
func normalizeLocations(locations []model.Location) []model.Location {
	seen := map[string]bool{}
	out := []model.Location{}
	for _, l := range locations {
		l.Path = filepath.ToSlash(l.Path)
		if l.Path == "" {
			continue
		}
		if l.Line < 0 {
			l.Line = 0
		}
		key := fmt.Sprintf("%s:%d", l.Path, l.Line)
		if !seen[key] {
			seen[key] = true
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Line < out[j].Line
		}
		return out[i].Path < out[j].Path
	})
	return out
}
func (in *Inventory) ByID(id string) *model.Component {
	for i := range in.Components {
		if in.Components[i].ID == id {
			return &in.Components[i]
		}
	}
	return nil
}
func (in *Inventory) Add(c model.Component, native string) string {
	c.Ecosystem = ecosystem(c.Ecosystem)
	c.Locations = normalizeLocations(c.Locations)
	if c.Scope == "" {
		c.Scope, c.ScopeReason = classify(c.Ecosystem)
	}
	if c.Licenses == nil {
		c.Licenses = []model.LicenseEvidence{}
	}
	if native != "" {
		if id, ok := in.Native[native]; ok {
			return id
		}
	}
	candidates := []int{}
	for i, x := range in.Components {
		same := c.PURL != "" && x.PURL == c.PURL
		if c.PURL == "" || x.PURL == "" {
			same = c.Name == x.Name && c.Version == x.Version && c.Ecosystem == x.Ecosystem
		}
		if same && c.Version == x.Version {
			candidates = append(candidates, i)
		}
	}
	match := -1
	if len(candidates) == 1 {
		match = candidates[0]
	}
	if len(candidates) > 1 {
		for _, i := range candidates {
			for _, l := range c.Locations {
				for _, x := range in.Components[i].Locations {
					if l.Path == x.Path {
						if match >= 0 && match != i {
							match = -2
							break
						}
						match = i
					}
				}
			}
		}
	}
	if match >= 0 {
		x := &in.Components[match]
		x.Locations = normalizeLocations(append(x.Locations, c.Locations...))
		for _, l := range c.Licenses {
			x.Licenses = addLicense(x.Licenses, l)
		}
		if x.Scope == "unknown" && c.Scope != "unknown" {
			x.Scope = c.Scope
			x.ScopeReason = c.ScopeReason
		}
		if native != "" {
			in.Native[native] = x.ID
		}
		return x.ID
	}
	origin := ""
	for _, l := range c.Locations {
		origin += l.Path + "\x00"
	}
	c.ID = model.Hash(c.PURL, c.Name, c.Version, c.Ecosystem, origin)[:24]
	in.Components = append(in.Components, c)
	if native != "" {
		in.Native[native] = c.ID
	}
	return c.ID
}
func addLicense(list []model.LicenseEvidence, e model.LicenseEvidence) []model.LicenseEvidence {
	e.Expression = strings.TrimSpace(e.Expression)
	if e.Expression == "" {
		return list
	}
	for _, x := range list {
		if x.Expression == e.Expression && x.Source == e.Source && x.Kind == e.Kind {
			return list
		}
	}
	return append(list, e)
}
func ParseSyft(b []byte, in *Inventory) (string, error) {
	var doc struct {
		Artifacts json.RawMessage `json:"artifacts"`
		Source    struct {
			ID       string `json:"id"`
			Metadata struct {
				ImageID     string   `json:"imageID"`
				RepoDigests []string `json:"repoDigests"`
			} `json:"metadata"`
		} `json:"source"`
	}
	if e := json.Unmarshal(b, &doc); e != nil {
		return "", fmt.Errorf("invalid Syft JSON: %w", e)
	}
	if len(doc.Artifacts) == 0 || string(doc.Artifacts) == "null" {
		return "", fmt.Errorf("unrecognized Syft schema: artifacts array missing")
	}
	var artifacts []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Type      string `json:"type"`
		PURL      string `json:"purl"`
		Locations []struct {
			Path       string `json:"path"`
			AccessPath string `json:"accessPath"`
		} `json:"locations"`
		Licenses []json.RawMessage `json:"licenses"`
	}
	if e := json.Unmarshal(doc.Artifacts, &artifacts); e != nil {
		return "", e
	}
	for _, a := range artifacts {
		if a.Name == "" {
			return "", fmt.Errorf("Syft artifact missing name")
		}
		scope, reason := classify(a.Type)
		c := model.Component{Name: a.Name, Version: a.Version, Ecosystem: a.Type, PURL: a.PURL, Scope: scope, ScopeReason: reason}
		for _, l := range a.Locations {
			p := l.Path
			if p == "" {
				p = l.AccessPath
			}
			c.Locations = append(c.Locations, model.Location{Path: p})
		}
		for _, raw := range a.Licenses {
			var value string
			if json.Unmarshal(raw, &value) == nil {
				c.Licenses = addLicense(c.Licenses, model.LicenseEvidence{Expression: value, Source: "syft", Kind: "metadata"})
				continue
			}
			var l struct {
				Value     string           `json:"value"`
				SPDX      string           `json:"spdxExpression"`
				Type      string           `json:"type"`
				Locations []model.Location `json:"locations"`
			}
			if e := json.Unmarshal(raw, &l); e != nil {
				return "", fmt.Errorf("invalid Syft license entry")
			}
			value = l.SPDX
			if value == "" {
				value = l.Value
			}
			kind := "metadata"
			if len(l.Locations) > 0 {
				kind = "detected"
			}
			c.Licenses = addLicense(c.Licenses, model.LicenseEvidence{Expression: value, Source: "syft", Kind: kind, Locations: l.Locations})
		}
		in.Add(c, a.ID)
	}
	id := doc.Source.Metadata.ImageID
	if len(doc.Source.Metadata.RepoDigests) > 0 {
		id = doc.Source.Metadata.RepoDigests[0]
	}
	return id, nil
}
func findingForComponent(in *Inventory, id string, f model.Finding) model.Finding {
	if c := in.ByID(id); c != nil {
		f.ComponentID = id
		f.Package = c.Name
		f.Version = c.Version
		f.Ecosystem = c.Ecosystem
		f.Scope = c.Scope
		f.Locations = append(f.Locations, c.Locations...)
	}
	f.Locations = normalizeLocations(f.Locations)
	f.Severity = model.NormalizeSeverity(f.Severity)
	return f
}
func ParseGrype(b []byte, in *Inventory) ([]model.Finding, json.RawMessage, error) {
	var doc struct {
		Matches    json.RawMessage `json:"matches"`
		Descriptor struct {
			DB json.RawMessage `json:"db"`
		} `json:"descriptor"`
	}
	if e := json.Unmarshal(b, &doc); e != nil {
		return nil, nil, fmt.Errorf("invalid Grype JSON: %w", e)
	}
	if len(doc.Matches) == 0 || string(doc.Matches) == "null" {
		return nil, nil, fmt.Errorf("unrecognized Grype schema: matches array missing")
	}
	type vuln struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Namespace   string `json:"namespace"`
		DataSource  string `json:"dataSource"`
		Description string `json:"description"`
		Fix         struct {
			Versions []string `json:"versions"`
		} `json:"fix"`
	}
	var matches []struct {
		Vulnerability vuln   `json:"vulnerability"`
		Related       []vuln `json:"relatedVulnerabilities"`
		Artifact      struct {
			ID        string           `json:"id"`
			Name      string           `json:"name"`
			Version   string           `json:"version"`
			Type      string           `json:"type"`
			PURL      string           `json:"purl"`
			Locations []model.Location `json:"locations"`
		} `json:"artifact"`
	}
	if e := json.Unmarshal(doc.Matches, &matches); e != nil {
		return nil, nil, e
	}
	out := []model.Finding{}
	for _, m := range matches {
		if m.Vulnerability.ID == "" || m.Artifact.Name == "" {
			return nil, nil, fmt.Errorf("incomplete Grype finding")
		}
		id := in.Native[m.Artifact.ID]
		if id == "" {
			id = in.Add(model.Component{Name: m.Artifact.Name, Version: m.Artifact.Version, Ecosystem: m.Artifact.Type, PURL: m.Artifact.PURL, Locations: m.Artifact.Locations}, m.Artifact.ID)
		}
		v := m.Vulnerability
		aliases := []string{v.ID}
		for _, r := range m.Related {
			aliases = append(aliases, r.ID)
		}
		f := model.Finding{Category: "vulnerability", RuleID: v.ID, Aliases: model.Unique(aliases), Severity: v.Severity, Title: v.ID + " in " + m.Artifact.Name, Description: v.Description, FixedVersions: model.Unique(v.Fix.Versions), Observations: []model.Observation{{Engine: "grype", Advisory: v.ID, Severity: model.NormalizeSeverity(v.Severity), SeveritySource: v.Namespace, FixedVersions: v.Fix.Versions, URL: v.DataSource}}}
		out = append(out, findingForComponent(in, id, f))
	}
	return out, doc.Descriptor.DB, nil
}
func ParseTrivy(b []byte, in *Inventory) ([]model.Finding, error) {
	var doc struct {
		SchemaVersion int `json:"SchemaVersion"`
		Results       []struct {
			Target   string `json:"Target"`
			Class    string `json:"Class"`
			Type     string `json:"Type"`
			Packages []struct {
				ID         string   `json:"ID"`
				Name       string   `json:"Name"`
				Version    string   `json:"Version"`
				Licenses   []string `json:"Licenses"`
				Identifier struct {
					PURL string `json:"PURL"`
				} `json:"Identifier"`
			} `json:"Packages"`
			Vulnerabilities []struct {
				ID             string `json:"VulnerabilityID"`
				PkgName        string `json:"PkgName"`
				PkgID          string `json:"PkgID"`
				Version        string `json:"InstalledVersion"`
				Fixed          string `json:"FixedVersion"`
				Severity       string `json:"Severity"`
				SeveritySource string `json:"SeveritySource"`
				Title          string `json:"Title"`
				Description    string `json:"Description"`
				URL            string `json:"PrimaryURL"`
				Identifier     struct {
					PURL string `json:"PURL"`
				} `json:"PkgIdentifier"`
			} `json:"Vulnerabilities"`
			Secrets []struct {
				RuleID    string `json:"RuleID"`
				Category  string `json:"Category"`
				Severity  string `json:"Severity"`
				Title     string `json:"Title"`
				StartLine int    `json:"StartLine"`
			} `json:"Secrets"`
			Misconfigurations []struct {
				ID          string `json:"ID"`
				AVDID       string `json:"AVDID"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
				Severity    string `json:"Severity"`
				Status      string `json:"Status"`
				Resolution  string `json:"Resolution"`
				URL         string `json:"PrimaryURL"`
				Cause       struct {
					StartLine int `json:"StartLine"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
			Licenses []struct {
				Name       string  `json:"Name"`
				PkgName    string  `json:"PkgName"`
				FilePath   string  `json:"FilePath"`
				Confidence float64 `json:"Confidence"`
			} `json:"Licenses"`
		} `json:"Results"`
	}
	if e := json.Unmarshal(b, &doc); e != nil {
		return nil, fmt.Errorf("invalid Trivy JSON: %w", e)
	}
	if doc.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported Trivy schema version %d", doc.SchemaVersion)
	}
	out := []model.Finding{}
	for _, r := range doc.Results {
		scope, reason := classify(r.Type)
		if r.Class == "os-pkgs" {
			scope = "operating-system"
			reason = "Trivy OS package classification"
		}
		if r.Class == "lang-pkgs" {
			scope = "application"
			reason = "Trivy language package classification"
		}
		packageIDs := map[string][]string{}
		for _, p := range r.Packages {
			c := model.Component{Name: p.Name, Version: p.Version, Ecosystem: r.Type, PURL: p.Identifier.PURL, Scope: scope, ScopeReason: reason, Locations: []model.Location{{Path: r.Target}}}
			for _, l := range p.Licenses {
				c.Licenses = addLicense(c.Licenses, model.LicenseEvidence{Expression: l, Source: "trivy", Kind: "metadata"})
			}
			id := in.Add(c, "")
			packageIDs[p.Name] = append(packageIDs[p.Name], id)
		}
		for _, v := range r.Vulnerabilities {
			if v.ID == "" || v.PkgName == "" {
				return nil, fmt.Errorf("incomplete Trivy vulnerability")
			}
			id := in.Add(model.Component{Name: v.PkgName, Version: v.Version, Ecosystem: r.Type, PURL: v.Identifier.PURL, Scope: scope, ScopeReason: reason, Locations: []model.Location{{Path: r.Target}}}, "")
			fixed := []string{}
			for _, s := range strings.Split(v.Fixed, ",") {
				if strings.TrimSpace(s) != "" {
					fixed = append(fixed, strings.TrimSpace(s))
				}
			}
			title := v.Title
			if title == "" {
				title = v.ID + " in " + v.PkgName
			}
			f := model.Finding{Category: "vulnerability", RuleID: v.ID, Aliases: []string{v.ID}, Severity: v.Severity, Title: title, Description: v.Description, FixedVersions: fixed, Observations: []model.Observation{{Engine: "trivy", Advisory: v.ID, Severity: model.NormalizeSeverity(v.Severity), SeveritySource: v.SeveritySource, FixedVersions: fixed, URL: v.URL}}}
			out = append(out, findingForComponent(in, id, f))
		}
		for _, s := range r.Secrets {
			if s.RuleID == "" {
				return nil, fmt.Errorf("Trivy secret missing rule ID")
			}
			// Deliberately do not deserialize Match, Code, or source snippets.
			out = append(out, model.Finding{Category: "secret", RuleID: s.RuleID, Scope: "application", Severity: model.NormalizeSeverity(s.Severity), Title: s.Title, Description: "Secret detected. Matched value and source code are not retained.", Locations: []model.Location{{Path: r.Target, Line: s.StartLine}}, Observations: []model.Observation{{Engine: "trivy", Severity: model.NormalizeSeverity(s.Severity)}}})
		}
		for _, m := range r.Misconfigurations {
			if m.Status != "" && strings.ToUpper(m.Status) != "FAIL" {
				continue
			}
			rule := m.AVDID
			if rule == "" {
				rule = m.ID
			}
			if rule == "" {
				return nil, fmt.Errorf("Trivy misconfiguration missing ID")
			}
			out = append(out, model.Finding{Category: "misconfiguration", RuleID: rule, Scope: "application", Severity: model.NormalizeSeverity(m.Severity), Title: m.Title, Description: m.Description + "\nRemediation: " + m.Resolution, Locations: []model.Location{{Path: r.Target, Line: m.Cause.StartLine}}, Observations: []model.Observation{{Engine: "trivy", Severity: model.NormalizeSeverity(m.Severity), URL: m.URL}}})
		}
		for _, l := range r.Licenses {
			ids := packageIDs[l.PkgName]
			if len(ids) == 0 && l.PkgName != "" {
				for _, c := range in.Components {
					if c.Name == l.PkgName && c.Ecosystem == ecosystem(r.Type) {
						ids = append(ids, c.ID)
					}
				}
			}
			if len(ids) == 1 {
				c := in.ByID(ids[0])
				kind := "metadata"
				if l.FilePath != "" {
					kind = "detected"
				}
				c.Licenses = addLicense(c.Licenses, model.LicenseEvidence{Expression: l.Name, Source: "trivy", Kind: kind, Locations: []model.Location{{Path: l.FilePath}}})
			} else if l.FilePath != "" || r.Class == "license-file" {
				p := l.FilePath
				if p == "" {
					p = r.Target
				}
				in.Add(model.Component{Name: "license-file:" + p, Ecosystem: "license-file", Scope: "unknown", ScopeReason: "License text without proven package ownership; use a scope override", Locations: []model.Location{{Path: p}}, Licenses: []model.LicenseEvidence{{Expression: l.Name, Source: "trivy", Kind: "detected", Locations: []model.Location{{Path: p}}}}}, "")
			}
		}
	}
	return out, nil
}
func ParseGitleaks(b []byte) ([]model.Finding, error) {
	var entries []struct {
		RuleID      string `json:"RuleID"`
		Description string `json:"Description"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("Gitleaks report is empty")
	}
	if e := json.Unmarshal(b, &entries); e != nil {
		return nil, e
	}
	out := []model.Finding{}
	for _, s := range entries {
		if s.RuleID == "" {
			return nil, fmt.Errorf("Gitleaks finding missing rule ID")
		}
		out = append(out, model.Finding{Category: "secret", RuleID: s.RuleID, Scope: "application", Severity: "high", Title: s.Description, Description: "Secret detected. Matched value and source code are not retained.", Locations: []model.Location{{Path: s.File, Line: s.StartLine}}, Observations: []model.Observation{{Engine: "gitleaks", Severity: "high"}}})
	}
	return out, nil
}
func ParseSARIF(b []byte, engine string) ([]model.Finding, error) {
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Invocations []struct {
				Success       *bool `json:"executionSuccessful"`
				Notifications []struct {
					Level string `json:"level"`
				} `json:"toolExecutionNotifications"`
				Configuration []struct {
					Level string `json:"level"`
				} `json:"toolConfigurationNotifications"`
			} `json:"invocations"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if e := json.Unmarshal(b, &doc); e != nil {
		return nil, e
	}
	if doc.Version != "2.1.0" || len(doc.Runs) == 0 {
		return nil, fmt.Errorf("extension must return SARIF 2.1.0 with at least one run")
	}
	out := []model.Finding{}
	for _, r := range doc.Runs {
		for _, inv := range r.Invocations {
			for _, notice := range append(inv.Notifications, inv.Configuration...) {
				if notice.Level == "error" {
					return nil, fmt.Errorf("SARIF reports an execution/configuration error")
				}
			}
			if inv.Success != nil && !*inv.Success {
				return nil, fmt.Errorf("SARIF reports unsuccessful scanner execution")
			}
		}
		for _, s := range r.Results {
			if s.RuleID == "" {
				return nil, fmt.Errorf("SARIF result missing ruleId")
			}
			f := model.Finding{Category: "code", RuleID: engine + ":" + s.RuleID, Scope: "application", Severity: model.NormalizeSeverity(s.Level), Title: s.Message.Text, Observations: []model.Observation{{Engine: engine, Severity: model.NormalizeSeverity(s.Level)}}}
			for _, l := range s.Locations {
				f.Locations = append(f.Locations, model.Location{Path: l.Physical.Artifact.URI, Line: l.Physical.Region.StartLine})
			}
			out = append(out, f)
		}
	}
	return out, nil
}
