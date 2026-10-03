// Package batch defines one manifest for local directories and GitHub sources.
package batch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sekscan/internal/config"
	"sekscan/internal/source"
)

const MaxProjects = 1000

// Settings are deliberately not executable definitions or security policy overrides.
// Pointer values distinguish an omitted setting from an explicit false.
type Settings struct {
	Hadolint    *bool `json:"hadolint,omitempty"`
	Zizmor      *bool `json:"zizmor,omitempty"`
	Govulncheck *bool `json:"govulncheck,omitempty"`
	Gosec       *bool `json:"gosec,omitempty"`

	Offline       *bool `json:"offline,omitempty"`
	InventoryOnly *bool `json:"inventory_only,omitempty"`
	Gitleaks      *bool `json:"gitleaks,omitempty"`
	Actionlint    *bool `json:"actionlint,omitempty"`
	TrivyVuln     *bool `json:"trivy_vuln,omitempty"`
	NoStore       *bool `json:"no_store,omitempty"`
}

type Entry struct {
	Project  string   `json:"project,omitempty"`
	Path     string   `json:"path,omitempty"`
	RepoURL  string   `json:"repo_url,omitempty"`
	Ref      string   `json:"ref,omitempty"`
	Subdir   string   `json:"subdir,omitempty"`
	Settings Settings `json:"settings,omitempty"`
}

type Manifest struct {
	Schema          string   `json:"$schema,omitempty"`
	Version         int      `json:"version"`
	Defaults        Settings `json:"defaults,omitempty"`
	ContinueOnError *bool    `json:"continue_on_error,omitempty"`
	Projects        []Entry  `json:"projects"`
}

// Job is the validated plan. Relative paths are resolved against the manifest,
// never the invocation's current directory or a downloaded repository.
type Job struct {
	Project  string   `json:"project"`
	Kind     string   `json:"kind"`
	Path     string   `json:"path,omitempty"`
	RepoURL  string   `json:"repo_url,omitempty"`
	Ref      string   `json:"ref,omitempty"`
	Subdir   string   `json:"subdir,omitempty"`
	Settings Settings `json:"settings"`
}

func Merge(a, b Settings) Settings {
	if b.Offline != nil {
		a.Offline = b.Offline
	}
	if b.InventoryOnly != nil {
		a.InventoryOnly = b.InventoryOnly
	}
	if b.Gitleaks != nil {
		a.Gitleaks = b.Gitleaks
	}
	if b.Actionlint != nil {
		a.Actionlint = b.Actionlint
	}
	if b.Hadolint != nil {
		a.Hadolint = b.Hadolint
	}
	if b.Zizmor != nil {
		a.Zizmor = b.Zizmor
	}
	if b.Govulncheck != nil {
		a.Govulncheck = b.Govulncheck
	}
	if b.Gosec != nil {
		a.Gosec = b.Gosec
	}
	if b.TrivyVuln != nil {
		a.TrivyVuln = b.TrivyVuln
	}
	if b.NoStore != nil {
		a.NoStore = b.NoStore
	}
	return a
}
func Enabled(v *bool) bool { return v != nil && *v }

func Load(path string) (Manifest, []Job, error) {
	var m Manifest
	f, err := os.Open(path)
	if err != nil {
		return m, nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return m, nil, err
	}
	if len(b) > 4<<20 {
		return m, nil, fmt.Errorf("batch manifest exceeds 4 MiB")
	}
	if err = RejectAmbiguousJSON(b); err != nil {
		return m, nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		return m, nil, fmt.Errorf("batch manifest: %w", err)
	}
	// Presence checks keep oneOf requirements identical to the published schema,
	// even for explicitly supplied empty strings.
	var raw struct {
		Projects []map[string]json.RawMessage `json:"projects"`
	}
	if err = json.Unmarshal(b, &raw); err != nil {
		return m, nil, err
	}
	for i, entry := range raw.Projects {
		_, local := entry["path"]
		_, remote := entry["repo_url"]
		if local == remote {
			return m, nil, fmt.Errorf("batch projects[%d]: specify exactly one of path or repo_url", i)
		}
		if local {
			for _, key := range []string{"ref", "subdir"} {
				if _, ok := entry[key]; ok {
					return m, nil, fmt.Errorf("batch projects[%d]: %s is only valid for repo_url", i, key)
				}
			}
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return m, nil, err
	}
	jobs, err := m.Plan(filepath.Dir(abs))
	return m, jobs, err
}

func (m Manifest) Plan(base string) ([]Job, error) {
	if m.Version != 1 {
		return nil, fmt.Errorf("batch version must be 1")
	}
	if len(m.Projects) < 1 || len(m.Projects) > MaxProjects {
		return nil, fmt.Errorf("batch projects must contain 1..%d entries", MaxProjects)
	}
	jobs := make([]Job, 0, len(m.Projects))
	identities := map[string]bool{}
	for i, e := range m.Projects {
		fail := func(err error) ([]Job, error) { return nil, fmt.Errorf("batch projects[%d]: %w", i, err) }
		if (e.Path == "") == (e.RepoURL == "") {
			return fail(fmt.Errorf("specify exactly one of path or repo_url"))
		}
		j := Job{Project: e.Project, Settings: Merge(m.Defaults, e.Settings)}
		if e.Path != "" {
			if e.Ref != "" || e.Subdir != "" {
				return fail(fmt.Errorf("ref and subdir are only valid for repo_url"))
			}
			if strings.ContainsRune(e.Path, 0) {
				return fail(fmt.Errorf("path contains a NUL byte"))
			}
			j.Kind = "directory"
			j.Path = e.Path
			if !filepath.IsAbs(j.Path) {
				j.Path = filepath.Join(base, j.Path)
			}
			var err error
			j.Path, err = filepath.Abs(j.Path)
			if err != nil {
				return fail(err)
			}
		} else {
			repo, err := source.ParseRepository(e.RepoURL)
			if err != nil {
				return fail(err)
			}
			if err = source.ValidateRef(e.Ref); err != nil {
				return fail(err)
			}
			sub, err := source.ValidateSubdir(e.Subdir)
			if err != nil {
				return fail(err)
			}
			j.Kind = "github"
			j.RepoURL = repo.URL()
			j.Ref = e.Ref
			j.Subdir = sub
			if j.Project == "" {
				j.Project = repo.Key()
			}
		}
		if err := config.RequireProject(config.Project{Key: j.Project}); err != nil {
			return fail(err)
		}
		// Case-folding prevents collisions with SQL Server's common case-insensitive collations.
		identity := strings.ToLower(j.Project)
		if identities[identity] {
			return fail(fmt.Errorf("duplicate project %q; use distinct explicit names for multiple refs/subdirectories", j.Project))
		}
		identities[identity] = true
		jobs = append(jobs, j)
	}
	return jobs, nil
}

// RejectAmbiguousJSON rejects duplicate keys and nulls, matching the published
// schema instead of accepting encoding/json's otherwise silent last-value wins.
func RejectAmbiguousJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("batch JSON nesting exceeds 32 levels")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if t == nil {
			return fmt.Errorf("batch JSON must not contain null values")
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := k.(string)
				if !ok {
					return fmt.Errorf("expected JSON key")
				}
				if s != strings.ToLower(s) {
					return fmt.Errorf("batch JSON keys must use the exact lowercase schema names: %q", s)
				}
				if seen[s] {
					return fmt.Errorf("duplicate JSON key %q", s)
				}
				seen[s] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' {
		return fmt.Errorf("batch manifest must be a JSON object")
	}
	if err := value(0); err != nil {
		return fmt.Errorf("batch manifest: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("batch manifest must contain one JSON object")
	}
	return nil
}
