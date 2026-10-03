package scan

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"sekscan/internal/config"
)

// analyzerLocation resolves scanner-specific path bases before enforcing source
// containment. zizmor emits repository-relative identifiers, not cwd-relative
// paths, even when invoked with an absolute filename from an isolated directory.
// A zizmor result must resolve to an explicitly selected input: no basename-only
// guessing, ancestor scanning, external file reads, or weakened boundary checks.
func analyzerLocation(engine, root, cwd string, inputs []string, raw string) (string, error) {
	p, err := localAnalyzerPath(raw)
	if err != nil {
		return "", err
	}
	if engine != "zizmor" {
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		if err = config.WithinDirectory(root, p); err != nil {
			return "", fmt.Errorf("analyzer returned a location outside the selected source target or through a symlink")
		}
		return filepath.Clean(p), nil
	}

	// Absolute paths are never rebased. Relative identifiers must use a known
	// base and exactly match a selected input. This also handles scanning a repo
	// subdirectory, or a nested repository within the selected source target.
	for _, input := range inputs {
		input = filepath.Clean(input)
		bases := []string{root, cwd, filepath.Dir(input)}
		if repo := nearestRepositoryRoot(filepath.Dir(input)); repo != "" {
			bases = append(bases, repo)
		}
		for _, base := range bases {
			candidate := p
			if !filepath.IsAbs(candidate) {
				candidate = filepath.Join(base, candidate)
			}
			rel, relErr := filepath.Rel(input, candidate)
			if relErr != nil || rel != "." {
				continue
			}
			if err = config.WithinDirectory(root, candidate); err != nil {
				return "", fmt.Errorf("analyzer returned a location outside the selected source target or through a symlink")
			}
			st, statErr := os.Stat(candidate)
			if statErr != nil || !st.Mode().IsRegular() {
				return "", fmt.Errorf("analyzer location does not identify an existing selected source file")
			}
			return filepath.Clean(candidate), nil
		}
	}
	return "", fmt.Errorf("zizmor location could not be resolved to its selected input; absolute, repository-relative and source-relative paths were checked")
}

// Only native paths and local file URIs identify source files. Do not silently
// interpret remote URLs, URI credentials, query strings or fragments as filenames.
func localAnalyzerPath(raw string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n") {
		return "", fmt.Errorf("analyzer returned an empty or invalid source location")
	}
	p := raw
	windowsDrive := len(raw) >= 3 && raw[1] == ':' && (raw[2] == '\\' || raw[2] == '/')
	if strings.HasPrefix(strings.ToLower(raw), "file:") {
		u, err := url.Parse(raw)
		if err != nil || (u.Host != "" && u.Host != "localhost") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return "", fmt.Errorf("analyzer returned an invalid or nonlocal file URI")
		}
		p = u.Path
		if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
		if !filepath.IsAbs(p) {
			return "", fmt.Errorf("analyzer file URI must use an absolute local path")
		}
	} else if windowsDrive {
		if runtime.GOOS != "windows" {
			return "", fmt.Errorf("analyzer returned a path for a different platform")
		}
	} else if u, err := url.Parse(raw); err == nil && (u.Scheme != "" || u.Host != "") {
		return "", fmt.Errorf("analyzer returned a nonlocal source URI")
	}
	if strings.ContainsAny(p, "\x00\r\n") || strings.HasPrefix(p, `\\`) {
		return "", fmt.Errorf("analyzer returned an invalid or network source path")
	}
	p = filepath.FromSlash(p)
	if !filepath.IsAbs(p) {
		for _, part := range strings.Split(filepath.ToSlash(p), "/") {
			if part == ".." {
				return "", fmt.Errorf("analyzer returned a traversing source path")
			}
		}
	}
	return p, nil
}

// Discover only the marker, without executing Git, reading its config, or following
// gitdir indirections. A regular .git file supports worktrees/submodules as well.
func nearestRepositoryRoot(start string) string {
	for p := filepath.Clean(start); ; p = filepath.Dir(p) {
		if st, err := os.Lstat(filepath.Join(p, ".git")); err == nil && (st.IsDir() || st.Mode().IsRegular()) {
			return p
		}
		if filepath.Dir(p) == p {
			return ""
		}
	}
}
