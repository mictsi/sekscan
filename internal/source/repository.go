// Package source acquires bounded GitHub source snapshots without Git, shells,
// hooks, submodule execution, or credentials embedded in URLs.
package source

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

type Repository struct{ Owner, Name string }

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var commitPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func (r Repository) URL() string { return "https://github.com/" + r.Owner + "/" + r.Name }
func (r Repository) Key() string { return strings.ToLower(r.Owner + "/" + r.Name) }
func ParseRepository(raw string) (Repository, error) {
	var r Repository
	if strings.HasPrefix(raw, "github:") {
		raw = strings.TrimPrefix(raw, "github:")
	}
	if strings.HasPrefix(raw, "git@github.com:") {
		raw = "https://github.com/" + strings.TrimPrefix(raw, "git@github.com:")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://github.com/" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "github.com") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return r, fmt.Errorf("repository must be owner/repo or an HTTPS github.com repository URL without credentials, query, or fragment")
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), "/"), "/")
	if len(parts) != 2 {
		return r, fmt.Errorf("repository URL must identify owner/repo; use ref and subdir separately")
	}
	parts[1] = strings.TrimSuffix(parts[1], ".git")
	for _, p := range parts {
		if len(p) < 1 || len(p) > 100 || p == "." || p == ".." || !namePattern.MatchString(p) {
			return r, fmt.Errorf("invalid GitHub owner or repository name")
		}
	}
	return Repository{Owner: strings.ToLower(parts[0]), Name: strings.ToLower(parts[1])}, nil
}
func ValidateRef(ref string) error {
	if ref == "." || ref == ".." || len(ref) > 256 || strings.TrimSpace(ref) != ref || strings.IndexFunc(ref, unicode.IsControl) >= 0 {
		return fmt.Errorf("ref must be at most 256 bytes without control characters or surrounding whitespace")
	}
	return nil
}
func ValidateSubdir(sub string) (string, error) {
	if sub == "" || sub == "." {
		return "", nil
	}
	if strings.ContainsAny(sub, "\\:\x00") || strings.HasPrefix(sub, "/") || strings.IndexFunc(sub, unicode.IsControl) >= 0 || len(sub) > 1024 {
		return "", fmt.Errorf("subdir must be a relative repository directory using forward slashes")
	}
	for _, s := range strings.Split(sub, "/") {
		if s == ".." {
			return "", fmt.Errorf("subdir may not traverse outside the repository")
		}
	}
	return path.Clean(sub), nil
}
