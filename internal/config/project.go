package config

import (
	"fmt"
	"strings"
	"unicode"
)

// RequireProject validates explicit project keys used by scans and history filters.
// Keys are never derived from paths or silently normalized.
func RequireProject(p Project) error {
	if p.Key == "" {
		return fmt.Errorf("scan project is required: use --project NAME or set project.key in sekscan.json")
	}
	if len(p.Key) > 256 || strings.TrimSpace(p.Key) != p.Key || strings.IndexFunc(p.Key, unicode.IsControl) >= 0 {
		return fmt.Errorf("project name/key must be 1..256 bytes with no control characters or surrounding whitespace")
	}
	return nil
}
