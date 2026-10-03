package scan

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"sekscan/internal/runner"
)

func syftExclusions(kind string, paths []string) []string {
	prefix := "/"
	if kind == "dir" || kind == "rootfs" {
		prefix = "./"
	}
	out := []string{}
	seen := map[string]bool{}
	for _, p := range paths {
		clean := filepath.ToSlash(filepath.Clean(p))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			continue
		}
		clean = prefix + strings.TrimPrefix(clean, "./")
		for _, pattern := range []string{clean, strings.TrimSuffix(clean, "/") + "/**"} {
			if !seen[pattern] {
				out = append(out, pattern)
				seen[pattern] = true
			}
		}
	}
	return out
}

func (s *Scanner) saveDiagnostics(engine string, stderr []byte) {
	if !s.Config.DiagnosticStderr || len(stderr) == 0 {
		return
	}
	name, err := runner.SaveStderr(s.Config.Paths.Logs, engine, stderr)
	if err != nil {
		s.Logger.Warn("cannot save private scanner diagnostics", "engine", engine)
		return
	}
	s.Logger.Warn("raw diagnostics saved locally; may contain secrets, do not publish automatically", "engine", engine, "file", name)
}

// gosec returns package-load diagnostics in JSON rather than necessarily stderr.
// Only its errors/stats are saved; issues, source snippets and all other sections
// stay out of this opt-in file. Raw error messages may still contain sensitive data.
func (s *Scanner) saveGosecDiagnostics(report []byte) {
	if !s.Config.DiagnosticStderr {
		return
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(report, &raw) != nil {
		return
	}
	payload := map[string]json.RawMessage{}
	for _, key := range []string{"Golang errors", "Stats"} {
		if value, ok := raw[key]; ok {
			payload[key] = value
		}
	}
	if len(payload) == 0 {
		return
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	file, err := runner.SaveDiagnostic(s.Config.Paths.Logs, "gosec", "processing-errors", b)
	if err != nil {
		s.Logger.Warn("cannot save private scanner diagnostics", "engine", "gosec")
		return
	}
	s.Logger.Warn("raw processing errors saved locally; may contain secrets, do not publish automatically", "engine", "gosec", "file", file)
}
