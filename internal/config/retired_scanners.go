package config

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"
)

// UnmarshalJSON accepts the retired check only for older workspace files. It has
// no effect on execution and is never written into newly generated configuration.
func (c *Checks) UnmarshalJSON(data []byte) error {
	type current Checks
	decoded := struct {
		*current
		Semgrep *bool `json:"semgrep"`
	}{current: (*current)(c)}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return err
	}
	c.retiredSemgrep = decoded.Semgrep != nil
	return nil
}

// RemovedScanner identifies retired managed scanner names, not arbitrary command
// arguments. Historical report engine names are deliberately left untouched.
func RemovedScanner(name string) bool {
	switch strings.TrimSuffix(strings.ToLower(name), ".exe") {
	case "semgrep", "pysemgrep", "semgrep-core":
		return true
	}
	return false
}

func RemovedScannerExtension(e Extension) bool {
	if RemovedScanner(e.Name) || RemovedScanner(e.Tool) ||
		RemovedScanner(path.Base(strings.ReplaceAll(e.Executable, `\`, "/"))) {
		return true
	}
	for _, tool := range e.RequiresTools {
		if RemovedScanner(tool) {
			return true
		}
	}
	return false
}

// WithoutSemgrep removes legacy activation, tool and extension entries in memory.
// It does not delete installations, caches, policies, findings, or the source file.
// Only an unused built-in uv helper accompanying a retired config is discarded;
// custom non-Semgrep integrations that explicitly require uv are preserved.
func (c Config) WithoutSemgrep() Config {
	removed := c.Checks.retiredSemgrep
	c.Checks.retiredSemgrep = false
	tools := make(map[string]Tool, len(c.Tools))
	for name, tool := range c.Tools {
		if RemovedScanner(name) {
			removed = true
			continue
		}
		tools[name] = tool
	}
	extensions := make([]Extension, 0, len(c.Extensions))
	uvUsed := false
	for _, e := range c.Extensions {
		if RemovedScannerExtension(e) {
			removed = true
			continue
		}
		if e.Tool == "uv" || containsTool(e.RequiresTools, "uv") {
			uvUsed = true
		}
		extensions = append(extensions, e)
	}
	if tool, ok := tools["uv"]; removed && ok && !uvUsed && tool.Install == nil && tool.Path == "" && len(tool.CommandArgs) == 0 {
		delete(tools, "uv")
	}
	c.Tools, c.Extensions = tools, extensions
	if removed {
		const notice = "Semgrep support has been removed; legacy Semgrep settings and its unused managed helper are ignored. Stored results and workspace files are unchanged."
		if !containsTool(c.MigrationWarnings, notice) {
			c.MigrationWarnings = append(append([]string{}, c.MigrationWarnings...), notice)
		}
	}
	return c
}
