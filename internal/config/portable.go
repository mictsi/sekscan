package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WithinDirectory rejects escapes and symlinks, including existing ancestors of
// a not-yet-created destination. It is validation, not an OS-level sandbox.
func WithinDirectory(root, filename string) error {
	base, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	target, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("portable path is outside its workspace directory")
	}
	for p := target; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot inspect portable path: %w", err)
		}
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("portable paths must not traverse symlinks")
		}
		// Rel respects platform path casing (notably Windows drive names).
		same, relErr := filepath.Rel(base, p)
		if relErr == nil && same == "." {
			break
		}
		if filepath.Dir(p) == p {
			return fmt.Errorf("cannot establish portable path containment")
		}
	}
	return nil
}

func (c Config) ValidatePortable() error {
	if !c.Portable || c.WorkspaceRoot == "" {
		return nil
	}
	for _, p := range []string{c.Paths.Bin, c.Paths.Cache, c.Paths.Logs, c.Paths.Data} {
		if err := WithinDirectory(c.WorkspaceRoot, p); err != nil {
			return fmt.Errorf("portable workspace: %w", err)
		}
	}
	if c.Storage.Driver == "sqlite" {
		if err := WithinDirectory(c.WorkspaceRoot, c.Storage.Path); err != nil {
			return fmt.Errorf("portable SQLite storage: %w", err)
		}
	}
	for name, tool := range c.Tools {
		if tool.NativeConfig != "" {
			if err := WithinDirectory(c.WorkspaceRoot, tool.NativeConfig); err != nil {
				return fmt.Errorf("%s native_config: %w", name, err)
			}
		}
	}
	for _, ext := range c.Extensions {
		if ext.NativeConfig != "" {
			if err := WithinDirectory(c.WorkspaceRoot, ext.NativeConfig); err != nil {
				return fmt.Errorf("%s native_config: %w", ext.Name, err)
			}
		}
		if ext.Tool == "" {
			if !filepath.IsAbs(ext.Executable) {
				return fmt.Errorf("portable extension %s must reference a managed tool or an executable inside bin", ext.Name)
			}
			if err := WithinDirectory(c.Paths.Bin, ext.Executable); err != nil {
				return fmt.Errorf("portable extension %s: %w", ext.Name, err)
			}
		}
	}
	return nil
}

// ForSave converts operational paths back to relative paths. Native configs are
// relative to the configuration file; workspace paths are relative to its root.
func (c Config) ForSave(configDirectory string) Config {
	base, err := filepath.Abs(configDirectory)
	if err != nil {
		return c
	}
	root := configRoot(filepath.Join(base, "sekscan.json"))
	relative := func(base, p string) string {
		if p == "" || !filepath.IsAbs(p) {
			return p
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return p
		}
		return filepath.ToSlash(rel)
	}
	for _, p := range []*string{&c.Paths.Bin, &c.Paths.Cache, &c.Paths.Logs, &c.Paths.Data, &c.Storage.Path} {
		*p = relative(root, *p)
	}
	tools := make(map[string]Tool, len(c.Tools))
	for name, tool := range c.Tools {
		tool.NativeConfig = relative(base, tool.NativeConfig)
		if c.Portable {
			tool.Path = ""
		} else {
			tool.Path = relative(base, tool.Path)
		}
		tools[name] = tool
	}
	c.Tools = tools
	c.Extensions = append([]Extension{}, c.Extensions...)
	for i := range c.Extensions {
		c.Extensions[i].NativeConfig = relative(base, c.Extensions[i].NativeConfig)
		c.Extensions[i].Executable = relative(base, c.Extensions[i].Executable)
	}
	return c
}
