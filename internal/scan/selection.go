package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"sekscan/internal/config"
	"sekscan/internal/model"
)

// selectInputs uses explicit paths rather than executing repository discovery tools.
// Symlinks are never followed. A matching symlink is a coverage error, not a clean input.
func selectInputs(ctx context.Context, target model.Target, selector string, exclude []string) ([]string, error) {
	if selector == "" || selector == "all" {
		return []string{target.Value}, nil
	}
	if target.Kind != "dir" && target.Kind != "rootfs" {
		return nil, nil
	}
	if selector == "go-modules" {
		return selectGoModules(ctx, target, exclude)
	}
	paths := []string{}
	count := 0
	err := filepath.WalkDir(target.Value, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("cannot inspect analyzer input: %w", err)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		count++
		if count > 250000 {
			return fmt.Errorf("analyzer discovery exceeds 250000 entries; split the project or add exclusions")
		}
		rel, err := filepath.Rel(target.Value, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel != "." && excludedPath(rel, exclude) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		// Dependency caches are not application source. Go analyzers still resolve
		// dependencies through the workspace module cache or an explicit vendor tree.
		if rel != "." && d.IsDir() && sourceDependencyDirectory(name) {
			return filepath.SkipDir
		}
		lower := strings.ToLower(name)
		match := false
		switch selector {
		case "dockerfiles":
			match = lower == "dockerfile" || lower == "containerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "containerfile.") || strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile")
		case "workflows":
			ext := strings.ToLower(filepath.Ext(name))
			workflow := strings.HasPrefix(rel, ".github/workflows/") && !strings.Contains(strings.TrimPrefix(rel, ".github/workflows/"), "/")
			match = (workflow && (ext == ".yml" || ext == ".yaml")) || lower == "action.yml" || lower == "action.yaml"
		case "source":
			switch strings.ToLower(filepath.Ext(name)) {
			case ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".cs", ".rb", ".php", ".c", ".h", ".cpp", ".rs", ".kt", ".scala", ".swift", ".sh":
				match = true
			}
		default:
			return fmt.Errorf("unknown analyzer selector %q", selector)
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if match {
				return fmt.Errorf("matching analyzer input is a symlink; select an explicit directory or exclude it")
			}
			return nil
		}
		if !match {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("analyzer input is not a regular file")
		}
		if err = config.WithinDirectory(target.Value, p); err != nil {
			return err
		}
		if selector == "source" {
			if len(paths) == 0 {
				paths = append(paths, target.Value)
			}
			return nil
		}
		if len(paths) >= 1024 {
			return fmt.Errorf("analyzer input count exceeds 1024; split the project")
		}
		paths = append(paths, p)
		return nil
	})
	return paths, err
}
func excludedPath(p string, excludes []string) bool {
	p = filepath.ToSlash(filepath.Clean(p))
	for _, x := range excludes {
		x = filepath.ToSlash(filepath.Clean(x))
		if p == x || strings.HasPrefix(p, x+"/") {
			return true
		}
	}
	return false
}

// ToolsForTarget avoids installing irrelevant language runtimes for an image or
// documentation-only directory. Preparation without a target still readies the full suite.
func ToolsForTarget(ctx context.Context, c config.Config, target model.Target) ([]string, error) {
	core := c
	core.Extensions = nil
	core.Checks.Hadolint = false
	core.Checks.Zizmor = false
	core.Checks.Govulncheck = false
	core.Checks.Gosec = false
	if target.Kind != "dir" && target.Kind != "rootfs" {
		core.Checks.Gitleaks = false
	}
	if target.Kind != "dir" {
		core.Checks.Actionlint = false
	}
	out := core.RequiredTools()
	exclude := analyzerExclusions(c, target)
	for _, e := range c.EffectiveExtensions() {
		applicable := false
		for _, kind := range e.Targets {
			if kind == target.Kind {
				applicable = true
			}
		}
		if !applicable {
			continue
		}
		inputs, err := selectInputs(ctx, target, e.When, exclude)
		if err != nil {
			return nil, err
		}
		if len(inputs) == 0 {
			continue
		}
		for _, n := range append(append([]string{}, e.RequiresTools...), e.Tool) {
			if n == "" {
				continue
			}
			found := false
			for _, v := range out {
				if v == n {
					found = true
				}
			}
			if !found {
				out = append(out, n)
			}
		}
	}
	return out, nil
}
