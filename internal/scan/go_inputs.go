package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sekscan/internal/config"
	"sekscan/internal/model"
)

// selectGoModules determines applicability without executing Go or reading its
// dependency graph. A go.mod alone is metadata, not evidence of analyzable Go
// source. Each source belongs to its nearest module, never to an empty parent
// module merely because a nested module contains Go files.
func selectGoModules(ctx context.Context, target model.Target, excludes []string) ([]string, error) {
	type marker struct {
		selected bool
		regular  bool
	}
	modules := map[string]marker{}
	sources := []string{}
	entries := 0
	err := filepath.WalkDir(target.Value, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("cannot determine Go applicability: %w", err)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > 250000 {
			return fmt.Errorf("Go discovery exceeds 250000 entries; split the project or add exclusions")
		}
		rel, err := filepath.Rel(target.Value, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		excluded := rel != "." && excludedPath(rel, excludes)
		// An excluded module marker is still an ownership boundary: its files
		// must not accidentally reactivate the parent module.
		if d.Name() == "go.mod" && !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			modules[filepath.Dir(p)] = marker{!excluded, info.Mode().IsRegular()}
		}
		if excluded {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if rel != "." && sourceDependencyDirectory(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		// Follow Go's filename convention without treating parse/build errors as
		// non-Go. Tests and platform-specific .go files are still Go evidence.
		if strings.HasSuffix(name, ".go") && !strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "_") {
			sources = append(sources, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, source := range sources {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		for dir := filepath.Dir(source); ; dir = filepath.Dir(dir) {
			if module, found := modules[dir]; found {
				if !module.selected || !goPackagePath(dir, source) {
					break
				}
				if !module.regular {
					return nil, fmt.Errorf("Go module marker is a symlink or non-regular file; cannot establish analysis scope")
				}
				st, statErr := os.Lstat(source)
				if statErr != nil {
					return nil, fmt.Errorf("cannot inspect Go source: %w", statErr)
				}
				if !st.Mode().IsRegular() {
					return nil, fmt.Errorf("Go source is a symlink or non-regular file; select an explicit directory or exclude it")
				}
				if err = config.WithinDirectory(target.Value, source); err != nil {
					return nil, err
				}
				selected[dir] = true
				if len(selected) > 1024 {
					return nil, fmt.Errorf("Go module input count exceeds 1024; split the project")
				}
				break
			}
			if dir == filepath.Clean(target.Value) || dir == filepath.Dir(dir) {
				break
			}
		}
	}
	paths := make([]string, 0, len(selected))
	for p := range selected {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

// Go ./... ignores these package-directory names. Evaluate relative to the
// selected module, so an explicitly selected nested module is not confused with
// its parent's packages. Build tags and compilation remain the analyzer's job.
func goPackagePath(module, source string) bool {
	rel, err := filepath.Rel(module, filepath.Dir(source))
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "testdata" || strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
			return false
		}
	}
	return true
}

func sourceDependencyDirectory(name string) bool {
	return name == "node_modules" || name == ".venv" || name == "vendor" || name == ".git"
}

// Both prerequisite planning and scanner invocation must use the same paths.
func analyzerExclusions(c config.Config, target model.Target, additional ...string) []string {
	excludes := append([]string{}, c.Exclude...)
	if target.Kind != "dir" && target.Kind != "rootfs" {
		return excludes
	}
	paths := append([]string{c.Paths.Bin, c.Paths.Cache, c.Paths.Logs, c.Paths.Data, c.Storage.Path}, additional...)
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			continue
		}
		rel, err := filepath.Rel(target.Value, p)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			excludes = append(excludes, filepath.ToSlash(rel))
		}
	}
	return excludes
}

func noAnalyzerInputsReason(selector string) string {
	if selector == "go-modules" {
		return "Not applicable: no non-excluded Go module with Go source files in the selected target"
	}
	return "No applicable non-excluded inputs (" + selector + ")"
}
