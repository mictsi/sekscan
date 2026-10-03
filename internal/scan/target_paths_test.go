package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitTargetPrefixes(t *testing.T) {
	for _, kind := range []string{"dir", "rootfs", "image", "docker-archive", "oci-archive", "oci-layout", "sbom"} {
		if !HasTargetPrefix(kind+":/outside/current/folder") || !HasTargetPrefix(kind+":") {
			t.Errorf("did not recognize target type %s", kind)
		}
	}
	for _, value := range []string{"", "scan", "scan:.", "bogus:.", ".", "/absolute/path", "./local", `C:\project`, "https://host/path"} {
		if HasTargetPrefix(value) {
			t.Errorf("treated non-target %q as shorthand", value)
		}
	}
}

func TestDirectoryTargetsOutsideWorkingDirectory(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	targetParent := t.TempDir()
	if _, err := filepath.Rel(cwd, targetParent); err != nil {
		// Windows runners may put the checkout and system temp directory on
		// different drives, where no relative path can represent the target.
		targetParent = filepath.Dir(cwd)
	}
	container, err := os.MkdirTemp(targetParent, "sekscan-target-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(container) })
	dir := filepath.Join(container, "project with spaces")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"absolute":           "dir:" + dir,
		"trailing_separator": "dir:" + dir + string(filepath.Separator),
		"relative":           "dir:" + relative,
		"bare_absolute":      dir,
		"bare_relative":      relative,
		"rootfs":             "rootfs:" + dir,
	} {
		t.Run(name, func(t *testing.T) {
			target, err := ParseTarget(input)
			if err != nil || target.Value != canonical {
				t.Fatalf("%q: %+v error=%v", input, target, err)
			}
			if got, err := os.Getwd(); err != nil || got != cwd {
				t.Fatalf("cwd changed: %q, %v", got, err)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "project-link")
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("host cannot create symlinks: %v", err)
		}
		target, err := ParseTarget("dir:" + link)
		if err != nil || target.Value != canonical {
			t.Fatalf("symlink not resolved: %+v, %v", target, err)
		}
	})
}
