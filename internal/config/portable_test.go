package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPortableConfigurationRelocation(t *testing.T) {
	old := filepath.Join(t.TempDir(), "original")
	if err := os.MkdirAll(filepath.Join(old, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	native := filepath.Join(old, "config", "syft.yaml")
	if err := os.WriteFile(native, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Default()
	c.ResolvePaths(old)
	tool := c.Tools["syft"]
	tool.NativeConfig = native
	tool.Path = "/ignored/system/syft"
	c.Tools["syft"] = tool
	if err := c.ValidatePortable(); err != nil {
		t.Fatal(err)
	}
	before := c.Hash()
	for _, sub := range []string{"", "config"} {
		t.Run("config_"+sub, func(t *testing.T) {
			raw, err := json.Marshal(c.ForSave(filepath.Join(old, sub)))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), old) || strings.Contains(string(raw), "/ignored/system") {
				t.Fatal("absolute installation paths persisted")
			}
			moved := filepath.Join(t.TempDir(), "moved")
			os.MkdirAll(filepath.Join(moved, "config"), 0700)
			os.WriteFile(filepath.Join(moved, "config", "syft.yaml"), []byte("{}"), 0600)
			filename := filepath.Join(moved, sub, "lock.json")
			os.WriteFile(filename, raw, 0600)
			got, err := Load(filename)
			if err != nil {
				t.Fatal(err)
			}
			got.ResolvePaths(moved)
			if err = got.ValidatePortable(); err != nil {
				t.Fatal(err)
			}
			if got.Hash() != before {
				t.Fatal("config hash changed after relocation")
			}
			if got.Tools["syft"].NativeConfig != filepath.Join(moved, "config", "syft.yaml") {
				t.Fatal("native config did not relocate")
			}
		})
	}
}

func TestPortablePathsRejectEscapesAndLinks(t *testing.T) {
	root := t.TempDir()
	c := Default()
	c.ResolvePaths(root)
	c.Paths.Cache = t.TempDir()
	if c.ValidatePortable() == nil {
		t.Fatal("external cache accepted")
	}
	c.Portable = false
	if err := c.ValidatePortable(); err != nil {
		t.Fatal(err)
	}
	if err := WithinDirectory(root, filepath.Join(root, "new", "leaf")); err != nil {
		t.Fatal(err)
	}
	if WithinDirectory(root, filepath.Join(root, "..", "other")) == nil {
		t.Fatal("path escape accepted")
	}
	if runtime.GOOS != "windows" {
		os.Symlink(t.TempDir(), filepath.Join(root, "linked"))
		if WithinDirectory(root, filepath.Join(root, "linked", "leaf")) == nil {
			t.Fatal("symlink escape accepted")
		}
	}
}

func TestPortableExtensionsCannotUseBarePath(t *testing.T) {
	c := Default()
	c.ResolvePaths(t.TempDir())
	c.Extensions = []Extension{{Name: "checker", Executable: "checker"}}
	if c.ValidatePortable() == nil {
		t.Fatal("PATH-dependent extension accepted")
	}
	c.Extensions[0].Tool = "checker"
	if err := c.ValidatePortable(); err != nil {
		t.Fatal(err)
	}
}
