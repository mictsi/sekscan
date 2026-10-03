package workspace

import (
	"os"
	"path/filepath"
	"sekscan/internal/config"
	"strings"
	"testing"
)

func TestFreshWorkspaceDoesNotSeedSemgrep(t *testing.T) {
	home := t.TempDir()
	names, err := Init(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.Contains(name, "semgrep") {
			t.Fatal("retired file seeded", name)
		}
	}
	if _, err = os.Stat(filepath.Join(home, "config", "semgrep-rules.yaml")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	c, err := config.Load(filepath.Join(home, "sekscan.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range c.RequiredTools() {
		if config.RemovedScanner(name) || name == "uv" {
			t.Fatal(name)
		}
	}
}
func TestExistingWorkspaceSemgrepFilesPreservedButNotRecreated(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, "config", "semgrep-rules.yaml")
	os.MkdirAll(filepath.Dir(p), 0700)
	os.WriteFile(p, []byte("user-authored"), 0600)
	if _, err := Initialize(home, true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "user-authored" {
		t.Fatal("existing data modified")
	}
	os.Remove(p)
	if _, err := Initialize(home, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("retired file recreated")
	}
}
