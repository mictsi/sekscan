package workspace

import (
	"os"
	"path/filepath"
	"sekscan/internal/config"
	"testing"
)

func TestInitializePreservesFilesAndDiscovery(t *testing.T) {
	root := t.TempDir()
	if _, e := Init(root); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"bin", "cache", "logs", "data", "config"} {
		if st, e := os.Stat(filepath.Join(root, n)); e != nil || !st.IsDir() {
			t.Fatal(n, e)
		}
	}
	c, e := config.Load(filepath.Join(root, "sekscan.json"))
	if e != nil || c.Tools["trivy"].NativeConfig != filepath.Join(root, "config", "trivy.yaml") {
		t.Fatal(c, e)
	}
	path := filepath.Join(root, "config", "trivy.yaml")
	os.WriteFile(path, []byte("reviewed: true\n"), 0600)
	if _, e := Init(root); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "reviewed: true\n" {
		t.Fatal("overwrote reviewed config")
	}
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "config"), 0700)
	os.WriteFile(filepath.Join(root, "config", "sekscan.json"), []byte(`{}`), 0600)
	if _, e := Init(root); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(root, "sekscan.json")); !os.IsNotExist(e) {
		t.Fatal("shadowed existing config")
	}
}
func TestAllStandardAppConfigurationsValidate(t *testing.T) {
	root := t.TempDir()
	if _, e := Init(root); e != nil {
		t.Fatal(e)
	}
	files, _ := filepath.Glob(filepath.Join(root, "config", "*.json"))
	for _, p := range files {
		if filepath.Base(p) == "gosec.json" {
			continue
		}
		if _, e := config.Load(p); e != nil {
			t.Fatal(p, e)
		}
	}
}
