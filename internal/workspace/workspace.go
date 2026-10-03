// Package workspace initializes a portable directory without overwriting user files.
package workspace

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sekscan/internal/config"
)

//go:embed defaults/*
var defaults embed.FS

func Ensure(c config.Config) error {
	for _, p := range []string{c.Paths.Bin, c.Paths.Cache, c.Paths.Logs, c.Paths.Data} {
		if e := os.MkdirAll(p, 0700); e != nil {
			return e
		}
	}
	return nil
}
func writeNew(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}
func Init(root string) ([]string, error) { return Initialize(root, true) }

// Initialize can seed supporting files without creating a second main config.
func Initialize(root string, createMain bool) ([]string, error) {
	c := config.Default()
	resolved := c
	resolved.ResolvePaths(root)
	if e := Ensure(resolved); e != nil {
		return nil, e
	}
	for _, n := range []string{"syft", "grype", "trivy", "actionlint", "hadolint"} {
		t := c.Tools[n]
		t.NativeConfig = "config/" + n + ".yaml"
		c.Tools[n] = t
	}
	for name, file := range map[string]string{"gosec": "gosec.json"} {
		t := c.Tools[name]
		t.NativeConfig = "config/" + file
		c.Tools[name] = t
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return nil, e
	}
	b = append(b, '\n')
	names := []string{}
	if createMain {
		// Do not shadow the supported config/sekscan.json discovery location.
		if _, statErr := os.Stat(filepath.Join(root, "config", "sekscan.json")); os.IsNotExist(statErr) {
			if e = writeNew(filepath.Join(root, "sekscan.json"), b); e != nil {
				return nil, e
			}
			names = append(names, "sekscan.json")
		} else if statErr != nil {
			return nil, statErr
		}
	}
	entries, e := fs.ReadDir(defaults, "defaults")
	if e != nil {
		return nil, e
	}
	for _, f := range entries {
		b, e := defaults.ReadFile("defaults/" + f.Name())
		if e != nil {
			return nil, e
		}
		p := filepath.Join(root, "config", f.Name())
		if e = writeNew(p, b); e != nil {
			return nil, e
		}
		names = append(names, "config/"+f.Name())
	}
	if e = writeNew(filepath.Join(root, ".sekscan-workspace"), []byte("sekscan workspace v2\n")); e != nil {
		return nil, e
	}
	return names, nil
}
func ReadDefault(name string) ([]byte, error) {
	b, e := defaults.ReadFile("defaults/" + name)
	if e != nil {
		return nil, fmt.Errorf("unknown standard config")
	}
	return b, nil
}
