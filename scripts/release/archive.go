package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"
)

// copyPath accepts only ordinary files/directories, never links or device files.
func copyPath(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.MkdirAll(destination, 0755); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() == "__pycache__" || entry.Name() == ".DS_Store" {
				continue
			}
			if err := copyPath(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe release input (links/special files are forbidden): %s", source)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	mode := fs.FileMode(0644)
	if info.Mode().Perm()&0111 != 0 || strings.HasSuffix(source, ".sh") {
		mode = 0755
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func copyLegalFiles(root, destination string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		n := strings.ToUpper(entry.Name())
		if n == "LICENSE" || strings.HasPrefix(n, "LICENSE.") || n == "NOTICE" || strings.HasPrefix(n, "NOTICE.") {
			if err := copyPath(filepath.Join(root, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func populatePayload(o options, destination, target string, modules []module) error {
	for _, name := range []string{"docs", "examples", "schema", "third_party", "CHANGELOG.md", "TESTING.md"} {
		if err := copyPath(filepath.Join(o.Root, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	if err := copyPath(filepath.Join(o.Root, "README.md"), filepath.Join(destination, "SOURCE-README.md")); err != nil {
		return err
	}
	if err := copyPath(filepath.Join(o.Root, "internal/workspace/defaults"), filepath.Join(destination, "config")); err != nil {
		return err
	}
	if err := copyPath(filepath.Join(o.Root, "examples/workspace-sekscan.json"), filepath.Join(destination, "sekscan.json")); err != nil {
		return err
	}
	for _, name := range []string{"bin", "cache", "logs", "data"} {
		if err := os.Mkdir(filepath.Join(destination, name), 0700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(destination, ".sekscan-workspace"), []byte("sekscan workspace v2\n"), 0644); err != nil {
		return err
	}
	if err := copyLegalFiles(o.Root, destination); err != nil {
		return err
	}
	parts := strings.Split(target, "/")
	data := struct{ Version, Target, Directory, Executable string }{
		Version: o.Version, Target: target, Directory: "sekscan-" + o.Version + "-" + parts[0] + "-" + parts[1], Executable: "sekscan",
	}
	if parts[0] == "windows" {
		data.Executable += ".exe"
	}
	raw, err := os.ReadFile(filepath.Join(o.Root, "scripts/release/README.md.tmpl"))
	if err != nil {
		return err
	}
	t, err := template.New("README").Option("missingkey=error").Parse(string(raw))
	if err != nil {
		return err
	}
	var readme bytes.Buffer
	if err := t.Execute(&readme, data); err != nil {
		return err
	}
	for _, name := range []string{"README.md", "readme.med"} {
		if err := os.WriteFile(filepath.Join(destination, name), readme.Bytes(), 0644); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(destination, "GO-MODULES.json"), modules); err != nil {
		return err
	}
	binaryHash, err := hashFile(filepath.Join(destination, data.Executable))
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(destination, "BUILD-INFO.json"), map[string]any{
		"schema_version": 1, "version": o.Version, "target": target,
		"build_time_utc": o.Timestamp.Format(time.RFC3339), "binary_sha256": binaryHash,
		"production_drivers": true, "publisher_signed": false,
		"scanner_tools_bundled": false, "scanner_databases_bundled": false,
	})
}

func populateSource(root, destination string) error {
	if err := os.Mkdir(destination, 0755); err != nil {
		return err
	}
	// Never copy the whole checkout: workspace secrets, logs, caches and databases stay out.
	for _, name := range []string{"go.mod", "go.sum", "README.md", "TESTING.md", "CHANGELOG.md", "cmd", "internal", "scripts", "docs", "examples", "schema", "testdata", "third_party"} {
		if err := copyPath(filepath.Join(root, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	for _, name := range []string{".github", ".gitignore", "go.offline.mod"} {
		if _, err := os.Lstat(filepath.Join(root, name)); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := copyPath(filepath.Join(root, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	if err := copyPath(filepath.Join(root, "README.md"), filepath.Join(destination, "readme.med")); err != nil {
		return err
	}
	return copyLegalFiles(root, destination)
}

func writeChecksums(root, name string) error {
	var lines []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsafe checksum input: %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == name {
			return nil
		}
		if strings.ContainsAny(rel, "\r\n\\") && filepath.Separator != '\\' {
			return fmt.Errorf("unsafe checksum filename: %s", rel)
		}
		rel = filepath.ToSlash(rel)
		if strings.ContainsAny(rel, "\r\n") {
			return fmt.Errorf("unsafe checksum filename: %s", rel)
		}
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		lines = append(lines, digest+"  "+rel)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(lines)
	return os.WriteFile(filepath.Join(root, name), []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func zipTree(source, destination string, timestamp time.Time) (err error) {
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	z := zip.NewWriter(f)
	defer func() {
		if e := z.Close(); err == nil {
			err = e
		}
		if e := f.Close(); err == nil {
			err = e
		}
		if err != nil {
			_ = os.Remove(destination)
		}
	}()
	// DOS timestamps cannot represent dates before 1980.
	if timestamp.Before(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)) {
		timestamp = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	parent := filepath.Dir(source)
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe ZIP input: %s", path)
		}
		rel, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if !fs.ValidPath(name) || strings.ContainsAny(name, "\\\r\n") {
			return fmt.Errorf("unsafe ZIP entry: %q", name)
		}
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: timestamp.UTC()}
		h.SetMode(info.Mode())
		if info.IsDir() {
			h.Name += "/"
			h.Method = zip.Store
		}
		w, err := z.CreateHeader(h)
		if err != nil || info.IsDir() {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(w, in)
		closeErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
