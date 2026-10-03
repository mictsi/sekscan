package deps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/store"
)

func safeBundlePath(p string) bool {
	return p != "" && p != "." && !strings.ContainsAny(p, "\\:\x00") && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}
func verifyBundle(root string, files map[string]string) error {
	if len(files) == 0 || len(files) > 100000 {
		return fmt.Errorf("invalid bundle manifest")
	}
	seen := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle symlinks are not allowed")
		}
		seen++
		rel, _ := filepath.Rel(root, p)
		key := filepath.ToSlash(rel)
		hash, ok := files[key]
		if !ok || !safeBundlePath(key) {
			return fmt.Errorf("untracked/invalid bundle file")
		}
		if err = config.WithinDirectory(root, p); err != nil {
			return err
		}
		actual, err := store.SHA256(p)
		if err != nil {
			return err
		}
		if actual != hash {
			return fmt.Errorf("bundle file integrity check failed")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(files) {
		return fmt.Errorf("bundle files are missing")
	}
	return nil
}

func (m *Manager) CommandArgs(name string, t config.Tool, args []string) []string {
	prefix := append([]string{}, t.CommandArgs...)
	root := ""
	var installed Installed
	if b, err := store.Read(filepath.Join(m.Dir, name, "current.json"), 16<<20); err == nil && json.Unmarshal(b, &installed) == nil && config.ValidVersion(installed.Version) && installed.Version != "latest" {
		root, _ = filepath.Abs(filepath.Join(m.Dir, name, installed.Version))
		if len(prefix) == 0 {
			prefix = append(prefix, installed.CommandArgs...)
		}
	}
	for i, a := range prefix {
		prefix[i] = strings.ReplaceAll(a, "{tool_dir}", root)
	}
	return append(prefix, args...)
}
func ExtractToolVersion(name string, b []byte) string {
	text := string(b)
	if name == "go" {
		text = strings.ReplaceAll(text, "go version go", "go version ")
	}
	if name == "govulncheck" {
		re := regexp.MustCompile(`govulncheck(?:@|\s+)(v?[0-9]+\.[0-9]+\.[0-9]+)`)
		if v := re.FindStringSubmatch(text); len(v) > 1 {
			return strings.TrimPrefix(v[1], "v")
		}
	}
	return ExtractVersion([]byte(text))
}

// ImportBundle copies a reviewed, self-contained tool/runtime directory into bin.
// No symlinks or special files are accepted, and the full file set is checksummed.
func (m *Manager) ImportBundle(ctx context.Context, name, version, source, entry string, commandArgs []string) (Installed, error) {
	if config.RemovedScanner(name) {
		return Installed{}, fmt.Errorf("Semgrep support has been removed")
	}
	var result Installed
	if _, ok := m.Tools[name]; !ok {
		return result, fmt.Errorf("undefined tool %q", name)
	}
	if !config.ValidVersion(version) || version == "latest" || !safeBundlePath(entry) {
		return result, fmt.Errorf("bundle requires an exact version and a safe relative executable path")
	}
	for _, arg := range commandArgs {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return result, fmt.Errorf("bundle command arguments cannot contain NUL or line breaks")
		}
	}
	version = strings.TrimPrefix(version, "v")
	source, err := filepath.Abs(source)
	if err != nil {
		return result, err
	}
	root := filepath.Join(m.Dir, name)
	if err = config.WithinDirectory(m.Dir, root); err != nil {
		return result, err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return result, err
	}
	// Prevent recursively copying an output nested inside its own source.
	rootAbs, _ := filepath.Abs(root)
	rel, _ := filepath.Rel(source, rootAbs)
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return result, fmt.Errorf("bundle source must not contain its installation directory")
	}
	staging, err := os.MkdirTemp(root, ".bundle-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(staging)
	files := map[string]string{}
	size := int64(0)
	err = filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !safeBundlePath(rel) {
			return fmt.Errorf("unsafe bundle path")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle contains a symlink; materialize its in-bundle target first")
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(staging, filepath.FromSlash(rel)), 0700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("bundle contains a non-regular file")
		}
		size += info.Size()
		if len(files) >= 100000 || size > 2<<30 || info.Size() > 512<<20 {
			return fmt.Errorf("bundle exceeds file or size limit")
		}
		b, err := store.Read(p, 512<<20)
		if err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if info.Mode()&0111 != 0 || rel == entry {
			mode = 0700
		}
		if err = store.Atomic(filepath.Join(staging, filepath.FromSlash(rel)), b, mode); err != nil {
			return err
		}
		hash := sha256.Sum256(b)
		files[rel] = hex.EncodeToString(hash[:])
		return nil
	})
	if err != nil {
		return result, err
	}
	if _, ok := files[entry]; !ok {
		return result, fmt.Errorf("bundle executable is absent")
	}
	manifest, _ := json.Marshal(files)
	hash := sha256.Sum256(manifest)
	result = Installed{Name: name, Version: version, Entrypoint: entry, Files: files, CommandArgs: commandArgs, ArchiveSHA256: hex.EncodeToString(hash[:]), BinarySHA256: files[entry], GOOS: m.GOOS, GOARCH: m.GOARCH, InstalledAt: time.Now().UTC(), Verification: "operator-approved bundle; SHA256 file manifest", Path: filepath.ToSlash(filepath.Join(name, version, entry))}
	if pin := m.Tools[name].SHA256; pin != "" && !strings.EqualFold(pin, result.ArchiveSHA256) {
		return Installed{}, fmt.Errorf("bundle manifest differs from configured SHA256 pin")
	}
	if err = m.publishBundle(staging, result); err != nil {
		return Installed{}, err
	}
	return result, nil
}
func (m *Manager) publishBundle(staging string, installed Installed) error {
	root := filepath.Join(m.Dir, installed.Name)
	dest := filepath.Join(root, installed.Version)
	if err := config.WithinDirectory(m.Dir, dest); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(root, ".install.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("another installation may be active: %w", err)
	}
	lock.Close()
	defer os.Remove(filepath.Join(root, ".install.lock"))
	if _, err = os.Stat(dest); err == nil {
		if err = verifyBundle(dest, installed.Files); err != nil {
			return fmt.Errorf("existing bundle version differs; select another version or remove it while scans are stopped")
		}
	} else if os.IsNotExist(err) {
		if err = os.Rename(staging, dest); err != nil {
			return err
		}
	} else {
		return err
	}
	return store.JSON(filepath.Join(root, "current.json"), installed)
}
