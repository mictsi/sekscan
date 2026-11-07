package deps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/safearchive"
	"sekscan/internal/store"
)

// KICS publishes the executable and rule assets separately. Verify both before
// publishing a single relocatable bundle; a lock pin covers the entire file tree.
func (m *Manager) installKICSBundle(ctx context.Context, t config.Tool, release Release, binary Asset, data []byte) (Installed, error) {
	var rules Asset
	for _, a := range release.Assets {
		if a.Name == "extracted-info.zip" {
			rules = a
		}
	}
	expected := strings.TrimPrefix(rules.Digest, "sha256:")
	if rules.URL == "" || !strings.HasPrefix(rules.Digest, "sha256:") || len(expected) != 64 {
		return Installed{}, fmt.Errorf("KICS release lacks rules with a SHA256 asset digest")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return Installed{}, fmt.Errorf("invalid KICS rule asset digest")
	}
	assets, err := m.get(ctx, rules.URL, 128<<20, false)
	if err != nil {
		return Installed{}, err
	}
	h := sha256.Sum256(assets)
	if hex.EncodeToString(h[:]) != expected {
		return Installed{}, fmt.Errorf("KICS rule archive SHA256 mismatch")
	}
	root := filepath.Join(m.Dir, "kics")
	if err = config.WithinDirectory(m.Dir, root); err != nil {
		return Installed{}, err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return Installed{}, err
	}
	temp, err := os.MkdirTemp(root, ".kics-")
	if err != nil {
		return Installed{}, err
	}
	defer os.RemoveAll(temp)
	if err = safearchive.Extract(ctx, data, binary.Name, temp, ""); err != nil {
		return Installed{}, err
	}
	if err = safearchive.Extract(ctx, assets, rules.Name, temp, ""); err != nil {
		return Installed{}, err
	}
	entry := binName("kics", m.GOOS)
	for _, p := range []string{entry, "assets/libraries/common.rego", "assets/libraries/common.json"} {
		st, err := os.Stat(filepath.Join(temp, filepath.FromSlash(p)))
		if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			return Installed{}, fmt.Errorf("KICS bundle lacks %s", p)
		}
	}
	files := map[string]string{}
	queries := 0
	err = filepath.WalkDir(temp, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(temp, p)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "assets/queries/") && strings.HasSuffix(rel, "/query.rego") {
			queries++
		}
		hash, err := store.SHA256(p)
		files[rel] = hash
		return err
	})
	if err != nil {
		return Installed{}, err
	}
	if queries == 0 {
		return Installed{}, fmt.Errorf("KICS bundle has no queries")
	}
	manifest, _ := json.Marshal(files)
	h = sha256.Sum256(manifest)
	version := strings.TrimPrefix(release.Tag, "v")
	installed := Installed{Name: "kics", Version: version, Repository: "Checkmarx/kics", Asset: binary.Name + " + " + rules.Name,
		Entrypoint: entry, Files: files, ArchiveSHA256: hex.EncodeToString(h[:]), BinarySHA256: files[entry],
		GOOS: m.GOOS, GOARCH: m.GOARCH, InstalledAt: time.Now().UTC(), Path: filepath.ToSlash(filepath.Join("kics", version, entry)),
		Verification: "executable archive checksum manifest; rules GitHub SHA256 digest; complete bundle file manifest"}
	if t.SHA256 != "" && !strings.EqualFold(t.SHA256, installed.ArchiveSHA256) {
		return Installed{}, fmt.Errorf("KICS bundle differs from configured SHA256 pin")
	}
	if err = os.Chmod(filepath.Join(temp, entry), 0700); err != nil {
		return Installed{}, err
	}
	if err = m.publishBundle(temp, installed); err != nil {
		return Installed{}, err
	}
	return installed, nil
}
