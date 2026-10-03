package store

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var cacheRoots = []string{"grype/db", "trivy/db", "trivy/java-db", "trivy/checks", "govulncheck"}

const bundleMax = int64(8 << 30)

type bundleManifest struct {
	Version int               `json:"version"`
	Created time.Time         `json:"created"`
	Files   map[string]string `json:"files"`
}

func allowedCachePath(p string) bool {
	if strings.Contains(p, "\\") || strings.Contains(p, ":") || strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return false
	}
	for _, root := range cacheRoots {
		if strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}
func safeCacheRoots(cache string) error {
	for _, relative := range []string{".", "grype", "trivy", "grype/db", "trivy/db", "trivy/java-db", "trivy/checks", "govulncheck"} {
		st, err := os.Lstat(filepath.Join(cache, filepath.FromSlash(relative)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("cache database roots must be real directories, not symlinks")
		}
	}
	return nil
}
func ExportBundle(cache, destination string) error {
	if err := safeCacheRoots(cache); err != nil {
		return err
	}
	paths := []string{}
	for _, root := range cacheRoots {
		base := filepath.Join(cache, filepath.FromSlash(root))
		if _, e := os.Stat(base); os.IsNotExist(e) {
			continue
		}
		e := filepath.WalkDir(base, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("cache contains a symlink")
			}
			if !d.IsDir() {
				info, e := d.Info()
				if e != nil {
					return e
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("non-regular cache file")
				}
				rel, _ := filepath.Rel(cache, p)
				paths = append(paths, filepath.ToSlash(rel))
			}
			return nil
		})
		if e != nil {
			return e
		}
	}
	if len(paths) == 0 {
		return fmt.Errorf("no database files found; run db update first")
	}
	sort.Strings(paths)
	if e := os.MkdirAll(filepath.Dir(destination), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(destination), ".sekscan-bundle-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	g := gzip.NewWriter(f)
	tw := tar.NewWriter(g)
	manifest := bundleManifest{Version: 1, Created: time.Now().UTC(), Files: map[string]string{}}
	total := int64(0)
	for _, p := range paths {
		name := filepath.Join(cache, filepath.FromSlash(p))
		input, e := os.Open(name)
		if e != nil {
			return e
		}
		st, e := input.Stat()
		if e != nil {
			input.Close()
			return e
		}
		total += st.Size()
		if total > bundleMax {
			input.Close()
			return fmt.Errorf("cache exceeds bundle size limit")
		}
		if e = tw.WriteHeader(&tar.Header{Name: p, Mode: 0600, Size: st.Size(), ModTime: st.ModTime()}); e != nil {
			input.Close()
			return e
		}
		h := sha256.New()
		_, e = io.Copy(io.MultiWriter(tw, h), input)
		input.Close()
		if e != nil {
			return e
		}
		manifest.Files[p] = hex.EncodeToString(h.Sum(nil))
	}
	b, e := json.Marshal(manifest)
	if e != nil {
		return e
	}
	if e = tw.WriteHeader(&tar.Header{Name: "sekscan-bundle.json", Mode: 0600, Size: int64(len(b))}); e != nil {
		return e
	}
	if _, e = tw.Write(b); e != nil {
		return e
	}
	if e = tw.Close(); e != nil {
		return e
	}
	if e = g.Close(); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), destination)
}
func ImportBundle(cache, source string) error {
	if err := safeCacheRoots(cache); err != nil {
		return err
	}
	if e := os.MkdirAll(cache, 0700); e != nil {
		return e
	}
	temp, e := os.MkdirTemp(cache, ".db-import-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	input, e := os.Open(source)
	if e != nil {
		return e
	}
	defer input.Close()
	g, e := gzip.NewReader(input)
	if e != nil {
		return e
	}
	defer g.Close()
	tr := tar.NewReader(io.LimitReader(g, bundleMax+(16<<20)))
	hashes := map[string]string{}
	total := int64(0)
	var manifest *bundleManifest
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if count > 100000 {
			return fmt.Errorf("too many bundle members")
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 {
			return fmt.Errorf("bundle contains a non-regular member")
		}
		total += h.Size
		if total > bundleMax {
			return fmt.Errorf("bundle exceeds decompressed size limit")
		}
		if h.Name == "sekscan-bundle.json" {
			if manifest != nil || h.Size > 16<<20 {
				return fmt.Errorf("invalid bundle manifest")
			}
			b, e := io.ReadAll(tr)
			if e != nil {
				return e
			}
			manifest = &bundleManifest{}
			if e = json.Unmarshal(b, manifest); e != nil {
				return e
			}
			continue
		}
		if !allowedCachePath(h.Name) {
			return fmt.Errorf("unsafe or unsupported bundle path: %q", h.Name)
		}
		if _, ok := hashes[h.Name]; ok {
			return fmt.Errorf("duplicate bundle path")
		}
		p := filepath.Join(temp, filepath.FromSlash(h.Name))
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return e
		}
		f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		hash := sha256.New()
		_, e = io.Copy(io.MultiWriter(f, hash), tr)
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		hashes[h.Name] = hex.EncodeToString(hash.Sum(nil))
	}
	if manifest == nil || manifest.Version != 1 || len(hashes) == 0 || len(manifest.Files) != len(hashes) {
		return fmt.Errorf("bundle manifest is missing or incomplete")
	}
	for name, hash := range hashes {
		if manifest.Files[name] != hash {
			return fmt.Errorf("bundle integrity check failed for %s", name)
		}
	}
	// Only the whitelisted database directories are replaced; tool installations are untouched.
	type moved struct {
		Destination, Backup string
		HadOld              bool
	}
	moves := []moved{}
	rollback := func() {
		for i := len(moves) - 1; i >= 0; i-- {
			m := moves[i]
			_ = os.RemoveAll(m.Destination)
			if m.HadOld {
				_ = os.Rename(m.Backup, m.Destination)
			}
		}
	}
	for _, root := range cacheRoots {
		src := filepath.Join(temp, filepath.FromSlash(root))
		if _, e := os.Stat(src); os.IsNotExist(e) {
			continue
		}
		dst := filepath.Join(cache, filepath.FromSlash(root))
		if e = os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
			rollback()
			return e
		}
		backup := filepath.Join(temp, "backup-"+strings.ReplaceAll(root, "/", "-"))
		hadOld := false
		if st, e := os.Lstat(dst); e == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				rollback()
				return fmt.Errorf("refusing to replace symlinked cache")
			}
			if e = os.Rename(dst, backup); e != nil {
				rollback()
				return e
			}
			hadOld = true
		} else if !os.IsNotExist(e) {
			rollback()
			return e
		}
		if e = os.Rename(src, dst); e != nil {
			if hadOld {
				_ = os.Rename(backup, dst)
			}
			rollback()
			return e
		}
		moves = append(moves, moved{dst, backup, hadOld})
	}
	return nil
}
