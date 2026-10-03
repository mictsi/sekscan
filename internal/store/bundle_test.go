package store

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleRoundTrip(t *testing.T) {
	src := t.TempDir()
	if e := Atomic(filepath.Join(src, "grype", "db", "6", "vulnerability.db"), []byte("test database"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(filepath.Join(src, "trivy", "db", "metadata.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(t.TempDir(), "data.tar.gz")
	if e := ExportBundle(src, bundle); e != nil {
		t.Fatal(e)
	}
	dst := t.TempDir()
	if e := ImportBundle(dst, bundle); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(dst, "grype", "db", "6", "vulnerability.db"))
	if e != nil || string(b) != "test database" {
		t.Fatal(e, string(b))
	}
}
func TestBundleTraversal(t *testing.T) {
	f, e := os.Create(filepath.Join(t.TempDir(), "bad.tar.gz"))
	if e != nil {
		t.Fatal(e)
	}
	g := gzip.NewWriter(f)
	w := tar.NewWriter(g)
	w.WriteHeader(&tar.Header{Name: "../evil", Size: 1, Mode: 0600})
	w.Write([]byte("x"))
	w.Close()
	g.Close()
	f.Close()
	if e = ImportBundle(t.TempDir(), f.Name()); e == nil {
		t.Fatal("accepted traversal")
	}
}
func TestAllowedBundlePaths(t *testing.T) {
	for _, s := range []string{"grype/db/../../tools/tool", "/trivy/db/x", "trivy\\db\\x", "tools/grype", "grype/db", "C:/x"} {
		if allowedCachePath(s) {
			t.Fatal(s)
		}
	}
}

func TestBundleRejectsSymlinkedParent(t *testing.T) {
	cache := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(cache, "grype")); err != nil {
		t.Skip("symlink creation not permitted", err)
	}
	if err := safeCacheRoots(cache); err == nil {
		t.Fatal("accepted symlinked database parent")
	}
}
