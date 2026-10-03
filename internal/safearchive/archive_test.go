package safearchive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractRejectsPathsLinksAndDuplicates(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "a/../../escape", "C:/drive", "a\\b", "./relative"} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			w := zip.NewWriter(&b)
			f, _ := w.Create(name)
			f.Write([]byte("x"))
			w.Close()
			if Extract(context.Background(), b.Bytes(), "x.zip", t.TempDir(), "") == nil {
				t.Fatal("unsafe entry accepted")
			}
		})
	}
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeChar} {
		var b bytes.Buffer
		g := gzip.NewWriter(&b)
		w := tar.NewWriter(g)
		w.WriteHeader(&tar.Header{Name: "go/link", Linkname: "/outside", Typeflag: kind})
		w.Close()
		g.Close()
		if Extract(context.Background(), b.Bytes(), "go.tar.gz", t.TempDir(), "go") == nil {
			t.Fatal("unsafe tar type accepted", kind)
		}
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i := 0; i < 2; i++ {
		f, _ := w.Create("same")
		f.Write([]byte("x"))
	}
	w.Close()
	if Extract(context.Background(), b.Bytes(), "x.zip", t.TempDir(), "") == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestExtractSDKPrefixAndExecutable(t *testing.T) {
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	w.WriteHeader(&tar.Header{Name: "go/bin/go", Typeflag: tar.TypeReg, Mode: 0755, Size: 3})
	w.Write([]byte("sdk"))
	w.Close()
	g.Close()
	root := t.TempDir()
	if err := Extract(context.Background(), b.Bytes(), "go.tar.gz", root, "go"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(root, "bin", "go"))
	if err != nil || st.Size() != 3 || st.Mode()&0100 == 0 {
		t.Fatal(st, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if Extract(ctx, b.Bytes(), "go.tar.gz", t.TempDir(), "go") == nil {
		t.Fatal("cancellation ignored")
	}
}
