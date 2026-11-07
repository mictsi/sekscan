package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type archiveEntry struct {
	name, body string
	kind       byte
	link       string
}

func archiveBytes(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, v := range entries {
		kind := v.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		h := &tar.Header{Name: v.name, Mode: 0600, Typeflag: kind, Linkname: v.link}
		if kind == tar.TypeReg {
			h.Size = int64(len(v.body))
		}
		if e := tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if h.Size > 0 {
			if _, e := tw.Write([]byte(v.body)); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestRepositoryParsing(t *testing.T) {
	for _, v := range []string{"Org/Repo", "https://github.com/Org/Repo/", "git@github.com:Org/Repo.git", "github:Org/Repo"} {
		r, e := ParseRepository(v)
		if e != nil || r.Key() != "org/repo" || r.URL() != "https://github.com/org/repo" {
			t.Fatal(r, e)
		}
	}
	for _, v := range []string{"http://github.com/o/r", "https://github.com:443/o/r", "https://user:secret@github.com/o/r", "https://github.com/o/r?token=a", "https://evil.test/o/r", "https://github.com/o/r/tree/main", "o/../r", "o/r#x", "o/r%2fextra", "o/.git", ""} {
		if _, e := ParseRepository(v); e == nil {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"../a", "/root", "a/../../b", "a\\b", "a:c", "a\x00b"} {
		if _, e := ValidateSubdir(v); e == nil {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"..", ".", " main", "x\ny", strings.Repeat("a", 257)} {
		if ValidateRef(v) == nil {
			t.Fatal(v)
		}
	}
}
func TestExtractionRejectsUnsafeArchives(t *testing.T) {
	cases := [][]archiveEntry{
		{{name: "root/../escape", body: "x"}}, {{name: "/root/file", body: "x"}}, {{name: "root/a\\b", body: "x"}}, {{name: "root/a:b", body: "x"}},
		{{name: "root/a", body: "x"}, {name: "other/b", body: "x"}}, {{name: "root/a", body: "x"}, {name: "root/A", body: "x"}}, {{name: "root/pipe", kind: tar.TypeFifo}}, {{name: "single-file", body: "x"}},
	}
	for i, entries := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, e := extract(context.Background(), bytes.NewReader(archiveBytes(t, entries...)), t.TempDir(), 1024, 100); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	data := archiveBytes(t, archiveEntry{name: "root/a", body: "0123456789"})
	if _, e := extract(context.Background(), bytes.NewReader(data), t.TempDir(), 5, 100); e == nil {
		t.Fatal("size bound")
	}
	data = archiveBytes(t, archiveEntry{name: "root/a", body: "x"}, archiveEntry{name: "root/b", body: "x"})
	if _, e := extract(context.Background(), bytes.NewReader(data), t.TempDir(), 100, 1); e == nil {
		t.Fatal("entry bound")
	}
	data[len(data)-5] ^= 0xff
	if _, e := extract(context.Background(), bytes.NewReader(data), t.TempDir(), 100, 10); e == nil {
		t.Fatal("corrupt gzip")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := extract(ctx, bytes.NewReader(archiveBytes(t, archiveEntry{name: "root/a", body: "x"})), t.TempDir(), 100, 10); e == nil {
		t.Fatal("cancellation")
	}
}
func TestExtractionReportsMissingCoverage(t *testing.T) {
	data := archiveBytes(t, archiveEntry{name: "root/symlink", kind: tar.TypeSymlink, link: "/etc/passwd"}, archiveEntry{name: "root/.gitmodules", body: "[submodule]\n"}, archiveEntry{name: "root/large.bin", body: "version https://git-lfs.github.com/spec/v1\noid sha256:abc\n"})
	dest := t.TempDir()
	notes, e := extract(context.Background(), bytes.NewReader(data), dest, 2048, 10)
	if e != nil || len(notes) != 3 {
		t.Fatal(notes, e)
	}
	if _, e = os.Lstat(filepath.Join(dest, "symlink")); !os.IsNotExist(e) {
		t.Fatal("materialized link")
	}
}
