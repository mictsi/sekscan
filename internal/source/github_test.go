package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(r *http.Request, code int, body []byte) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: r}
}

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
func TestGitHubAcquisitionCacheAndTokenBoundary(t *testing.T) {
	repo, _ := ParseRepository("Org/Repo")
	sha := strings.Repeat("a", 40)
	data := archiveBytes(t, archiveEntry{name: "root/src/main.go", body: "package main\n"})
	requests := []string{}
	c := Client{Cache: t.TempDir(), Token: "private-token"}
	c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.String())
		if r.URL.Host == "api.github.com" && r.Header.Get("Authorization") != "Bearer private-token" {
			t.Fatal("missing API authorization")
		}
		switch {
		case r.URL.Host == "codeload.github.com":
			if r.Header.Get("Authorization") != "" {
				t.Fatal("token forwarded to archive host")
			}
			return response(r, 200, data), nil
		case r.URL.Path == "/repos/org/repo":
			return response(r, 200, []byte(`{"default_branch":"main"}`)), nil
		case strings.Contains(r.URL.Path, "/commits/"):
			return response(r, 200, []byte(fmt.Sprintf(`{"sha":%q}`, sha))), nil
		case strings.Contains(r.URL.Path, "/tarball/"):
			v := response(r, 302, nil)
			v.Header.Set("Location", "https://codeload.github.com/org/repo/legacy.tar.gz/"+sha+"?ephemeral=sensitive")
			return v, nil
		}
		return nil, fmt.Errorf("unexpected request")
	})
	s, e := c.Acquire(context.Background(), repo, "", "src", false)
	if e != nil {
		t.Fatal(e)
	}
	if s.Revision != sha || s.ResolvedRef != "main" || !s.Complete || s.RequestedRef != "" {
		t.Fatal(s)
	}
	h := sha256.Sum256(data)
	if s.ArchiveSHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("hash")
	}
	path := s.Path
	if _, e = os.Stat(filepath.Join(path, "main.go")); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("cleanup")
	}
	count := len(requests)
	offline, e := c.Acquire(context.Background(), repo, sha, "", true)
	if e != nil {
		t.Fatal(e)
	}
	offline.Close()
	if len(requests) != count {
		t.Fatal("offline network")
	}
	if _, e = c.Acquire(context.Background(), repo, "main", "", true); e == nil {
		t.Fatal("offline mutable ref")
	}
	if _, e = c.Acquire(context.Background(), repo, strings.Repeat("b", 40), "", true); e == nil {
		t.Fatal("offline missing cache")
	}
	if _, e = c.Acquire(context.Background(), repo, sha, "missing-subdir", true); e == nil {
		t.Fatal("missing subdir")
	}
	files, _ := filepath.Glob(filepath.Join(c.Cache, "sources", "github", "*", "*.tar.gz"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	os.WriteFile(files[0], []byte("modified"), 0600)
	if _, e = c.Acquire(context.Background(), repo, sha, "", true); e == nil || !strings.Contains(e.Error(), "checksum mismatch") {
		t.Fatal(e)
	}
}
func TestGitHubErrorsAndLimits(t *testing.T) {
	repo, _ := ParseRepository("o/r")
	for _, code := range []int{401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			c := Client{Cache: t.TempDir(), Token: "HIDDEN", Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return response(r, code, []byte("HIDDEN private response")), nil
			})}
			_, e := c.Acquire(context.Background(), repo, "main", "", false)
			if e == nil || strings.Contains(e.Error(), "HIDDEN") {
				t.Fatal(e)
			}
		})
	}
	c := Client{Cache: t.TempDir(), Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		v := response(r, 302, nil)
		v.Header.Set("Location", "https://evil.test/?token=HIDDEN")
		return v, nil
	})}
	if _, e := c.Acquire(context.Background(), repo, "main", "", false); e == nil || strings.Contains(e.Error(), "HIDDEN") {
		t.Fatal(e)
	}
	for _, raw := range []string{"http://api.github.com/x", "https://api.github.com.evil.test/x", "https://user@codeload.github.com/x", "https://api.github.com:8443/x"} {
		u, _ := url.Parse(raw)
		if allowedURL(u) {
			t.Fatal(raw)
		}
	}
	sha := strings.Repeat("a", 40)
	c.MaxArchiveBytes = 5
	c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/commits/") {
			return response(r, 200, []byte(`{"sha":"`+sha+`"}`)), nil
		}
		return response(r, 200, []byte("too big")), nil
	})
	if _, e := c.Acquire(context.Background(), repo, sha, "", false); e == nil || !strings.Contains(e.Error(), "limit") {
		t.Fatal(e)
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
