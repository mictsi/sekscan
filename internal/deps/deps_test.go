package deps

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sekscan/internal/config"
)

func TestAssetNames(t *testing.T) {
	for _, tt := range []struct{ tool, os, arch, want string }{{"syft", "linux", "amd64", "syft_1.2.3_linux_amd64.tar.gz"}, {"grype", "windows", "amd64", "grype_1.2.3_windows_amd64.zip"}, {"trivy", "darwin", "arm64", "trivy_1.2.3_macOS-ARM64.tar.gz"}, {"trivy", "windows", "amd64", "trivy_1.2.3_windows-64bit.zip"}, {"gitleaks", "linux", "amd64", "gitleaks_1.2.3_linux_x64.tar.gz"}} {
		got, e := AssetName(tt.tool, "v1.2.3", tt.os, tt.arch)
		if e != nil || got != tt.want {
			t.Fatal(got, e)
		}
	}
}
func TestChecksum(t *testing.T) {
	hash := strings.Repeat("a", 64)
	got, e := Checksum([]byte(hash+"  syft.tar.gz\n"), "syft.tar.gz")
	if e != nil || got != hash {
		t.Fatal(got, e)
	}
	for _, b := range []string{"bad syft.tar.gz", hash + " other.gz", hash + " syft.tar.gz\n" + hash + " syft.tar.gz"} {
		if _, e = Checksum([]byte(b), "syft.tar.gz"); e == nil {
			t.Fatal("accepted bad manifest")
		}
	}
}
func tarArchive(t *testing.T, names []string, mode byte) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	for _, name := range names {
		h := &tar.Header{Name: name, Mode: 0700, Size: 5, Typeflag: mode}
		if mode == tar.TypeSymlink {
			h.Size = 0
			h.Linkname = "/etc/passwd"
		}
		if e := w.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if h.Size > 0 {
			w.Write([]byte("hello"))
		}
	}
	w.Close()
	g.Close()
	return b.Bytes()
}
func TestSafeExtraction(t *testing.T) {
	b, e := ExtractExecutable(tarArchive(t, []string{"syft"}, tar.TypeReg), "asset.tar.gz", "syft")
	if e != nil || string(b) != "hello" {
		t.Fatal(e)
	}
	for _, test := range []struct {
		names []string
		mode  byte
	}{{[]string{"../syft"}, tar.TypeReg}, {[]string{"syft", "syft"}, tar.TypeReg}, {[]string{"syft"}, tar.TypeSymlink}} {
		if _, e = ExtractExecutable(tarArchive(t, test.names, test.mode), "a.tar.gz", "syft"); e == nil {
			t.Fatal("accepted unsafe archive")
		}
	}
	var zipData bytes.Buffer
	z := zip.NewWriter(&zipData)
	w, _ := z.Create("syft.exe")
	w.Write([]byte("hello"))
	z.Close()
	if b, e = ExtractExecutable(zipData.Bytes(), "a.zip", "syft.exe"); e != nil || string(b) != "hello" {
		t.Fatal(e)
	}
}
func TestInstallerEndToEndLocalServer(t *testing.T) {
	archive := tarArchive(t, []string{"syft"}, tar.TypeReg)
	hash := sha256.Sum256(archive)
	digest := hex.EncodeToString(hash[:])
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/anchore/syft/releases/latest":
			json.NewEncoder(w).Encode(Release{Tag: "v1.2.3", Assets: []Asset{{Name: "syft_1.2.3_linux_amd64.tar.gz", URL: base + "/asset", Digest: "sha256:" + digest}, {Name: "syft_1.2.3_checksums.txt", URL: base + "/checksums"}}})
		case "/asset":
			w.Write(archive)
		case "/checksums":
			fmt.Fprintln(w, digest+"  syft_1.2.3_linux_amd64.tar.gz")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base = server.URL
	m := New(t.TempDir())
	m.APIBase = base
	m.Client = server.Client()
	m.GOOS = "linux"
	m.GOARCH = "amd64"
	installed, e := m.Install(context.Background(), "syft", config.Tool{Version: "latest"})
	if e != nil {
		t.Fatal(e)
	}
	if installed.Version != "1.2.3" {
		t.Fatal(installed)
	}
	executable, source, e := m.resolve("syft", config.Tool{Version: "1.2.3"})
	if e != nil || source != "managed" {
		t.Fatal(e)
	}
	if e = os.WriteFile(executable, []byte("modified"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, _, e = m.resolve("syft", config.Tool{Version: "latest"}); e == nil {
		t.Fatal("accepted modified managed binary")
	}
	if _, e = m.Install(context.Background(), "syft", config.Tool{Version: "latest", SHA256: strings.Repeat("0", 64)}); e == nil {
		t.Fatal("accepted mismatched independent checksum pin")
	}
	if _, e = os.Stat(filepath.Join(m.Dir, "syft", "current.json")); e != nil {
		t.Fatal(e)
	}
}
func TestTrustedURLs(t *testing.T) {
	for _, s := range []string{"http://github.com/x", "https://github.com.evil.example/x", "https://user:pass@github.com/x", "file:///tmp/x"} {
		u, _ := url.Parse(s)
		if trustedURL(u) {
			t.Fatal(s)
		}
	}
	u, _ := url.Parse("https://release-assets.githubusercontent.com/x")
	if !trustedURL(u) {
		t.Fatal("reject release host")
	}
}
