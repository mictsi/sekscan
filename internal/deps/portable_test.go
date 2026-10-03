package deps

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sekscan/internal/config"
)

func TestPortableInstallIgnoresPATHAndRelocates(t *testing.T) {
	old := filepath.Join(t.TempDir(), "workspace")
	c := config.Default()
	c.ResolvePaths(old)
	m := NewConfigured("", c)
	m.GOOS = "linux"
	m.GOARCH = "amd64"
	m.Executor = versionExecutor{}
	system := t.TempDir()
	outside := filepath.Join(system, "syft")
	os.WriteFile(outside, []byte("system fixture must not execute"), 0700)
	t.Setenv("PATH", system)
	tool := c.Tools["syft"]
	tool.Path = outside
	if st := m.Inspect(context.Background(), "syft", tool); st.Error == "" || st.Path == outside {
		t.Fatal("system executable used", st)
	}
	archive := tarArchive(t, []string{"syft"}, tar.TypeReg)
	hash := fmt.Sprintf("%x", sha256.Sum256(archive))
	downloads := 0
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/anchore/syft/releases/latest":
			json.NewEncoder(w).Encode(Release{Tag: "v1.2.3", Assets: []Asset{{Name: "syft_1.2.3_linux_amd64.tar.gz", URL: base + "/asset"}, {Name: "syft_1.2.3_checksums.txt", URL: base + "/sums"}}})
		case "/asset":
			downloads++
			w.Write(archive)
		case "/sums":
			fmt.Fprintln(w, hash+"  syft_1.2.3_linux_amd64.tar.gz")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	m.APIBase = base
	m.Client = srv.Client()
	installed, err := m.Install(context.Background(), "syft", tool)
	if err != nil {
		t.Fatal(err)
	}
	if downloads != 1 || filepath.IsAbs(installed.Path) || installed.GOOS != "linux" {
		t.Fatal(installed, downloads)
	}
	st := m.Inspect(context.Background(), "syft", tool)
	if st.Error != "" || st.Source != "managed" {
		t.Fatal(st)
	}
	moved := filepath.Join(t.TempDir(), "renamed")
	if err = os.Rename(old, moved); err != nil {
		t.Fatal(err)
	}
	c = config.Default()
	c.ResolvePaths(moved)
	mm := NewConfigured("", c)
	mm.GOOS = "linux"
	mm.GOARCH = "amd64"
	mm.Executor = versionExecutor{}
	st = mm.Inspect(context.Background(), "syft", tool)
	if st.Error != "" || !strings.HasPrefix(st.Path, moved+string(os.PathSeparator)) {
		t.Fatal(st)
	}
	mm.GOARCH = "arm64"
	if st = mm.Inspect(context.Background(), "syft", tool); st.Error == "" {
		t.Fatal("foreign-platform binary accepted")
	}
}
func TestPortableEnvironmentIsWorkspaceLocal(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	t.Setenv("PATH", "/UNWANTED_SYSTEM_PATH")
	t.Setenv("HOME", "/UNWANTED_HOME")
	t.Setenv("GITHUB_TOKEN", "SECRET_SENTINEL")
	t.Setenv("GRYPE_DB_CACHE_DIR", "/wrong/db")
	t.Setenv("Path", "/UNWANTED_CASE_VARIANT")
	env, err := m.Environment(true)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range env {
		k, val, _ := strings.Cut(v, "=")
		got[strings.ToUpper(k)] = val
	}
	for _, k := range []string{"HOME", "USERPROFILE", "XDG_CACHE_HOME", "TMPDIR", "GOMODCACHE", "GRYPE_DB_CACHE_DIR", "TRIVY_CACHE_DIR"} {
		if !strings.HasPrefix(got[k], c.Paths.Cache+string(os.PathSeparator)) {
			t.Fatal(k, got[k])
		}
	}
	if strings.Contains(strings.Join(env, "\n"), "UNWANTED") || strings.Contains(strings.Join(env, "\n"), "SECRET_SENTINEL") {
		t.Fatal("inherited path or token")
	}
	if got["GRYPE_DB_AUTO_UPDATE"] != "false" || got["GOPROXY"] != "off" {
		t.Fatal(got)
	}
	online, err := m.Environment(false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(online, "\n"), "GRYPE_DB_AUTO_UPDATE=true") {
		t.Fatal("online auto update disabled")
	}
}
func TestManagedToolDirectorySymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privilege varies")
	}
	root := t.TempDir()
	c := config.Default()
	c.ResolvePaths(root)
	os.MkdirAll(c.Paths.Bin, 0700)
	os.Symlink(t.TempDir(), filepath.Join(c.Paths.Bin, "syft"))
	m := NewConfigured("", c)
	if _, _, err := m.resolve("syft", c.Tools["syft"]); err == nil {
		t.Fatal("managed symlink accepted")
	}
}
func TestActionlintReleaseNaming(t *testing.T) {
	for _, platform := range []struct{ os, arch, want string }{{"linux", "amd64", "actionlint_1.2.3_linux_amd64.tar.gz"}, {"windows", "amd64", "actionlint_1.2.3_windows_amd64.zip"}, {"darwin", "arm64", "actionlint_1.2.3_darwin_arm64.tar.gz"}} {
		got, err := AssetName("actionlint", "v1.2.3", platform.os, platform.arch)
		if err != nil || got != platform.want {
			t.Fatal(got, err)
		}
	}
}
