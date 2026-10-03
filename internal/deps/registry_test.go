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
	"sekscan/internal/config"
	"sekscan/internal/runner"
	"testing"
)

func TestSemverPrecedence(t *testing.T) {
	for _, v := range []struct {
		a, b string
		n    int
	}{{"1.10.0", "1.9.9", 1}, {"v1.2.3", "1.2.3+build", 0}, {"1.2.3", "1.2.3-rc.1", 1}, {"1.2.3-rc.2", "1.2.3-rc.10", -1}, {"1.2.3-alpha", "1.2.3-alpha.1", -1}, {"1.0.0", "2.0.0", -1}} {
		n, e := CompareVersions(v.a, v.b)
		if e != nil || n != v.n {
			t.Fatal(v, n, e)
		}
	}
	if _, e := CompareVersions("n/a", "1.0.0"); e == nil {
		t.Fatal("invalid version")
	}
}

type versionExecutor struct{}

func (versionExecutor) Run(_ context.Context, r runner.Request) (runner.Result, error) {
	return runner.Result{Stderr: []byte("checker 1.2.3")}, nil
}
func TestCustomRecipeInstallAndUpdate(t *testing.T) {
	archive := tarArchive(t, []string{"checker"}, tar.TypeReg)
	hash := fmt.Sprintf("%x", sha256.Sum256(archive))
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/company/checker/releases/latest":
			json.NewEncoder(w).Encode(Release{Tag: "v1.3.0", Assets: []Asset{{Name: "checker_1.3.0_linux_amd64.tar.gz", URL: base + "/bin"}, {Name: "checksums.txt", URL: base + "/sums"}}})
		case "/bin":
			w.Write(archive)
		case "/sums":
			fmt.Fprintln(w, hash+"  checker_1.3.0_linux_amd64.tar.gz")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	tool := config.Tool{Version: "latest", VersionArgs: []string{"--version"}, Install: &config.InstallRecipe{Repository: "company/checker", Executable: "checker", Checksums: "checksums.txt", Assets: map[string]string{"linux/amd64": "checker_{version}_{os}_{arch}.tar.gz"}}}
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	c.Tools["checker"] = tool
	m := NewConfigured(t.TempDir(), c)
	m.GOOS = "linux"
	m.GOARCH = "amd64"
	m.APIBase = base
	m.Client = srv.Client()
	m.Executor = versionExecutor{}
	i, e := m.Install(context.Background(), "checker", tool)
	if e != nil || i.Version != "1.3.0" {
		t.Fatal(i, e)
	}
	// Version fixture deliberately reports older than release to exercise check-only behavior.
	status := m.CheckUpdate(context.Background(), "checker", tool)
	if status.State != "update-available" || status.Latest != "1.3.0" {
		t.Fatal(status)
	}
	p := filepath.Join(m.Dir, "checker", "current.json")
	before, _ := os.ReadFile(p)
	tool.Version = "1.2.3"
	status = m.CheckUpdate(context.Background(), "checker", tool)
	after, _ := os.ReadFile(p)
	if status.State != "update-available-pinned" || string(before) != string(after) {
		t.Fatal(status, "check changed installation")
	}
}
