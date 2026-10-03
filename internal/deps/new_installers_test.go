package deps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sekscan/internal/config"
	"sekscan/internal/runner"
)

func TestManagedHadolintAndZizmorReleaseInstall(t *testing.T) {
	for _, name := range []string{"hadolint", "zizmor"} {
		t.Run(name, func(t *testing.T) {
			blob := []byte("portable binary fixture")
			if name == "zizmor" {
				blob = tarArchive(t, []string{"zizmor"}, 0)
			}
			sum := sha256.Sum256(blob)
			digest := hex.EncodeToString(sum[:])
			asset, err := AssetName(name, "1.2.3", "linux", "amd64")
			if err != nil {
				t.Fatal(err)
			}
			var base string
			bad := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/releases/latest"):
					hash := digest
					if bad {
						hash = strings.Repeat("0", 64)
					}
					assets := []Asset{{Name: asset, URL: base + "/asset", Digest: "sha256:" + hash}}
					if name == "hadolint" {
						assets = append(assets, Asset{Name: "checksums.sha256", URL: base + "/checksums"})
					}
					json.NewEncoder(w).Encode(Release{Tag: "v1.2.3", Assets: assets})
				case r.URL.Path == "/asset":
					w.Write(blob)
				case r.URL.Path == "/checksums":
					fmt.Fprintln(w, digest+"  "+asset)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			base = server.URL
			c := config.Default()
			c.ResolvePaths(t.TempDir())
			m := NewConfigured("", c)
			m.APIBase, m.Client, m.GOOS, m.GOARCH = base, server.Client(), "linux", "amd64"
			installed, err := m.Install(context.Background(), name, c.Tools[name])
			if err != nil || installed.Version != "1.2.3" {
				t.Fatal(installed, err)
			}
			path, source, err := m.resolve(name, c.Tools[name])
			if err != nil || source != "managed" {
				t.Fatal(path, source, err)
			}
			if _, err = os.Stat(path); err != nil {
				t.Fatal(err)
			}
			bad = true
			if _, err = m.Install(context.Background(), name, c.Tools[name]); err == nil {
				t.Fatal("release digest mismatch accepted")
			}
		})
	}
}

type versionProbeExecutor struct {
	t      *testing.T
	called bool
}

func (x *versionProbeExecutor) Run(_ context.Context, r runner.Request) (runner.Result, error) {
	x.called = true
	if len(r.Args) != 3 || r.Args[0] != "-db" || !strings.HasPrefix(r.Args[1], "file:///") || r.Args[2] != "-version" {
		x.t.Fatal(r.Args)
	}
	if !strings.Contains(r.Args[1], "version-db") {
		x.t.Fatal("not using isolated version DB", r.Args)
	}
	return runner.Result{Stdout: []byte("Go: go1.27.1\nScanner: govulncheck@v1.2.3\n")}, nil
}
func TestGovulncheckVersionProbeUsesLocalDatabase(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "govulncheck"), []byte("fixture"), 0700)
	if _, err := m.ImportBundle(context.Background(), "govulncheck", "1.2.3", src, "govulncheck", nil); err != nil {
		t.Fatal(err)
	}
	exec := &versionProbeExecutor{t: t}
	m.Executor = exec
	status := m.Inspect(context.Background(), "govulncheck", c.Tools["govulncheck"])
	if status.Error != "" || status.Version != "1.2.3" || !exec.called {
		t.Fatal(status)
	}
}
func TestBundleRejectsControlCharactersInArguments(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	for _, arg := range []string{"a\x00b", "a\nb", "a\rb"} {
		if _, err := m.ImportBundle(context.Background(), "custom-sast", "1.2.3", t.TempDir(), "python", []string{arg}); err == nil {
			t.Fatal("invalid argument accepted")
		}
	}
}
