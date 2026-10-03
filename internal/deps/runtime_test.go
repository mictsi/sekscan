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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sekscan/internal/config"
	"sekscan/internal/runner"
	"sekscan/internal/store"
	"strings"
	"testing"
)

type runtimeTransport func(*http.Request) (*http.Response, error)

func (f runtimeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func runtimeResponse(b []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b))}
}
func TestPublicRuntimeDownloadBoundaries(t *testing.T) {
	for _, u := range []string{"http://go.dev/file", "https://evil.invalid/file", "https://user:pass@go.dev/file", "https://go.dev:443/file"} {
		if _, err := PublicDownload(context.Background(), nil, u, 10); err == nil {
			t.Fatal(u)
		}
	}
	client := &http.Client{Transport: runtimeTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("credential leaked")
		}
		return runtimeResponse([]byte("12345")), nil
	})}
	if _, err := PublicDownload(context.Background(), client, "https://proxy.golang.org/golang.org/x/vuln/@latest", 4); err == nil {
		t.Fatal("limit ignored")
	}
}
func TestPortableBundleImportIntegrityRelocationAndPin(t *testing.T) {
	c := config.Default()
	c.Tools["custom-sast"] = config.Tool{Version: "latest"}
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	source := t.TempDir()
	os.MkdirAll(filepath.Join(source, "lib"), 0700)
	os.WriteFile(filepath.Join(source, "tool"), []byte("exe"), 0700)
	os.WriteFile(filepath.Join(source, "lib", "rules"), []byte("rules"), 0600)
	entry, err := m.ImportBundle(context.Background(), "custom-sast", "1.2.3", source, "tool", []string{"{tool_dir}/lib/rules"})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Files["lib/rules"] == "" || len(entry.ArchiveSHA256) != 64 {
		t.Fatal(entry)
	}
	moved := filepath.Join(t.TempDir(), "bin")
	if err = os.Rename(m.Dir, moved); err != nil {
		t.Fatal(err)
	}
	m.Dir = moved
	p, src, err := m.resolve("custom-sast", c.Tools["custom-sast"])
	if err != nil || src != "managed" || !strings.HasPrefix(p, moved) {
		t.Fatal(p, src, err)
	}
	args := m.CommandArgs("custom-sast", c.Tools["custom-sast"], []string{"scan"})
	if args[0] != filepath.Join(moved, "custom-sast", "1.2.3", "lib", "rules") {
		t.Fatal(args)
	}
	os.WriteFile(filepath.Join(moved, "custom-sast", "1.2.3", "injected.py"), []byte("evil"), 0600)
	if _, _, err = m.resolve("custom-sast", c.Tools["custom-sast"]); err == nil {
		t.Fatal("untracked injection accepted")
	}
	c.Tools["custom-sast"] = config.Tool{Version: "latest", SHA256: strings.Repeat("0", 64)}
	m.Tools = c.Tools
	if _, err = m.ImportBundle(context.Background(), "custom-sast", "2.0.0", source, "tool", nil); err == nil {
		t.Fatal("wrong pin accepted")
	}
}
func TestBundleRejectsLinksAndBadEntrypoint(t *testing.T) {
	c := config.Default()
	c.Tools["custom-sast"] = config.Tool{Version: "latest"}
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	source := t.TempDir()
	os.WriteFile(filepath.Join(source, "tool"), []byte("exe"), 0700)
	for _, entry := range []string{"../tool", "/tool", "C:/tool", "missing"} {
		if _, err := m.ImportBundle(context.Background(), "custom-sast", "1.0.0", source, entry, nil); err == nil {
			t.Fatal(entry)
		}
	}
	if err := os.Symlink("tool", filepath.Join(source, "link")); err == nil {
		if _, err = m.ImportBundle(context.Background(), "custom-sast", "1.0.0", source, "tool", nil); err == nil {
			t.Fatal("link accepted")
		}
	}
}
func TestManagedGoSDKChecksumAndBundle(t *testing.T) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tarw := tar.NewWriter(gz)
	for n, body := range map[string]string{"go/bin/go": "executable", "go/src/runtime/runtime.go": "runtime"} {
		tarw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len(body))})
		tarw.Write([]byte(body))
	}
	tarw.Close()
	gz.Close()
	hash := sha256.Sum256(archive.Bytes())
	checksum := hex.EncodeToString(hash[:])
	c := config.Default()
	c.Tools["custom-sast"] = config.Tool{Version: "latest"}
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	m.GOOS = "linux"
	m.GOARCH = "amd64"
	meta := []goRelease{{Version: "go1.27.1", Stable: true, Files: []goFile{{Filename: "go1.27.1.linux-amd64.tar.gz", OS: "linux", Arch: "amd64", Kind: "archive", SHA256: checksum}}}}
	m.Client = &http.Client{Transport: runtimeTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "go.dev" {
			b, _ := json.Marshal(meta)
			return runtimeResponse(b), nil
		}
		return runtimeResponse(archive.Bytes()), nil
	})}
	entry, err := m.Install(context.Background(), "go", c.Tools["go"])
	if err != nil {
		t.Fatal(err)
	}
	if entry.Entrypoint != "bin/go" || len(entry.Files) != 2 {
		t.Fatal(entry)
	}
	env, err := m.Environment(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(env, "\n"), "GOROOT="+filepath.Join(c.Paths.Bin, "go", "1.27.1")) {
		t.Fatal("managed GOROOT missing")
	}
	meta[0].Files[0].SHA256 = strings.Repeat("0", 64)
	if _, err = m.Install(context.Background(), "go", c.Tools["go"]); err == nil {
		t.Fatal("SDK checksum ignored")
	}
}

type runtimeExec struct{ requests []runner.Request }

func (x *runtimeExec) Run(_ context.Context, q runner.Request) (runner.Result, error) {
	x.requests = append(x.requests, q)
	if len(q.Args) == 1 || (len(q.Args) == 3 && q.Args[2] == "-version") {
		return runner.Result{Stdout: []byte("tool 1.2.3")}, nil
	}
	if len(q.Args) == 2 && q.Args[0] == "install" && strings.HasPrefix(q.Args[1], "golang.org/x/vuln/") {
		for _, e := range q.Env {
			if strings.HasPrefix(e, "GOBIN=") {
				p := filepath.Join(strings.TrimPrefix(e, "GOBIN="), "govulncheck")
				return runner.Result{}, os.WriteFile(p, []byte("fixture binary"), 0700)
			}
		}
	}
	return runner.Result{}, fmt.Errorf("unexpected runtime command")
}
func seedRuntime(t *testing.T, m *Manager, name string) {
	t.Helper()
	p := filepath.Join(m.Dir, name, "1.2.3", name)
	os.MkdirAll(filepath.Dir(p), 0700)
	os.WriteFile(p, []byte("fixture"), 0700)
	hash, _ := store.SHA256(p)
	store.JSON(filepath.Join(m.Dir, name, "current.json"), Installed{Name: name, Version: "1.2.3", BinarySHA256: hash})
}
func TestManagedGovulncheckRecipe(t *testing.T) {
	c := config.Default()
	c.Tools["custom-sast"] = config.Tool{Version: "latest"}
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	m.GOOS = "linux"
	m.GOARCH = "amd64"
	x := &runtimeExec{}
	m.Executor = x
	seedRuntime(t, m, "go")
	m.Client = &http.Client{Transport: runtimeTransport(func(r *http.Request) (*http.Response, error) {

		return runtimeResponse([]byte(`{"Version":"v1.2.3"}`)), nil
	})}
	g, err := m.Install(context.Background(), "govulncheck", c.Tools["govulncheck"])
	if err != nil {
		t.Fatal(err)
	}
	if g.Version != "1.2.3" {
		t.Fatal(g)
	}
	for _, q := range x.requests {
		if len(q.Args) > 0 && q.Args[0] == "install" {
			env := strings.Join(q.Env, "\n")
			if !strings.Contains(env, "GOSUMDB=sum.golang.org") || !strings.Contains(env, "GOTOOLCHAIN=local") {
				t.Fatal("unsafe Go build environment")
			}
		}
	}
	u := m.CheckUpdate(context.Background(), "govulncheck", c.Tools["govulncheck"])
	if u.Latest != "1.2.3" {
		t.Fatal(u)
	}
}
func TestManagedNativeReleaseLayouts(t *testing.T) {
	for _, name := range []string{"hadolint", "zizmor", "gosec", "uv"} {
		for _, o := range []string{"linux", "darwin", "windows"} {
			for _, a := range []string{"amd64", "arm64"} {
				if o == "windows" && a == "arm64" {
					continue
				}
				if asset, err := AssetName(name, "1.2.3", o, a); err != nil || asset == "" {
					t.Fatal(name, o, a, asset, err)
				}
			}
		}
	}
	if v := ExtractToolVersion("govulncheck", []byte("Go: go1.27.1\nScanner: govulncheck@v1.8.0")); v != "1.8.0" {
		t.Fatal(v)
	}
}

func TestManagedWindowsSDKArchive(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create("go/bin/go.exe")
	f.Write([]byte("exe"))
	w.Close()
	hash := sha256.Sum256(b.Bytes())
	c := config.Default()
	c.Tools["custom-sast"] = config.Tool{Version: "latest"}
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	m.GOOS = "windows"
	m.GOARCH = "amd64"
	m.Client = &http.Client{Transport: runtimeTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "go.dev" {
			doc, _ := json.Marshal([]goRelease{{Version: "go1.27.1", Stable: true, Files: []goFile{{Filename: "go1.27.1.windows-amd64.zip", OS: "windows", Arch: "amd64", Kind: "archive", SHA256: hex.EncodeToString(hash[:])}}}})
			return runtimeResponse(doc), nil
		}
		return runtimeResponse(b.Bytes()), nil
	})}
	entry, err := m.Install(context.Background(), "go", c.Tools["go"])
	if err != nil || entry.Entrypoint != "bin/go.exe" || entry.GOOS != "windows" {
		t.Fatal(entry, err)
	}
}
