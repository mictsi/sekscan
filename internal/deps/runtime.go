package deps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/runner"
	"sekscan/internal/safearchive"
	"sekscan/internal/store"
)

// PublicDownload is limited to official runtime/database endpoints. It never sends
// GitHub credentials. An injected client may change transport, not host validation.
func PublicDownload(ctx context.Context, client *http.Client, address string, max int64) ([]byte, error) {
	allowed := func(u *url.URL) bool {
		if u.Scheme != "https" || u.User != nil || u.Port() != "" {
			return false
		}
		switch u.Hostname() {
		case "go.dev", "dl.google.com", "proxy.golang.org", "vuln.go.dev":
			return true
		}
		return false
	}
	u, err := url.Parse(address)
	if err != nil || !allowed(u) {
		return nil, fmt.Errorf("unapproved runtime/database URL")
	}
	c := http.Client{Timeout: 15 * time.Minute}
	if client != nil {
		c = *client
	}
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || !allowed(r.URL) {
			return fmt.Errorf("unapproved runtime redirect")
		}
		r.Header.Del("Authorization")
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sekscan")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("runtime/database download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("runtime/database endpoint returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("runtime/database download exceeds limit")
	}
	return b, nil
}

type goFile struct {
	Filename string `json:"filename"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kind     string `json:"kind"`
	SHA256   string `json:"sha256"`
}
type goRelease struct {
	Version string   `json:"version"`
	Stable  bool     `json:"stable"`
	Files   []goFile `json:"files"`
}

func (m *Manager) goRelease(ctx context.Context, version string) (goRelease, goFile, error) {
	address := "https://go.dev/dl/?mode=json"
	if version != "" && version != "latest" {
		address += "&include=all"
	}
	b, err := PublicDownload(ctx, m.Client, address, 16<<20)
	if err != nil {
		return goRelease{}, goFile{}, err
	}
	var releases []goRelease
	if err = json.Unmarshal(b, &releases); err != nil {
		return goRelease{}, goFile{}, err
	}
	for _, r := range releases {
		v := strings.TrimPrefix(r.Version, "go")
		if !r.Stable || !config.ValidVersion(v) {
			continue
		}
		if version != "" && version != "latest" && strings.TrimPrefix(version, "v") != v {
			continue
		}
		for _, f := range r.Files {
			if f.OS == m.GOOS && f.Arch == m.GOARCH && f.Kind == "archive" {
				return r, f, nil
			}
		}
		return goRelease{}, goFile{}, fmt.Errorf("Go SDK release lacks this platform")
	}
	return goRelease{}, goFile{}, fmt.Errorf("requested stable Go SDK release not found")
}
func (m *Manager) runtimeVersion(ctx context.Context, name, version string) (string, error) {
	if name != "go" && name != "govulncheck" {
		return "", fmt.Errorf("unsupported managed runtime %q", name)
	}
	if name == "go" {
		r, _, err := m.goRelease(ctx, version)
		return strings.TrimPrefix(r.Version, "go"), err
	}
	if version != "" && version != "latest" {
		if !config.ValidVersion(version) {
			return "", fmt.Errorf("invalid runtime version")
		}
		return strings.TrimPrefix(version, "v"), nil
	}
	address := "https://proxy.golang.org/golang.org/x/vuln/@latest"
	b, err := PublicDownload(ctx, m.Client, address, 16<<20)
	if err != nil {
		return "", err
	}
	var doc struct{ Version string }
	if err = json.Unmarshal(b, &doc); err != nil {
		return "", err
	}
	v := strings.TrimPrefix(doc.Version, "v")
	if !config.ValidVersion(v) || v == "latest" || strings.ContainsAny(v, "-+") {
		return "", fmt.Errorf("upstream did not provide a stable version")
	}
	return v, nil
}
func (m *Manager) installGo(ctx context.Context, t config.Tool) (Installed, error) {
	r, f, err := m.goRelease(ctx, t.Version)
	if err != nil {
		return Installed{}, err
	}
	if !safeBundlePath(f.Filename) || strings.Contains(f.Filename, "/") || len(f.SHA256) != 64 {
		return Installed{}, fmt.Errorf("invalid Go release metadata")
	}
	b, err := PublicDownload(ctx, m.Client, "https://dl.google.com/go/"+f.Filename, 256<<20)
	if err != nil {
		return Installed{}, err
	}
	h := sha256.Sum256(b)
	if !strings.EqualFold(hex.EncodeToString(h[:]), f.SHA256) {
		return Installed{}, fmt.Errorf("Go SDK archive checksum mismatch")
	}
	temp, err := m.runtimeTemp("go")
	if err != nil {
		return Installed{}, err
	}
	defer os.RemoveAll(temp)
	if err = safearchive.Extract(ctx, b, f.Filename, temp, "go"); err != nil {
		return Installed{}, err
	}
	// Bundle pins cover the complete installed file tree, including runtime libraries.
	return m.ImportBundle(ctx, "go", strings.TrimPrefix(r.Version, "go"), temp, "bin/"+binName("go", m.GOOS), nil)
}
func (m *Manager) runtimeTemp(name string) (string, error) {
	cache := m.CacheDir
	if cache == "" {
		cache = filepath.Join(filepath.Dir(m.Dir), "cache")
	}
	cache, err := filepath.Abs(cache)
	if err != nil {
		return "", err
	}
	root := filepath.Join(cache, "preparation")
	if err = config.WithinDirectory(cache, root); err != nil {
		return "", err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	return os.MkdirTemp(root, name+"-")
}
func (m *Manager) ensureRuntime(ctx context.Context, name string) (Status, error) {
	t, ok := m.Tools[name]
	if !ok {
		return Status{}, fmt.Errorf("required managed prerequisite %s has no tool definition", name)
	}
	s := m.Inspect(ctx, name, t)
	if s.Error != "" {
		if _, err := m.Install(ctx, name, t); err != nil {
			return s, err
		}
		s = m.Inspect(ctx, name, t)
	}
	if s.Error != "" {
		return s, fmt.Errorf("prerequisite %s: %s", name, s.Error)
	}
	return s, nil
}
func (m *Manager) installGovulncheck(ctx context.Context, t config.Tool) (Installed, error) {
	version, err := m.runtimeVersion(ctx, "govulncheck", t.Version)
	if err != nil {
		return Installed{}, err
	}
	goTool, err := m.ensureRuntime(ctx, "go")
	if err != nil {
		return Installed{}, err
	}
	temp, err := m.runtimeTemp("govulncheck")
	if err != nil {
		return Installed{}, err
	}
	defer os.RemoveAll(temp)
	env, err := m.Environment(false)
	if err != nil {
		return Installed{}, err
	}
	env = goDownloadEnvironment(env)
	env = runner.Merge(env, "GOBIN="+temp, "GOFLAGS=-trimpath", "CGO_ENABLED=0")
	_, err = m.runPreparation(ctx, runner.Request{Executable: goTool.Path, Args: []string{"install", "golang.org/x/vuln/cmd/govulncheck@v" + version}, Dir: temp, Env: env, Timeout: 20 * time.Minute, MaxOutput: 8 << 20})
	if err != nil {
		return Installed{}, fmt.Errorf("managed govulncheck build failed: %w", err)
	}
	return m.ImportBundle(ctx, "govulncheck", version, temp, binName("govulncheck", m.GOOS), nil)
}
func goDownloadEnvironment(env []string) []string {
	return runner.Merge(env, "GOTOOLCHAIN=local", "GOENV=off", "GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org", "GOPRIVATE=", "GONOPROXY=none", "GONOSUMDB=none", "GOVCS=*:off", "GOWORK=off")
}

// WarmGoModule fills only the managed dependency cache. It does not build the
// selected project, run tests, execute generators, or weaken checksum validation.
func (m *Manager) WarmGoModule(ctx context.Context, directory string) error {
	root, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	if _, err = store.Read(filepath.Join(root, "go.mod"), 4<<20); err != nil {
		return fmt.Errorf("--go-module requires a directory with go.mod")
	}
	g, err := m.ensureRuntime(ctx, "go")
	if err != nil {
		return err
	}
	env, err := m.Environment(false)
	if err != nil {
		return err
	}
	env = goDownloadEnvironment(env)
	env = runner.Merge(env, "GOFLAGS=-mod=readonly")
	_, err = m.runPreparation(ctx, runner.Request{Executable: g.Path, Args: []string{"mod", "download", "all"}, Dir: root, Env: env, Timeout: 20 * time.Minute, MaxOutput: 8 << 20})
	return err
}

// Preserve ordinary errors without exposing source/config/environment output.
func (m *Manager) runPreparation(ctx context.Context, q runner.Request) (runner.Result, error) {
	result, err := m.Executor.Run(ctx, q)
	if err != nil && m.DiagnosticDir != "" && len(result.Stderr) > 0 {
		if name, saveErr := runner.SaveStderr(m.DiagnosticDir, "prerequisite", result.Stderr); saveErr == nil {
			err = fmt.Errorf("%w (sensitive private diagnostics: %s)", err, name)
		}
	}
	return result, err
}
