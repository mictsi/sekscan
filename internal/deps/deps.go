// Package deps discovers external tools and installs checksum-verified upstream releases.
package deps

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/runner"
	"sekscan/internal/store"
)

var Repositories = map[string]string{"syft": "anchore/syft", "grype": "anchore/grype", "trivy": "aquasecurity/trivy", "gitleaks": "gitleaks/gitleaks", "actionlint": "rhysd/actionlint", "hadolint": "hadolint/hadolint", "zizmor": "zizmorcore/zizmor", "gosec": "securego/gosec", "uv": "astral-sh/uv"}

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
}
type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}
type Installed struct {
	Entrypoint    string            `json:"entrypoint,omitempty"`
	Files         map[string]string `json:"files,omitempty"`
	CommandArgs   []string          `json:"command_args,omitempty"`
	Verification  string            `json:"verification,omitempty"`
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Repository    string            `json:"repository"`
	Asset         string            `json:"asset"`
	ArchiveSHA256 string            `json:"archive_sha256"`
	BinarySHA256  string            `json:"binary_sha256"`
	InstalledAt   time.Time         `json:"installed_at"`
	Path          string            `json:"path"`
	GOOS          string            `json:"os,omitempty"`
	GOARCH        string            `json:"arch,omitempty"`
}
type Status struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Source  string `json:"source"`
	Error   string `json:"error,omitempty"`
}
type Manager struct {
	Tools         map[string]config.Tool
	DenyEnv       []string
	Dir           string
	Client        *http.Client
	APIBase       string
	Token         string
	GOOS          string
	GOARCH        string
	Executor      runner.Executor
	Portable      bool
	CacheDir      string
	MaxDBAge      string
	DiagnosticDir string
	LogDir        string
}

func New(dir string) *Manager {
	if dir == "" {
		dir = "bin"
	}
	c := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 8 {
			return fmt.Errorf("too many redirects")
		}
		if !trustedURL(r.URL) {
			return fmt.Errorf("redirect outside trusted release hosts")
		}
		if r.URL.Hostname() != "api.github.com" {
			r.Header.Del("Authorization")
		}
		return nil
	}}
	return &Manager{Dir: dir, Client: c, APIBase: "https://api.github.com", Token: os.Getenv("GITHUB_TOKEN"), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Executor: runner.OSExecutor{}}
}
func trustedURL(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil {
		return false
	}
	switch u.Hostname() {
	case "api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}
func binName(name, goos string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}
func (m *Manager) resolve(name string, t config.Tool) (string, string, error) {
	if config.RemovedScanner(name) {
		return "", "", fmt.Errorf("Semgrep support has been removed")
	}
	if _, ok := m.Tools[name]; !ok {
		if _, ok = Repositories[name]; !ok {
			return "", "", fmt.Errorf("unknown tool %q", name)
		}
	}
	if t.Path != "" && !m.Portable {
		p, e := filepath.Abs(t.Path)
		if e != nil {
			return "", "", e
		}
		return p, "configured", nil
	}
	if err := config.WithinDirectory(m.Dir, filepath.Join(m.Dir, name)); err != nil {
		return "", "managed", err
	}
	metadata := filepath.Join(m.Dir, name, "current.json")
	if err := config.WithinDirectory(m.Dir, metadata); err != nil {
		return "", "managed", err
	}
	if b, e := store.Read(metadata, 16<<20); e == nil {
		var installed Installed
		if e = json.Unmarshal(b, &installed); e != nil {
			return "", "", fmt.Errorf("invalid managed installation metadata for %s", name)
		}
		// Metadata cannot redirect execution outside the managed installation tree.
		if installed.Name != name || !config.ValidVersion(installed.Version) || installed.Version == "latest" {
			return "", "", fmt.Errorf("invalid managed installation identity")
		}
		if (installed.GOOS != "" && installed.GOOS != m.GOOS) || (installed.GOARCH != "" && installed.GOARCH != m.GOARCH) {
			return "", "managed", fmt.Errorf("%s belongs to a different OS/architecture; run prepare on this platform", name)
		}
		if t.Version != "" && t.Version != "latest" && strings.TrimPrefix(t.Version, "v") != strings.TrimPrefix(installed.Version, "v") {
			return "", "", fmt.Errorf("%s installed version differs from configured pin; run deps install", name)
		}
		if t.SHA256 != "" && !strings.EqualFold(t.SHA256, installed.ArchiveSHA256) {
			return "", "", fmt.Errorf("%s installed archive does not match configured SHA256 pin", name)
		}
		entry := m.executableName(name)
		if installed.Entrypoint != "" {
			entry = installed.Entrypoint
			if !safeBundlePath(entry) {
				return "", "managed", fmt.Errorf("invalid bundle entrypoint")
			}
		}
		base := filepath.Join(m.Dir, name, installed.Version)
		p := filepath.Join(base, filepath.FromSlash(entry))
		if len(installed.Files) > 0 {
			if err := verifyBundle(base, installed.Files); err != nil {
				return "", "managed", err
			}
		}
		if err := config.WithinDirectory(m.Dir, p); err != nil {
			return "", "managed", err
		}
		actual, e := store.SHA256(p)
		if e != nil {
			return "", "", e
		}
		if actual != installed.BinarySHA256 {
			return "", "", fmt.Errorf("%s managed executable checksum mismatch; reinstall", name)
		}
		p, e = filepath.Abs(p)
		return p, "managed", e
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", "", e
	}
	if m.Portable {
		return "", "managed", fmt.Errorf("%s is not installed in workspace bin; run sekscan deps install %s --yes --diagnostic-stderr with the same --home/--config and check its exit status (PATH copies are intentionally ignored)", name, name)
	}
	p, e := exec.LookPath(m.executableName(name))
	if e != nil {
		return "", "", fmt.Errorf("%s not installed; run sekscan deps install --yes", name)
	}
	p, e = filepath.Abs(p)
	return p, "PATH", e
}

var versionRE = regexp.MustCompile(`\bv?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)\b`)

func ExtractVersion(b []byte) string {
	if x := versionRE.FindSubmatch(b); len(x) > 1 {
		return string(x[1])
	}
	return "unknown"
}
func (m *Manager) Inspect(ctx context.Context, name string, t config.Tool) Status {
	s := Status{Name: name}
	p, src, e := m.resolve(name, t)
	s.Path = p
	s.Source = src
	if e != nil {
		s.Error = e.Error()
		return s
	}
	st, e := os.Stat(p)
	if e != nil || !st.Mode().IsRegular() {
		s.Error = "executable is missing or is not a regular file"
		return s
	}
	hash, e := store.SHA256(p)
	if e != nil {
		s.Error = e.Error()
		return s
	}
	s.SHA256 = hash
	args := []string{"version"}
	if name == "trivy" {
		args = []string{"--version"}
	}
	if name == "actionlint" || name == "gosec" || name == "govulncheck" {
		args = []string{"-version"}
	}
	if name == "hadolint" || name == "zizmor" || name == "uv" {
		args = []string{"--version"}
	}
	if len(t.VersionArgs) > 0 {
		args = t.VersionArgs
	}
	temp, e := os.MkdirTemp("", "sekscan-version-")
	if e != nil {
		s.Error = e.Error()
		return s
	}
	defer os.RemoveAll(temp)
	// govulncheck contacts its configured database even for -version. Point its
	// version-only client at a private local index, including before DB preparation.
	if name == "govulncheck" && len(args) == 1 && args[0] == "-version" {
		probeRoot := filepath.Join(temp, "version-db")
		// The local client recognizes v1 by index/modules.json, even for -version.
		// This empty database is probe-only; it must never be used for a scan.
		for filename, body := range map[string]string{
			"db.json":      `{"modified":"2000-01-01T00:00:00Z"}`,
			"modules.json": `[]`,
			"vulns.json":   `[]`,
		} {
			if e = store.Atomic(filepath.Join(probeRoot, "index", filename), []byte(body), 0600); e != nil {
				s.Error = e.Error()
				return s
			}
		}
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(probeRoot)}
		if !strings.HasPrefix(u.Path, "/") {
			u.Path = "/" + u.Path
		}
		args = []string{"-db", u.String(), "-version"}
	}
	env, e := m.Environment(true)
	if e != nil {
		s.Error = e.Error()
		return s
	}
	invocationArgs, e := m.InvocationArgs(name, t, args)
	if e != nil {
		s.Error = e.Error()
		return s
	}
	result, e := m.Executor.Run(ctx, runner.Request{Executable: p, Args: invocationArgs, Dir: temp, Env: env, Timeout: 15 * time.Second, MaxOutput: 1 << 20})
	if e != nil {
		s.Error = name + " version probe failed: " + e.Error()
		if m.DiagnosticDir != "" && len(result.Stderr) > 0 {
			if file, saveErr := runner.SaveDiagnostic(m.DiagnosticDir, name, "version-stderr", result.Stderr); saveErr == nil {
				s.Error += " (sensitive private diagnostics: " + file + ")"
			}
		}
		return s
	}
	versionOutput := append(append([]byte{}, result.Stdout...), result.Stderr...)
	s.Version = ExtractToolVersion(name, versionOutput)
	if s.Version == "unknown" {
		s.Error = "could not parse tool version"
		return s
	}
	if t.Version != "" && t.Version != "latest" && strings.TrimPrefix(t.Version, "v") != s.Version {
		s.Error = "executable version does not match configured pin"
	}
	return s
}
func (m *Manager) Release(ctx context.Context, name, version string) (Release, error) {
	var release Release
	repo, ok := m.repository(name)
	if !ok {
		return release, fmt.Errorf("unsupported tool %q", name)
	}
	if !config.ValidVersion(version) {
		return release, fmt.Errorf("invalid release version")
	}
	endpoint := m.APIBase + "/repos/" + repo + "/releases/"
	if version == "latest" {
		endpoint += "latest"
	} else {
		endpoint += "tags/v" + strings.TrimPrefix(version, "v")
	}
	b, e := m.get(ctx, endpoint, 8<<20, true)
	if e != nil {
		return release, e
	}
	if e = json.Unmarshal(b, &release); e != nil {
		return release, fmt.Errorf("release response: %w", e)
	}
	if !config.ValidVersion(release.Tag) || release.Tag == "latest" || release.Draft {
		return release, fmt.Errorf("upstream returned invalid release")
	}
	if version == "latest" && release.Prerelease {
		return release, fmt.Errorf("refusing prerelease as latest")
	}
	if version != "latest" && strings.TrimPrefix(version, "v") != strings.TrimPrefix(release.Tag, "v") {
		return release, fmt.Errorf("upstream release does not match requested version")
	}
	return release, nil
}
func AssetName(name, version, goos, arch string) (string, error) {
	if goos != "linux" && goos != "darwin" && goos != "windows" {
		return "", fmt.Errorf("unsupported OS %s", goos)
	}
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("unsupported architecture %s", arch)
	}
	v := strings.TrimPrefix(version, "v")
	extension := ".tar.gz"
	if goos == "windows" {
		extension = ".zip"
	}
	switch name {
	case "syft", "grype", "actionlint":
		return fmt.Sprintf("%s_%s_%s_%s%s", name, v, goos, arch, extension), nil
	case "gosec":
		return fmt.Sprintf("gosec_%s_%s_%s.tar.gz", v, goos, arch), nil
	case "hadolint":
		if goos == "windows" && arch != "amd64" {
			return "", fmt.Errorf("Hadolint has no native Windows ARM64 release asset")
		}
		o := map[string]string{"linux": "linux", "darwin": "macos", "windows": "windows"}[goos]
		a := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[arch]
		suffix := ""
		if goos == "windows" {
			suffix = ".exe"
		}
		return "hadolint-" + o + "-" + a + suffix, nil
	case "zizmor", "uv":
		if goos == "windows" && arch != "amd64" {
			return "", fmt.Errorf("no configured native Windows ARM64 asset for %s", name)
		}
		a := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[arch]
		o := map[string]string{"linux": "unknown-linux-gnu", "darwin": "apple-darwin", "windows": "pc-windows-msvc"}[goos]
		return name + "-" + a + "-" + o + extension, nil
	case "gitleaks":
		a := arch
		if a == "amd64" {
			a = "x64"
		}
		return fmt.Sprintf("%s_%s_%s_%s%s", name, v, goos, a, extension), nil
	case "trivy":
		o := map[string]string{"linux": "Linux", "darwin": "macOS", "windows": "windows"}[goos]
		a := map[string]string{"amd64": "64bit", "arm64": "ARM64"}[arch]
		return fmt.Sprintf("trivy_%s_%s-%s%s", v, o, a, extension), nil
	default:
		return "", fmt.Errorf("unsupported tool %q", name)
	}
}
func (m *Manager) get(ctx context.Context, address string, max int64, api bool) ([]byte, error) {
	u, e := url.Parse(address)
	if e != nil {
		return nil, e
	}
	// Custom APIBase is for injected local test servers; production always uses HTTPS.
	if m.APIBase == "https://api.github.com" && !trustedURL(u) {
		return nil, fmt.Errorf("untrusted download URL")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "sekscan")
	if api {
		req.Header.Set("Accept", "application/vnd.github+json")
		if m.Token != "" && u.Hostname() == "api.github.com" {
			req.Header.Set("Authorization", "Bearer "+m.Token)
		}
	}
	response, e := m.Client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("upstream request failed: %w", e)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned HTTP %d; verify version and GitHub API rate limits", response.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("download exceeds limit")
	}
	return b, nil
}
func Checksum(manifest []byte, filename string) (string, error) {
	scan := bufio.NewScanner(bytes.NewReader(manifest))
	found := ""
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) != 2 {
			continue
		}
		if strings.TrimPrefix(fields[1], "*") != filename {
			continue
		}
		if len(fields[0]) != 64 {
			return "", fmt.Errorf("invalid checksum")
		}
		if _, e := hex.DecodeString(fields[0]); e != nil {
			return "", e
		}
		if found != "" {
			return "", fmt.Errorf("duplicate checksum entry")
		}
		found = strings.ToLower(fields[0])
	}
	if e := scan.Err(); e != nil {
		return "", e
	}
	if found == "" {
		return "", fmt.Errorf("asset is absent from checksum manifest")
	}
	return found, nil
}
func (m *Manager) Install(ctx context.Context, name string, t config.Tool) (Installed, error) {
	var installed Installed
	if config.RemovedScanner(name) {
		return installed, fmt.Errorf("Semgrep support has been removed")
	}
	if t.Path != "" && !m.Portable {
		return installed, fmt.Errorf("%s has an explicit path; refusing to overwrite an externally managed executable", name)
	}
	if t.Version == "" {
		t.Version = "latest"
	}
	if t.Install == nil {
		switch name {
		case "go":
			return m.installGo(ctx, t)
		case "govulncheck":
			return m.installGovulncheck(ctx, t)
		}
	}
	r, e := m.Release(ctx, name, t.Version)
	if e != nil {
		return installed, e
	}
	assetName, checksumName, e := m.assetNames(name, r.Tag)
	if e != nil {
		return installed, e
	}
	var archive, checksums Asset
	for _, a := range r.Assets {
		if a.Name == assetName {
			archive = a
		}
		if a.Name == checksumName {
			checksums = a
		}
	}
	if archive.URL == "" {
		return installed, fmt.Errorf("release %s has no %s asset; platform may not be supported", r.Tag, assetName)
	}
	expected := ""
	verification := "upstream checksum manifest"
	if checksums.URL != "" {
		manifest, err := m.get(ctx, checksums.URL, 2<<20, false)
		if err != nil {
			return installed, err
		}
		expected, e = Checksum(manifest, assetName)
		if e != nil {
			return installed, e
		}
	} else if name == "hadolint" && t.Install == nil {
		// Older releases published one checksum file per executable.
		for _, a := range r.Assets {
			if a.Name == assetName+".sha256" {
				checksums = a
			}
		}
		if checksums.URL != "" {
			manifest, err := m.get(ctx, checksums.URL, 2<<20, false)
			if err != nil {
				return installed, err
			}
			expected, e = Checksum(manifest, assetName)
			if e != nil {
				return installed, e
			}
		}
	}
	if expected == "" && (name == "zizmor" || name == "uv") && t.Install == nil {
		expected = strings.TrimPrefix(archive.Digest, "sha256:")
		if len(expected) != 64 || !strings.HasPrefix(archive.Digest, "sha256:") {
			return installed, fmt.Errorf("upstream has no SHA256 release-asset digest; refuse unverified installation")
		}
		if _, err := hex.DecodeString(expected); err != nil {
			return installed, fmt.Errorf("invalid release-asset digest")
		}
		verification = "GitHub release-asset SHA256 digest"
	}
	if expected == "" {
		return installed, fmt.Errorf("release has no expected checksum manifest; refusing unverified installation")
	}
	if t.SHA256 != "" && !strings.EqualFold(t.SHA256, expected) {
		return installed, fmt.Errorf("upstream checksum differs from independently configured SHA256 pin")
	}
	b, e := m.get(ctx, archive.URL, 512<<20, false)
	if e != nil {
		return installed, e
	}
	hash := sha256.Sum256(b)
	actual := hex.EncodeToString(hash[:])
	if actual != expected {
		return installed, fmt.Errorf("archive SHA256 mismatch; installation aborted")
	}
	if archive.Digest != "" && archive.Digest != "sha256:"+actual {
		return installed, fmt.Errorf("GitHub asset digest differs from checksum manifest")
	}
	var exe []byte
	if name == "hadolint" && t.Install == nil {
		exe = b
		if len(exe) < 2 {
			return installed, fmt.Errorf("empty Hadolint executable")
		}
	} else {
		wanted := m.executableName(name)
		if name == "uv" && strings.HasSuffix(assetName, ".tar.gz") {
			wanted = strings.TrimSuffix(assetName, ".tar.gz") + "/" + wanted
		}
		exe, e = ExtractExecutable(b, assetName, wanted)
	}
	if e != nil {
		return installed, e
	}
	root := filepath.Join(m.Dir, name)
	if e = config.WithinDirectory(m.Dir, filepath.Join(root, strings.TrimPrefix(r.Tag, "v"), m.executableName(name))); e != nil {
		return installed, e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return installed, e
	}
	lock, e := os.OpenFile(filepath.Join(root, ".install.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return installed, fmt.Errorf("another installation may be active: %w", e)
	}
	lock.Close()
	defer os.Remove(filepath.Join(root, ".install.lock"))
	version := strings.TrimPrefix(r.Tag, "v")
	destination := filepath.Join(root, version, m.executableName(name))
	if e = store.Atomic(destination, exe, 0700); e != nil {
		return installed, e
	}
	binaryHash := sha256.Sum256(exe)
	repo, _ := m.repository(name)
	installed = Installed{Name: name, Version: version, Repository: repo, Asset: assetName, ArchiveSHA256: actual, BinarySHA256: hex.EncodeToString(binaryHash[:]), InstalledAt: time.Now().UTC(), Path: filepath.ToSlash(filepath.Join(name, version, m.executableName(name))), GOOS: m.GOOS, GOARCH: m.GOARCH, Verification: verification}
	if e = store.JSON(filepath.Join(root, "current.json"), installed); e != nil {
		return installed, e
	}
	return installed, nil
}

// Only the exact root-level executable is extracted; no archive paths are created.
func ExtractExecutable(data []byte, filename, wanted string) ([]byte, error) {
	const max = 512 << 20
	var out []byte
	accept := func(name string, mode os.FileMode, size int64, r io.Reader) error {
		name = strings.TrimPrefix(name, "./")
		if name != wanted {
			return nil
		}
		if !mode.IsRegular() || size < 1 || size > max {
			return fmt.Errorf("invalid executable archive member")
		}
		if out != nil {
			return fmt.Errorf("duplicate executable archive member")
		}
		b, e := io.ReadAll(io.LimitReader(r, max+1))
		if e != nil {
			return e
		}
		if len(b) > max || int64(len(b)) != size {
			return fmt.Errorf("invalid executable size")
		}
		out = b
		return nil
	}
	if strings.HasSuffix(filename, ".zip") {
		z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if e != nil {
			return nil, e
		}
		if len(z.File) > 10000 {
			return nil, fmt.Errorf("too many archive members")
		}
		for _, f := range z.File {
			if path.Clean(f.Name) != wanted {
				continue
			}
			r, e := f.Open()
			if e != nil {
				return nil, e
			}
			e = accept(f.Name, f.Mode(), int64(f.UncompressedSize64), r)
			r.Close()
			if e != nil {
				return nil, e
			}
		}
	} else if strings.HasSuffix(filename, ".tar.gz") {
		g, e := gzip.NewReader(bytes.NewReader(data))
		if e != nil {
			return nil, e
		}
		defer g.Close()
		// Bound decompression of non-executable members too.
		tr := tar.NewReader(io.LimitReader(g, 1<<30))
		count := 0
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, e
			}
			count++
			if count > 10000 {
				return nil, fmt.Errorf("too many archive members")
			}
			if e = accept(h.Name, h.FileInfo().Mode(), h.Size, tr); e != nil {
				return nil, e
			}
		}
	} else {
		return nil, fmt.Errorf("unsupported release archive")
	}
	if out == nil {
		return nil, fmt.Errorf("executable not found in archive")
	}
	return out, nil
}
