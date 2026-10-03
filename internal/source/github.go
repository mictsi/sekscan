package source

import (
	"archive/tar"
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
	"path"
	"path/filepath"
	"strings"
	"time"

	"sekscan/internal/model"
	"sekscan/internal/store"
)

const (
	maxMetadata               = 4 << 20
	defaultArchiveLimit int64 = 512 << 20
	defaultSourceLimit  int64 = 2 << 30
	defaultFileLimit          = 200000
	apiVersion                = "2026-03-10"
)

type Client struct {
	// Transport can be injected for tests; request and redirect destinations remain allowlisted.
	Transport                       http.RoundTripper
	Cache                           string
	Token                           string
	MaxArchiveBytes, MaxSourceBytes int64
	MaxFiles                        int
}
type Snapshot struct {
	Path          string
	Repository    string
	RequestedRef  string
	ResolvedRef   string
	Revision      string
	ArchiveSHA256 string
	Warnings      []string
	Complete      bool
	cleanup       string
}

func (s *Snapshot) Close() error {
	if s.cleanup != "" {
		return os.RemoveAll(s.cleanup)
	}
	return nil
}

type cachedArchive struct {
	Repository   string    `json:"repository"`
	Revision     string    `json:"revision"`
	SHA256       string    `json:"sha256"`
	DownloadedAt time.Time `json:"downloaded_at"`
}

func allowedURL(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && u.Port() == "" && (u.Host == "api.github.com" || u.Host == "codeload.github.com")
}
func (c *Client) httpClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Minute, Transport: c.Transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !allowedURL(req.URL) {
			return fmt.Errorf("GitHub redirect destination is not allowed")
		}
		// Archive redirects often contain an expiring authorization query. Never log
		// them, and never forward the API token to the content host.
		req.Header.Del("Authorization")
		if req.URL.Host == "api.github.com" && c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		return nil
	}}
}
func (c *Client) request(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", "sekscan-source")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("GitHub request failed (network, TLS, timeout, or blocked redirect); request details withheld")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		switch resp.StatusCode {
		case 401:
			return nil, fmt.Errorf("GitHub authentication failed; check the selected token environment variable")
		case 403, 429:
			return nil, fmt.Errorf("GitHub denied or rate-limited the request (HTTP %d); check token permissions and rate limits", resp.StatusCode)
		case 404:
			return nil, fmt.Errorf("GitHub repository/ref not found or not accessible to the token (HTTP 404)")
		default:
			return nil, fmt.Errorf("GitHub request returned HTTP %d", resp.StatusCode)
		}
	}
	return resp, nil
}
func (c *Client) getJSON(ctx context.Context, endpoint string, out any) error {
	r, e := c.request(ctx, endpoint)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, maxMetadata+1))
	if e != nil {
		return fmt.Errorf("read GitHub metadata failed")
	}
	if len(b) > maxMetadata {
		return fmt.Errorf("GitHub metadata exceeds limit")
	}
	if e = json.Unmarshal(b, out); e != nil {
		return fmt.Errorf("invalid GitHub metadata")
	}
	return nil
}
func (c *Client) Acquire(ctx context.Context, repo Repository, ref, subdir string, offline bool) (*Snapshot, error) {
	if err := ValidateRef(ref); err != nil {
		return nil, err
	}
	subdir, err := ValidateSubdir(subdir)
	if err != nil {
		return nil, err
	}
	if c.Cache == "" {
		return nil, fmt.Errorf("source cache directory is required")
	}
	s := &Snapshot{Repository: repo.URL(), RequestedRef: ref, ResolvedRef: ref, Warnings: []string{}, Complete: true}
	base := "/repos/" + repo.Owner + "/" + repo.Name
	if offline {
		if !commitPattern.MatchString(ref) {
			return nil, fmt.Errorf("offline GitHub scans require an exact 40-character commit SHA and a previously cached archive; branch names are not resolved offline")
		}
		s.Revision = strings.ToLower(ref)
	} else {
		if ref == "" {
			var info struct {
				DefaultBranch string `json:"default_branch"`
			}
			if err = c.getJSON(ctx, base, &info); err != nil {
				return nil, err
			}
			if info.DefaultBranch == "" || ValidateRef(info.DefaultBranch) != nil {
				return nil, fmt.Errorf("GitHub repository has no valid default branch")
			}
			ref = info.DefaultBranch
			s.ResolvedRef = ref
		}
		var commit struct {
			SHA string `json:"sha"`
		}
		if err = c.getJSON(ctx, base+"/commits/"+url.PathEscape(ref), &commit); err != nil {
			return nil, err
		}
		if !commitPattern.MatchString(commit.SHA) {
			return nil, fmt.Errorf("GitHub did not return a full commit SHA")
		}
		s.Revision = strings.ToLower(commit.SHA)
	}
	root := filepath.Join(c.Cache, "sources", "github", model.Hash(repo.Key())[:24])
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create source cache: %w", err)
	}
	archive := filepath.Join(root, s.Revision+".tar.gz")
	meta := archive + ".json"
	cached := cachedArchive{}
	mb, readErr := store.Read(meta, 1<<20)
	if readErr == nil {
		if err = json.Unmarshal(mb, &cached); err != nil || cached.Repository != repo.URL() || cached.Revision != s.Revision || len(cached.SHA256) != 64 {
			return nil, fmt.Errorf("invalid source cache metadata; remove this cached archive and prepare it again")
		}
		info, e := os.Lstat(archive)
		if e != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("cached source archive is missing or is not a regular file")
		}
		digest, e := store.SHA256(archive)
		if e != nil || digest != cached.SHA256 {
			return nil, fmt.Errorf("source archive checksum mismatch; cache was not used")
		}
	} else {
		if !os.IsNotExist(readErr) {
			return nil, fmt.Errorf("source cache metadata is unreadable")
		}
		if offline {
			return nil, fmt.Errorf("source archive is not cached; run github mode online for this exact commit first")
		}
		lock, e := os.OpenFile(archive+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, fmt.Errorf("source archive is being prepared; retry after the other operation completes")
		}
		lock.Close()
		defer os.Remove(archive + ".lock")
		digest, e := c.download(ctx, base+"/tarball/"+s.Revision, archive)
		if e != nil {
			return nil, e
		}
		cached = cachedArchive{Repository: repo.URL(), Revision: s.Revision, SHA256: digest, DownloadedAt: time.Now().UTC()}
		if e = store.JSON(meta, cached); e != nil {
			return nil, e
		}
	}
	s.ArchiveSHA256 = cached.SHA256
	temp, err := os.MkdirTemp(root, "checkout-")
	if err != nil {
		return nil, err
	}
	s.cleanup = temp
	maxSource := c.MaxSourceBytes
	if maxSource <= 0 {
		maxSource = defaultSourceLimit
	}
	maxFiles := c.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultFileLimit
	}
	f, err := os.Open(archive)
	if err != nil {
		s.Close()
		return nil, err
	}
	warnings, err := extract(ctx, f, temp, maxSource, maxFiles)
	f.Close()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("extract GitHub source: %w", err)
	}
	s.Warnings = append(s.Warnings, warnings...)
	s.Complete = len(warnings) == 0
	s.Path = filepath.Join(temp, filepath.FromSlash(subdir))
	info, err := os.Stat(s.Path)
	if err != nil || !info.IsDir() {
		s.Close()
		return nil, fmt.Errorf("requested repository subdir does not exist or is not a directory")
	}
	s.Warnings = append(s.Warnings, "GitHub mode scans a commit snapshot, not Git history. Submodules, unresolved LFS objects, dependency installs and build outputs are not fetched or executed.")
	return s, nil
}
func (c *Client) download(ctx context.Context, endpoint, dest string) (string, error) {
	r, err := c.request(ctx, endpoint)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	max := c.MaxArchiveBytes
	if max <= 0 {
		max = defaultArchiveLimit
	}
	if r.ContentLength > max {
		return "", fmt.Errorf("GitHub archive exceeds download limit")
	}
	f, err := os.CreateTemp(filepath.Dir(dest), "archive-*.part")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, max+1))
	if err != nil {
		return "", fmt.Errorf("GitHub archive download interrupted")
	}
	if n > max {
		return "", fmt.Errorf("GitHub archive exceeds download limit")
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(f.Name(), dest); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extract(ctx context.Context, in io.Reader, dest string, maxBytes int64, maxFiles int) ([]string, error) {
	gz, err := gzip.NewReader(in)
	if err != nil {
		return nil, fmt.Errorf("invalid gzip archive")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	root := ""
	seen := map[string]bool{}
	var expanded int64
	count, links, lfs := 0, 0, 0
	modules := false
	warnings := []string{}
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("invalid tar archive")
		}
		count++
		if count > maxFiles {
			return nil, fmt.Errorf("archive exceeds %d entries", maxFiles)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\:\x00") {
			return nil, fmt.Errorf("unsafe archive path")
		}
		parts := strings.Split(name, "/")
		for _, part := range parts {
			if part == ".." || part == "." || part == "" {
				return nil, fmt.Errorf("unsafe archive traversal")
			}
		}
		if root == "" {
			root = parts[0]
		}
		if parts[0] != root {
			return nil, fmt.Errorf("archive has multiple roots")
		}
		if len(parts) == 1 {
			if h.Typeflag != tar.TypeDir {
				return nil, fmt.Errorf("archive root is not a directory")
			}
			continue
		}
		rel := path.Join(parts[1:]...)
		key := strings.ToLower(rel)
		if seen[key] {
			return nil, fmt.Errorf("archive has duplicate or case-colliding paths")
		}
		seen[key] = true
		target := filepath.Join(dest, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(target, 0700); e != nil {
				return nil, fmt.Errorf("create archive directory: %w", e)
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > maxBytes-expanded {
				return nil, fmt.Errorf("archive exceeds expanded-size limit")
			}
			expanded += h.Size
			if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
				return nil, e
			}
			f, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return nil, fmt.Errorf("create archive file: %w", e)
			}
			// Probe a bounded prefix for Git LFS pointers before streaming the rest.
			prefix := make([]byte, min(h.Size, 256))
			_, e = io.ReadFull(tr, prefix)
			if e == nil {
				_, e = f.Write(prefix)
			}
			if e == nil {
				_, e = io.Copy(f, tr)
			}
			closeErr := f.Close()
			if e != nil || closeErr != nil {
				return nil, fmt.Errorf("extract source file failed")
			}
			if strings.HasPrefix(string(prefix), "version https://git-lfs.github.com/spec/v1\n") {
				lfs++
			}
			if path.Base(rel) == ".gitmodules" {
				modules = true
			}
		case tar.TypeSymlink, tar.TypeLink:
			links++ // Never materialize archive links.
		default:
			return nil, fmt.Errorf("unsupported archive entry type")
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("empty GitHub archive")
	}
	// Drain gzip so a corrupt trailer cannot be accepted merely because tar ended.
	if n, e := io.Copy(io.Discard, io.LimitReader(gz, (1<<20)+1)); e != nil || n > 1<<20 {
		return nil, fmt.Errorf("invalid gzip checksum")
	}
	if links > 0 {
		warnings = append(warnings, fmt.Sprintf("Source acquisition skipped %d symbolic/hard links. Source coverage is incomplete.", links))
	}
	if lfs > 0 {
		warnings = append(warnings, fmt.Sprintf("Source contains %d unresolved Git LFS pointers. Source coverage is incomplete.", lfs))
	}
	if modules {
		warnings = append(warnings, "Source contains .gitmodules; submodule content is not fetched. Source coverage is incomplete.")
	}
	return warnings, nil
}
