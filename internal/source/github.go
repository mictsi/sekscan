package source

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"sekscan/internal/model"
	"sekscan/internal/store"
)

const (
	defaultArchiveLimit int64 = 512 << 20
	defaultSourceLimit  int64 = 2 << 30
	defaultFileLimit          = 200000
)

type Client struct {
	// GitCommand is an optional command runner for tests.
	GitCommand                      func(context.Context, string, ...string) ([]byte, error)
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
	root := filepath.Join(c.Cache, "sources", "github", model.Hash(repo.Key())[:24])
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create source cache: %w", err)
	}
	if offline {
		if !commitPattern.MatchString(ref) {
			return nil, fmt.Errorf("offline GitHub scans require an exact 40-character commit SHA and a previously cached archive")
		}
		s.Revision = strings.ToLower(ref)
	} else {
		revision, resolved, err := c.prepareGit(ctx, repo, ref, root)
		if err != nil {
			return nil, err
		}
		s.Revision, s.ResolvedRef = revision, resolved
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
		return nil, fmt.Errorf("source archive was not prepared")
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
		// Git archive includes a global PAX header carrying the commit ID.
		// archive/tar has already parsed it; it is not a filesystem entry.
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
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
