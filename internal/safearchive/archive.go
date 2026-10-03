// Package safearchive extracts bounded, regular-file-only runtime/database bundles.
package safearchive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Extract requires a newly created destination. It never follows archive links.
func Extract(ctx context.Context, data []byte, filename, root, prefix string) error {
	const maxFiles = 100000
	const maxFile int64 = 512 << 20
	const maxTotal int64 = 2 << 30
	count := 0
	var total int64
	seen := map[string]bool{}
	write := func(name string, size int64, mode os.FileMode, dir bool, r io.Reader) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		name = strings.TrimSuffix(name, "/")
		if name == prefix && dir {
			return nil
		}
		if prefix != "" {
			if !strings.HasPrefix(name, prefix+"/") {
				return fmt.Errorf("unexpected archive root")
			}
			name = strings.TrimPrefix(name, prefix+"/")
		}
		if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\:\x00") || path.Clean(name) != name {
			return fmt.Errorf("unsafe archive path")
		}
		if seen[name] {
			return fmt.Errorf("duplicate archive path")
		}
		seen[name] = true
		count++
		if count > maxFiles {
			return fmt.Errorf("archive has too many entries")
		}
		dest := filepath.Join(root, filepath.FromSlash(name))
		if dir {
			return os.MkdirAll(dest, 0700)
		}
		if size < 0 || size > maxFile || total+size > maxTotal {
			return fmt.Errorf("archive exceeds extraction limit")
		}
		total += size
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return err
		}
		perms := os.FileMode(0600)
		if mode&0111 != 0 {
			perms = 0700
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perms)
		if err != nil {
			return err
		}
		n, err := io.Copy(f, io.LimitReader(r, size+1))
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if n != size {
			return fmt.Errorf("archive entry length mismatch")
		}
		return nil
	}
	if strings.HasSuffix(filename, ".zip") {
		z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
		for _, f := range z.File {
			if !f.Mode().IsRegular() && !f.FileInfo().IsDir() {
				return fmt.Errorf("archive links/special files are not permitted")
			}
			r, err := f.Open()
			if err != nil {
				return err
			}
			err = write(f.Name, int64(f.UncompressedSize64), f.Mode(), f.FileInfo().IsDir(), r)
			r.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	if !strings.HasSuffix(filename, ".tar.gz") {
		return fmt.Errorf("unsupported archive format")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeDir {
			return fmt.Errorf("archive links/special files are not permitted")
		}
		if err = write(h.Name, h.Size, h.FileInfo().Mode(), h.Typeflag == tar.TypeDir, tr); err != nil {
			return err
		}
	}
}
