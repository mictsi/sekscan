package scannerdb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/safearchive"
	"sekscan/internal/store"
)

type goSnapshot struct {
	Snapshot      string            `json:"snapshot"`
	DownloadedAt  time.Time         `json:"downloaded_at"`
	ArchiveSHA256 string            `json:"archive_sha256"`
	Files         map[string]string `json:"files"`
}

var goID = regexp.MustCompile(`^GO-[0-9]{4}-[0-9]+$`)
var snapshotID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// UpdateGovulncheck downloads the public bulk database, not project dependency
// data. A complete immutable snapshot is published only after validation succeeds.
func UpdateGovulncheck(ctx context.Context, c config.Config, client *http.Client) error {
	root := filepath.Join(Cache(c), "govulncheck")
	if err := config.WithinDirectory(Cache(c), root); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(root, ".update.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("govulncheck DB update is already active")
	}
	lock.Close()
	defer os.Remove(filepath.Join(root, ".update.lock"))
	b, err := deps.PublicDownload(ctx, client, "https://vuln.go.dev/vulndb.zip", 256<<20)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(b)
	id := hex.EncodeToString(hash[:])
	temp, err := os.MkdirTemp(root, ".snapshot-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if err = safearchive.Extract(ctx, b, "vulndb.zip", temp, ""); err != nil {
		return err
	}
	if err = validateGoDatabase(temp); err != nil {
		return err
	}
	files := map[string]string{}
	err = filepath.WalkDir(temp, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(temp, p)
		h, err := store.SHA256(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = h
		return nil
	})
	if err != nil {
		return err
	}
	dest := filepath.Join(root, id)
	if _, err = os.Stat(dest); os.IsNotExist(err) {
		if err = os.Rename(temp, dest); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if err = validateGoManifest(dest, files); err != nil {
			return fmt.Errorf("cached snapshot differs; remove the damaged snapshot before retrying")
		}
	}
	return store.JSON(filepath.Join(root, "current.json"), goSnapshot{Snapshot: id, DownloadedAt: time.Now().UTC(), ArchiveSHA256: id, Files: files})
}
func validateGoDatabase(root string) error {
	b, err := store.Read(filepath.Join(root, "index", "db.json"), 1<<20)
	if err != nil {
		return fmt.Errorf("Go DB index/db.json missing")
	}
	var db struct {
		Modified time.Time `json:"modified"`
	}
	if json.Unmarshal(b, &db) != nil || db.Modified.IsZero() {
		return fmt.Errorf("Go DB modification index invalid")
	}
	b, err = store.Read(filepath.Join(root, "index", "vulns.json"), 32<<20)
	if err != nil {
		return err
	}
	var entries []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(b, &entries) != nil || len(entries) == 0 {
		return fmt.Errorf("Go DB vulnerability index invalid/empty")
	}
	ids := map[string]bool{}
	for _, v := range entries {
		if !goID.MatchString(v.ID) || ids[v.ID] {
			return fmt.Errorf("Go DB duplicate/invalid ID")
		}
		ids[v.ID] = true
		b, err = store.Read(filepath.Join(root, "ID", v.ID+".json"), 8<<20)
		if err != nil {
			return fmt.Errorf("Go DB indexed vulnerability absent")
		}
		var osv struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(b, &osv) != nil || osv.ID != v.ID {
			return fmt.Errorf("Go DB OSV identity mismatch")
		}
	}
	b, err = store.Read(filepath.Join(root, "index", "modules.json"), 64<<20)
	if err != nil {
		return err
	}
	var modules []struct {
		Path  string `json:"path"`
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if json.Unmarshal(b, &modules) != nil || len(modules) == 0 {
		return fmt.Errorf("Go DB module index invalid/empty")
	}
	for _, m := range modules {
		if m.Path == "" {
			return fmt.Errorf("Go DB module path missing")
		}
		for _, v := range m.Vulns {
			if !ids[v.ID] {
				return fmt.Errorf("Go DB module index references missing advisory")
			}
		}
	}
	return nil
}
func validateGoManifest(root string, files map[string]string) error {
	if len(files) < 4 || len(files) > 100000 {
		return fmt.Errorf("invalid Go DB manifest")
	}
	count := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		count++
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("Go DB contains a symlink")
		}
		rel, _ := filepath.Rel(root, p)
		name := filepath.ToSlash(rel)
		expected, ok := files[name]
		if !ok {
			return fmt.Errorf("Go DB contains an untracked file")
		}
		if err = config.WithinDirectory(root, p); err != nil {
			return err
		}
		hash, err := store.SHA256(p)
		if err != nil {
			return err
		}
		if hash != expected {
			return fmt.Errorf("Go DB file checksum mismatch")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if count != len(files) {
		return fmt.Errorf("Go DB file missing")
	}
	return nil
}
func InspectGovulncheck(c config.Config) Status {
	root := filepath.Join(Cache(c), "govulncheck")
	s := Status{Engine: "govulncheck", Database: "vulnerability", State: "missing", Path: root, Validation: "bulk snapshot SHA256 file manifest; age measured from download, not last advisory modification"}
	if err := config.WithinDirectory(Cache(c), filepath.Join(root, "current.json")); err != nil {
		s.State = "invalid"
		s.Error = err.Error()
		return s
	}
	b, err := store.Read(filepath.Join(root, "current.json"), 16<<20)
	if err != nil {
		s.Error = "govulncheck database missing; run sekscan prepare --yes or sekscan db update"
		return s
	}
	var doc goSnapshot
	if json.Unmarshal(b, &doc) != nil || !snapshotID.MatchString(doc.Snapshot) || doc.Snapshot != doc.ArchiveSHA256 {
		s.State = "invalid"
		s.Error = "invalid govulncheck database metadata"
		return s
	}
	s.Path = filepath.Join(root, doc.Snapshot)
	s.BuiltAt = doc.DownloadedAt
	s.Schema = "Go vulnerability database v1"
	if err = config.WithinDirectory(root, s.Path); err != nil {
		s.State = "invalid"
		s.Error = err.Error()
		return s
	}
	if err = validateGoManifest(s.Path, doc.Files); err != nil {
		s.State = "invalid"
		s.Error = err.Error()
		return s
	}
	// index/db.modified indicates the most recent advisory change, not cache age.
	if err = checkAge(doc.DownloadedAt, c.MaxDBAge); err != nil {
		s.State = "stale"
		s.Error = strings.ReplaceAll(err.Error(), "build timestamp", "download timestamp")
		return s
	}
	s.State = "ready"
	return s
}
