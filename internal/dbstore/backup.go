package dbstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"sekscan/internal/config"
)

// BackupSQLite takes a consistent snapshot, including committed WAL contents.
// Unlike copying a live .db file, VACUUM INTO works while other readers exist.
func (s *Store) BackupSQLite(ctx context.Context, destination string) error {
	if s.dialect != "sqlite" {
		return fmt.Errorf("portable file backup is SQLite-only; use the database service's native backup for remote storage")
	}
	dest, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if err = config.WithinDirectory(filepath.Dir(dest), dest); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	// Reserve the filename exclusively. SQLite permits an existing empty file.
	f, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("cannot create backup destination (must not exist): %w", err)
	}
	if err = f.Close(); err != nil {
		os.Remove(dest)
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(dest)
		}
	}()
	if _, err = s.db.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		return fmt.Errorf("SQLite snapshot failed; source database was not modified")
	}
	f, err = os.OpenFile(dest, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	ok = true
	return nil
}
