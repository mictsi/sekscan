package dbstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteBackupConsistentAndNoOverwrite(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t)
	p, r := fixture(t)
	artifacts := []Artifact{{Name: "sbom.cdx.json", Content: []byte(`{"bomFormat":"CycloneDX"}`)}}
	if err := s.Save(ctx, p, r, artifacts); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snapshot.db")
	if err := s.BackupSQLite(ctx, dest); err != nil {
		t.Fatal(err)
	}
	cfg := s.settings
	cfg.Path = dest
	b, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	got, err := b.Load(ctx, p.Namespace, r.ID)
	if err != nil || got.ID != r.ID {
		t.Fatal(got, err)
	}
	a, err := b.Artifacts(ctx, p.Namespace, r.ID)
	if err != nil || len(a) != 1 {
		t.Fatal(a, err)
	}
	if err = s.BackupSQLite(ctx, dest); err == nil {
		t.Fatal("existing backup overwritten")
	}
	before, _ := os.Stat(s.settings.Path)
	if err = s.BackupSQLite(ctx, s.settings.Path); err == nil {
		t.Fatal("source overwritten")
	}
	after, _ := os.Stat(s.settings.Path)
	if before.Size() != after.Size() {
		t.Fatal("source damaged")
	}
	s2 := &Store{dialect: "postgres"}
	if err = s2.BackupSQLite(ctx, filepath.Join(t.TempDir(), "no.db")); err == nil {
		t.Fatal("remote store exported as file")
	}
}
