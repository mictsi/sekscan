package dbstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sekscan/internal/config"
	"sekscan/internal/model"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (config.Project, *model.Report) {
	t.Helper()
	b, e := os.ReadFile("../../examples/demo-report/results.json")
	if e != nil {
		t.Fatal(e)
	}
	var r model.Report
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	p := config.Project{Namespace: "testing", Key: "demo", Name: "Demo"}
	r.Namespace = p.Namespace
	r.ProjectKey = p.Key
	return p, &r
}
func sqliteStore(t *testing.T) *Store {
	t.Helper()
	c := config.Default().Storage
	c.Path = filepath.Join(t.TempDir(), "app.db")
	s, e := Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if e = s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestSQLiteRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t)
	p, r := fixture(t)
	a := []Artifact{{Name: "sbom.cdx.json", Content: []byte(`{"bomFormat":"CycloneDX"}`)}}
	if e := s.Save(ctx, p, r, a); e != nil {
		t.Fatal(e)
	}
	if e := s.Save(ctx, p, r, a); e != nil {
		t.Fatal("idempotent save", e)
	}
	if e := s.Save(ctx, p, r, []Artifact{{Name: "sbom.cdx.json", Content: []byte(`{"changed":true}`)}}); !errors.Is(e, ErrConflict) {
		t.Fatal("changed immutable artifact accepted", e)
	}
	got, e := s.Load(ctx, p.Namespace, r.ID)
	if e != nil {
		t.Fatal(e)
	}
	if encode(got) != encode(r) {
		t.Fatal("snapshot changed")
	}
	if _, e = s.Load(ctx, "other", r.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("namespace leakage", e)
	}
	list, e := s.List(ctx, Filter{Namespace: p.Namespace, Query: "dem", Limit: 10})
	if e != nil || len(list) != 1 {
		t.Fatal(list, e)
	}
	if list, e = s.List(ctx, Filter{Namespace: p.Namespace, Query: "%"}); e != nil || len(list) != 0 {
		t.Fatal("wildcard not escaped", list, e)
	}
	artifacts, e := s.Artifacts(ctx, p.Namespace, r.ID)
	if e != nil || len(artifacts) != 1 || string(artifacts[0].Content) != string(a[0].Content) {
		t.Fatal(artifacts, e)
	}
	r.Revision = "modified"
	if e = s.Save(ctx, p, r, a); !errors.Is(e, ErrConflict) {
		t.Fatal("overwrote immutable report", e)
	}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal("migration not idempotent", e)
	}
	if v, e := s.Status(ctx); e != nil || v != 1 {
		t.Fatal(v, e)
	}
}
func TestSQLiteRollbackAndForeignKeys(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t)
	p, r := fixture(t)
	// Fail during the transaction rather than before it to check rollback of all parent records.
	_, e := s.db.Exec(`CREATE TRIGGER reject_components BEFORE INSERT ON sekscan_components BEGIN SELECT RAISE(ABORT,'test failure'); END;`)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Save(ctx, p, r, nil); e == nil {
		t.Fatal("write should fail")
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM sekscan_scans").Scan(&count)
	if count != 0 {
		t.Fatal("partial scan persisted")
	}
	s.db.QueryRow("SELECT COUNT(*) FROM sekscan_projects").Scan(&count)
	if count != 0 {
		t.Fatal("partial project persisted")
	}
	if _, e = s.db.Exec(`INSERT INTO sekscan_artifacts(scan_id,name,media_type,sha256,size_bytes,content) VALUES('missing','x','x','x',1,X'00')`); e == nil {
		t.Fatal("foreign keys not enforced")
	}
}
func TestSQLiteConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t)
	p, r := fixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := *r
			rr.ID = model.Hash(r.ID, string(rune('a'+i)))
			errs <- s.Save(ctx, p, &rr, nil)
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	list, e := s.List(ctx, Filter{Namespace: p.Namespace})
	if e != nil || len(list) != 8 {
		t.Fatal(len(list), e)
	}
}
func TestMigrationChecksum(t *testing.T) {
	s := sqliteStore(t)
	if _, e := s.db.Exec("UPDATE sekscan_schema_migrations SET checksum='tampered'"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(context.Background()); e == nil {
		t.Fatal("tampered migration accepted")
	}
}
func TestArtifactValidation(t *testing.T) {
	s := sqliteStore(t)
	p, r := fixture(t)
	for _, a := range []Artifact{{Name: "../../escape", Content: []byte("{}")}, {Name: "sbom.cdx.json", Content: []byte("bad")}} {
		if e := s.Save(context.Background(), p, r, []Artifact{a}); e == nil {
			t.Fatal("invalid artifact accepted")
		}
	}
}
func TestDSNSecurity(t *testing.T) {
	for _, test := range []struct {
		d, url          string
		insecure, valid bool
	}{
		{"postgres", "postgres://u:secret@db/app", false, true}, {"postgres", "postgres://db/app?sslmode=disable", false, false}, {"postgres", "postgres://db/app?sslmode=disable", true, true}, {"postgres", "postgres://db/app?sslmode=verify-full&sslmode=disable", false, false},
		{"mssql", "sqlserver://u:secret@db?database=app", false, true}, {"mssql", "sqlserver://db?encrypt=false", false, false}, {"mssql", "sqlserver://db?TrustServerCertificate=true", false, false}, {"mssql", "sqlserver://db?TrustServerCertificate=true&trustservercertificate=false", false, false}, {"mssql", "sqlserver://db?encrypt=true&trustservercertificate=true", true, true},
	} {
		out, e := ValidateDSN(test.d, test.url, test.insecure)
		if (e == nil) != test.valid {
			t.Fatalf("%s %s: %s %v", test.d, test.url, out, e)
		}
		if e != nil && strings.Contains(e.Error(), "secret") {
			t.Fatal("DSN leaked")
		}
	}
}
func TestDialectBindingAndSchema(t *testing.T) {
	for _, d := range []string{"sqlite", "postgres", "mssql"} {
		s := Store{dialect: d}
		q := s.bind("SELECT a FROM t WHERE x=? AND y=?")
		want := map[string]string{"sqlite": "x=? AND y=?", "postgres": "x=$1 AND y=$2", "mssql": "x=@p1 AND y=@p2"}[d]
		if !strings.Contains(q, want) {
			t.Fatal(q)
		}
		schema, e := SchemaSQL(d)
		if e != nil || !strings.Contains(schema, "CREATE TABLE sekscan_findings") || !strings.Contains(schema, "INSERT INTO sekscan_schema_migrations") {
			t.Fatal(d, e)
		}
	}
}
func TestExternalDatabaseIntegration(t *testing.T) {
	// Dedicated disposable databases only: schema migrations create application tables.
	for _, d := range []string{"postgres", "mssql"} {
		t.Run(d, func(t *testing.T) {
			key := "SEKSCAN_TEST_" + strings.ToUpper(d) + "_DSN"
			if os.Getenv(key) == "" {
				t.Skip("no live database DSN")
			}
			c := config.Default().Storage
			c.Driver = d
			c.DSNEnv = key
			c.AutoMigrate = false
			c.AllowInsecureTLS = os.Getenv("SEKSCAN_TEST_ALLOW_INSECURE") == "1"
			s, e := Open(context.Background(), c)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if e = s.Migrate(context.Background()); e != nil {
				t.Fatal(e)
			}
			p, r := fixture(t)
			p.Key = "integration-" + time.Now().Format("150405.000000000")
			r.ProjectKey = p.Key
			r.ID = model.Hash(p.Key)
			if e = s.Save(context.Background(), p, r, []Artifact{{Name: "sbom.syft.json", Content: []byte("{}")}}); e != nil {
				t.Fatal(e)
			}
			if _, e = s.Load(context.Background(), p.Namespace, r.ID); e != nil {
				t.Fatal(e)
			}
			filter := Filter{Namespace: p.Namespace, Project: p.Key, Limit: 10}
			projects, e := s.ProjectPage(context.Background(), filter)
			if e != nil || projects.Total != 1 || len(projects.Items) != 1 || projects.Items[0].Key != p.Key {
				t.Fatalf("project paging: %+v %v", projects, e)
			}
			runs, e := s.ScanPage(context.Background(), filter)
			if e != nil || runs.Total != 1 || len(runs.Items) != 1 || runs.Items[0].ID != r.ID {
				t.Fatalf("run paging: %+v %v", runs, e)
			}
			trend, e := s.Trends(context.Background(), filter, 10)
			if e != nil || trend.Total != 1 || len(trend.Points) != 1 || trend.Points[0].ID != r.ID {
				t.Fatalf("project trends: %+v %v", trend, e)
			}
		})
	}
}

func TestSQLiteIndependentConnections(t *testing.T) {
	c := config.Default().Storage
	c.Path = filepath.Join(t.TempDir(), "shared-local.db")
	a, e := Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if e = a.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	b, e := Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	p, r := fixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := *r
			rr.ID = model.Hash(r.ID, string(rune('0'+i)))
			s := a
			if i%2 != 0 {
				s = b
			}
			errs <- s.Save(context.Background(), p, &rr, nil)
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	got, e := a.List(context.Background(), Filter{Namespace: p.Namespace})
	if e != nil || len(got) != 10 {
		t.Fatal(len(got), e)
	}
}
