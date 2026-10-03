package dbstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var schemas embed.FS

const SchemaVersion = 1

func migration(dialect string) (string, error) {
	d, e := Dialect(dialect)
	if e != nil {
		return "", e
	}
	b, e := schemas.ReadFile("migrations/" + d + "_001.sql")
	return string(b), e
}
func statements(script string) []string { return strings.Split(script, "-- sekscan:statement") }
func (s *Store) lock(ctx context.Context, tx *sql.Tx, resource string) error {
	switch s.dialect {
	case "postgres":
		// hashtext collisions only serialize unrelated writers; they cannot corrupt data.
		if _, e := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(1936026483, hashtext($1))", resource); e != nil {
			return dbError("acquire transaction lock")
		}
	case "mssql":
		_, e := tx.ExecContext(ctx, `DECLARE @result int; EXEC @result=sys.sp_getapplock @Resource=@p1,@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=10000; IF @result < 0 THROW 51000,'Sekscan lock unavailable',1;`, "sekscan:"+resource)
		if e != nil {
			return dbError("acquire transaction lock")
		}
	}
	return nil
}
func (s *Store) Migrate(ctx context.Context) error {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	script, e := migration(s.dialect)
	if e != nil {
		return e
	}
	parts := statements(script)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return dbError("begin migration")
	}
	defer tx.Rollback()
	if e = s.lock(ctx, tx, "schema"); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, parts[0]); e != nil {
		return dbError("initialize migration ledger")
	}
	var version int
	var checksum string
	rows, e := tx.QueryContext(ctx, "SELECT version,checksum FROM sekscan_schema_migrations ORDER BY version")
	if e != nil {
		return dbError("read schema version")
	}
	versions := map[int]string{}
	for rows.Next() {
		if e = rows.Scan(&version, &checksum); e != nil {
			rows.Close()
			return dbError("read migration ledger")
		}
		versions[version] = checksum
	}
	err := rows.Err()
	rows.Close()
	if err != nil {
		return dbError("read migration ledger")
	}
	for v := range versions {
		if v != 1 {
			return fmt.Errorf("database schema is newer than this application or has an unsupported migration")
		}
	}
	if hash, ok := versions[1]; ok {
		if hash != digest([]byte(script)) {
			return fmt.Errorf("migration checksum mismatch; do not modify applied migrations")
		}
		if e = tx.Commit(); e != nil {
			return dbError("commit schema migration")
		}
		return nil
	}
	for _, q := range parts[1:] {
		if _, e = tx.ExecContext(ctx, q); e != nil {
			return dbError("apply schema migration")
		}
	}
	_, e = tx.ExecContext(ctx, s.bind("INSERT INTO sekscan_schema_migrations(version,checksum,applied_at) VALUES(?,?,?)"), 1, digest([]byte(script)), time.Now().UTC().Format(stamp))
	if e != nil {
		return dbError("record schema migration")
	}
	if e = tx.Commit(); e != nil {
		return dbError("commit schema migration")
	}
	return nil
}
func (s *Store) Status(ctx context.Context) (int, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var v int
	var hash string
	e := s.db.QueryRowContext(ctx, "SELECT version,checksum FROM sekscan_schema_migrations WHERE version=(SELECT MAX(version) FROM sekscan_schema_migrations)").Scan(&v, &hash)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, fmt.Errorf("schema has not been migrated")
	}
	if e != nil {
		return 0, dbError("read schema; run storage migrate first")
	}
	script, e := migration(s.dialect)
	if e != nil {
		return 0, e
	}
	if v != SchemaVersion || hash != digest([]byte(script)) {
		return v, fmt.Errorf("incompatible database schema or migration checksum")
	}
	return v, nil
}

// SchemaSQL exports an executable initial schema for an empty, dedicated database.
func SchemaSQL(dialect string) (string, error) {
	script, e := migration(dialect)
	if e != nil {
		return "", e
	}
	d, _ := Dialect(dialect)
	start, end := "BEGIN;\n", "COMMIT;\n"
	if d == "sqlite" {
		start = "PRAGMA foreign_keys=ON;\nBEGIN IMMEDIATE;\n"
	}
	if d == "mssql" {
		start = "SET XACT_ABORT ON;\nBEGIN TRANSACTION;\nBEGIN TRY\n"
		end = "COMMIT TRANSACTION;\nEND TRY\nBEGIN CATCH\nIF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;\nTHROW;\nEND CATCH;\n"
	}
	ledger := fmt.Sprintf("\nINSERT INTO sekscan_schema_migrations(version,checksum,applied_at) VALUES (1,'%s','%s');\n", digest([]byte(script)), time.Now().UTC().Format(stamp))
	return "-- INITIAL SCHEMA ONLY: run once against an empty dedicated database.\n" + start + script + ledger + end, nil
}
