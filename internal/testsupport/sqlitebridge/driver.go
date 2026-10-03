//go:build offline_sqltest && cgo

// Package sqlitebridge is a test-only database/sql bridge to the system SQLite library.
// It is NOT a production backend and does not implement PostgreSQL or SQL Server.
package sqlitebridge

/*
#cgo LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>
static int bind_text_copy(sqlite3_stmt *s, int i, const char *p, int n) {return sqlite3_bind_text(s,i,p,n,SQLITE_TRANSIENT);}
static int bind_blob_copy(sqlite3_stmt *s, int i, const void *p, int n) {return sqlite3_bind_blob(s,i,p,n,SQLITE_TRANSIENT);}
*/
import "C"
import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unsafe"
)

type drv struct{}
type conn struct{ db *C.sqlite3 }
type tx struct{ c *conn }
type stmt struct {
	c *conn
	q string
}
type rows struct {
	columns []string
	values  [][]driver.Value
	at      int
}

func init() { sql.Register("sqlite", drv{}) }
func (drv) Open(dsn string) (driver.Conn, error) {
	u, e := url.Parse(dsn)
	if e != nil {
		return nil, e
	}
	path := u.Path
	if u.Scheme != "file" {
		path = dsn
	}
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	c := &conn{}
	if rc := C.sqlite3_open_v2(p, &c.db, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil); rc != C.SQLITE_OK {
		return nil, c.err()
	}
	for _, q := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=10000", "PRAGMA journal_mode=WAL"} {
		if _, e = c.ExecContext(context.Background(), q, nil); e != nil {
			c.Close()
			return nil, e
		}
	}
	return c, nil
}
func (c *conn) err() error                            { return fmt.Errorf("test SQLite: %s", C.GoString(C.sqlite3_errmsg(c.db))) }
func (c *conn) Close() error                          { C.sqlite3_close(c.db); return nil }
func (c *conn) Prepare(q string) (driver.Stmt, error) { return &stmt{c: c, q: q}, nil }
func (c *conn) Begin() (driver.Tx, error)             { return c.BeginTx(context.Background(), driver.TxOptions{}) }
func (c *conn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	_, e := c.ExecContext(ctx, "BEGIN IMMEDIATE", nil)
	return &tx{c}, e
}
func (t *tx) Commit() error { _, e := t.c.ExecContext(context.Background(), "COMMIT", nil); return e }
func (t *tx) Rollback() error {
	_, e := t.c.ExecContext(context.Background(), "ROLLBACK", nil)
	return e
}
func (c *conn) Ping(ctx context.Context) error { return ctx.Err() }
func (c *conn) execute(ctx context.Context, q string, args []driver.NamedValue) (*rows, int64, error) {
	if e := ctx.Err(); e != nil {
		return nil, 0, e
	}
	cq := C.CString(q)
	defer C.free(unsafe.Pointer(cq))
	var s *C.sqlite3_stmt
	if C.sqlite3_prepare_v2(c.db, cq, -1, &s, nil) != C.SQLITE_OK {
		return nil, 0, c.err()
	}
	if s == nil {
		return &rows{}, 0, nil
	}
	defer C.sqlite3_finalize(s)
	for i, a := range args {
		n := C.int(i + 1)
		var rc C.int
		switch v := a.Value.(type) {
		case nil:
			rc = C.sqlite3_bind_null(s, n)
		case int64:
			rc = C.sqlite3_bind_int64(s, n, C.sqlite3_int64(v))
		case float64:
			rc = C.sqlite3_bind_double(s, n, C.double(v))
		case bool:
			iv := 0
			if v {
				iv = 1
			}
			rc = C.sqlite3_bind_int(s, n, C.int(iv))
		case string:
			p := C.CString(v)
			rc = C.bind_text_copy(s, n, p, C.int(len(v)))
			C.free(unsafe.Pointer(p))
		case []byte:
			if len(v) == 0 {
				rc = C.sqlite3_bind_zeroblob(s, n, 0)
			} else {
				p := C.CBytes(v)
				rc = C.bind_blob_copy(s, n, p, C.int(len(v)))
				C.free(p)
			}
		default:
			return nil, 0, fmt.Errorf("unsupported test SQLite parameter %T", a.Value)
		}
		if rc != C.SQLITE_OK {
			return nil, 0, c.err()
		}
	}
	r := &rows{}
	count := int(C.sqlite3_column_count(s))
	for i := 0; i < count; i++ {
		r.columns = append(r.columns, C.GoString(C.sqlite3_column_name(s, C.int(i))))
	}
	for {
		if e := ctx.Err(); e != nil {
			return nil, 0, e
		}
		rc := C.sqlite3_step(s)
		if rc == C.SQLITE_DONE {
			break
		}
		if rc != C.SQLITE_ROW {
			return nil, 0, c.err()
		}
		values := make([]driver.Value, count)
		for i := 0; i < count; i++ {
			n := C.int(i)
			switch C.sqlite3_column_type(s, n) {
			case C.SQLITE_INTEGER:
				values[i] = int64(C.sqlite3_column_int64(s, n))
			case C.SQLITE_FLOAT:
				values[i] = float64(C.sqlite3_column_double(s, n))
			case C.SQLITE_TEXT:
				values[i] = C.GoStringN((*C.char)(unsafe.Pointer(C.sqlite3_column_text(s, n))), C.sqlite3_column_bytes(s, n))
			case C.SQLITE_BLOB:
				values[i] = C.GoBytes(C.sqlite3_column_blob(s, n), C.sqlite3_column_bytes(s, n))
			default:
				values[i] = nil
			}
		}
		r.values = append(r.values, values)
	}
	return r, int64(C.sqlite3_changes(c.db)), nil
}
func (c *conn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	_, n, e := c.execute(ctx, q, a)
	return driver.RowsAffected(n), e
}
func (c *conn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	r, _, e := c.execute(ctx, q, a)
	return r, e
}
func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return strings.Count(s.q, "?") }
func named(a []driver.Value) []driver.NamedValue {
	o := []driver.NamedValue{}
	for i, v := range a {
		o = append(o, driver.NamedValue{Ordinal: i + 1, Value: v})
	}
	return o
}
func (s *stmt) Exec(a []driver.Value) (driver.Result, error) {
	return s.c.ExecContext(context.Background(), s.q, named(a))
}
func (s *stmt) Query(a []driver.Value) (driver.Rows, error) {
	return s.c.QueryContext(context.Background(), s.q, named(a))
}
func (r *rows) Columns() []string { return r.columns }
func (r *rows) Close() error      { return nil }
func (r *rows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}
