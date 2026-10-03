module sekscan

go 1.26.0

toolchain go1.27.1

require (
	github.com/jackc/pgx/v5 v5.11.0
	github.com/microsoft/go-mssqldb v1.11.2
	modernc.org/sqlite v1.60.1
)

// Keep the SQLite runtime aligned with the SQLite module's own go.mod.
require modernc.org/libc v1.77.1 // indirect
