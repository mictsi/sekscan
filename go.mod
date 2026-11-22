module sekscan

go 1.26.0

toolchain go1.27.4

require (
	github.com/jackc/pgx/v5 v5.13.0
	github.com/microsoft/go-mssqldb v1.12.0
	modernc.org/sqlite v1.63.0
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.4 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/shopspring/decimal v1.6.0 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.13.0 // indirect
)

// Keep the SQLite runtime aligned with the SQLite module's own go.mod.
require modernc.org/libc v1.80.1 // indirect
