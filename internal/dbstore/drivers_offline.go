//go:build offline_sqltest && cgo

package dbstore

import _ "sekscan/internal/testsupport/sqlitebridge"

const DriverBuild = "TEST-ONLY: system SQLite; no PostgreSQL or SQL Server drivers"
