//go:build !offline_sqltest

package dbstore

import (
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
	_ "modernc.org/sqlite"
)

const DriverBuild = "production-drivers"
