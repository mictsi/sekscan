#!/usr/bin/env bash
# Use dedicated disposable databases: these tests create schema and scan records.
set -euo pipefail
: "${SEKSCAN_TEST_POSTGRES_DSN:?Set a PostgreSQL URL for a disposable test database}"
: "${SEKSCAN_TEST_MSSQL_DSN:?Set a SQL Server URL for a disposable test database}"
cd "$(dirname "$0")/.."
go test -count=1 -v -run '^TestExternalDatabaseIntegration$' ./internal/dbstore
