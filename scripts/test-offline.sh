#!/usr/bin/env bash
# Test infrastructure only; NOT a production build. Requires CGo and system SQLite.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=1
go test -modfile=go.offline.mod -tags=offline_sqltest -count=1 ./...
go vet -modfile=go.offline.mod -tags=offline_sqltest ./...

# The release helper is a separate standard-library-only Go module.
(cd scripts/release && go test -count=1 ./... && go vet ./...)
