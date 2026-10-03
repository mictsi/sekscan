#!/usr/bin/env bash
# Connected bootstrap build. Review and commit generated go.mod/go.sum before release.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
go version
go mod tidy
go mod verify
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o sekscan ./cmd/sekscan
./sekscan version
