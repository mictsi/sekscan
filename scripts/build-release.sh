#!/usr/bin/env bash
# Build every supported target using the standard-library-only release helper.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/scripts/release"
export GOWORK=off GOFLAGS=-mod=readonly
exec go run . --root "$root" "$@"
