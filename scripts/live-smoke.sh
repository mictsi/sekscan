#!/usr/bin/env bash
# Opt-in real scanner acceptance test; downloads and executes upstream releases.
set -euo pipefail
if [[ "${1:-}" != --yes ]]; then
  echo 'Usage: scripts/live-smoke.sh --yes [absolute-path-to-sekscan]' >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
binary="${2:-$root/sekscan}"
work="$(mktemp -d)"
cleanup() {
  code=$?
  if [[ "$code" -eq 0 ]]; then rm -rf "$work"; else
    echo "Failed acceptance workspace retained at: $work" >&2
  fi
}
trap cleanup EXIT
mkdir -p "$work/project/.github/workflows"
cp "$root/testdata/project/package.json" "$work/project/package.json"
cat > "$work/project/.github/workflows/ci.yml" <<'YAML'
name: Fixture workflow
on: workflow_dispatch
permissions: {}
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Acceptance fixture"
YAML
cat > "$work/project/Dockerfile" <<'DOCKER'
FROM alpine:3.22
RUN echo "fixture"
DOCKER
cat > "$work/project/go.mod" <<'GOMOD'
module example.invalid/sekscan-live-fixture

go 1.23.0
GOMOD
cat > "$work/project/main.go" <<'GO'
package main
import "fmt"
func main() { fmt.Println("fixture") }
GO
cat > "$work/project/app.py" <<'PYCODE'
print("fixture")
PYCODE
"$binary" init --home "$work/workspace" --no-config
"$binary" prepare --all --with-java --yes --home "$work/workspace" --config "$work/workspace/sekscan.json"
"$binary" doctor --all --home "$work/workspace" --config "$work/workspace/sekscan.json"
# Every persistent cache and executable must work after relocation.
mv "$work/workspace" "$work/moved"
common=(--home "$work/moved" --config "$work/moved/sekscan.json")
"$binary" db status --all --with-java "${common[@]}"
set +e
"$binary" scan "dir:$work/project" --offline \
  --project live-smoke --out "$work/report" "${common[@]}"
status=$?
set -e
if [[ "$status" -ne 0 && "$status" -ne 1 ]]; then
  cat "$work/report/summary.md" 2>/dev/null || :
  echo 'Live portable scanner integration did not complete.' >&2
  exit 2
fi
for file in results.json index.html sbom.syft.json sbom.cdx.json sbom.spdx.json findings.sarif junit.xml; do
  test -s "$work/report/$file"
done
# Verify that no applicable default analyzer vanished from the result.
for engine in syft grype trivy gitleaks actionlint hadolint zizmor govulncheck gosec; do
  if ! grep -Eq '"name"[[:space:]]*:[[:space:]]*"'"$engine"'"' "$work/report/results.json"; then
    echo "Missing analyzer result: $engine" >&2
    exit 2
  fi
done
"$binary" history list --json "${common[@]}"
"$binary" storage backup --out "$work/snapshot.db" "${common[@]}"
printf 'Live relocated offline directory scan completed; policy exit=%s. Container/registry tests remain separate.\n' "$status"
