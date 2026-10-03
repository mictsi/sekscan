# Scanner fixes and recovery — 0.6.1-preview

> Historical guide for the named release. Semgrep was removed in 0.6.5; use
> [SEMGREP-REMOVAL.md](SEMGREP-REMOVAL.md) instead of its old repair commands.

This patch fixes two reproducible sekscan adapter defects and makes preparation and
Go processing failures diagnosable. It does not disable the expanded scanner suite,
fall back to system tools, or turn incomplete scans into successful assessments.

## Interpreting the reported failures

| Log | Meaning and change |
|---|---|
| zizmor: location outside the selected source target | 0.6.0 treated zizmor's repository-relative SARIF locations as relative to its isolated working directory. The resolver now uses known repository/source/input bases and requires an exact match to the file passed to zizmor. Absolute paths are not rebased. Traversal, external locations and symlink traversal remain rejected. |
| govulncheck: exit 1, before `scanner started` | Version probing can fail before analysis. The 0.6.0 temporary probe database lacked `index/modules.json`, the endpoint used by the Go client's local schema detection. The patch supplies an empty, probe-only v1 index and retains failed version-probe stderr when diagnostics are enabled. The actual vulnerability database remains separate and subject to existing readiness/integrity checks. |
| gosec: package loading or processing errors | Not enough information to identify the user's package error. Missing dependencies/checksums, unsupported Go versions/build tags/CGO and real compilation errors are possible. The patch classifies known messages without exposing them and can save gosec's `Golang errors`/`Stats` JSON separately in private local logs, including when zero files were analyzed. |
| semgrep: not installed in workspace bin | No managed installation was resolved in the selected workspace; this is not a Semgrep finding. Install it in that same workspace and inspect any preparation failure. The patch adds immediate per-tool preparation/verification errors and a targeted installation command. No claim is made that the user's missing installation was caused by a specific installer bug. |
| Go analyzers: no applicable inputs (go-modules) | The selector discovered no non-excluded `go.mod` modules in that scan. Skipping those analyzers is expected; a non-Go scan should not be forced through a Go analyzer. GOPATH-only sources without go.mod are not selected. |
| scan persisted | The scan record was written to storage. It is not a successful-assessment message. Failed required engines still result in an incomplete report and exit code 2. |

## Apply the patch

Build the new executable from the source directory:

```sh
bash scripts/build.sh
./sekscan version
```

Use the full source ZIP, or apply the patch to an unmodified 0.6.0 source tree:

```sh
git apply --check /path/to/sekscan-0.6.1-preview.patch
git apply /path/to/sekscan-0.6.1-preview.patch
```

No database migration, workspace reset or policy change is required. Keep current
bin/cache/data/config directories. The schema versions and production Go module pins
are unchanged. Source/package metadata and the readme.med alias are synchronized.

## Repair prerequisites in the SAME workspace

Do not create a new workspace to troubleshoot an installation in an existing one.
Use the exact configuration previously selected by the scan (for example,
sekscan-expanded.json rather than sekscan.json when that was used).

```sh
WORKSPACE="/absolute/path/to/your/existing/workspace"
CONFIG="$WORKSPACE/sekscan.json"

# Isolate Semgrep installation; managed uv/Python prerequisites are included.
./sekscan deps install semgrep \
  --home "$WORKSPACE" --config "$CONFIG" \
  --yes --diagnostic-stderr

# Read-only checks of selected workspace installations.
./sekscan deps status zizmor govulncheck gosec semgrep \
  --home "$WORKSPACE" --config "$CONFIG"

# Full preparation, including scanner databases, when needed.
./sekscan prepare --all --with-java --yes --diagnostic-stderr \
  --home "$WORKSPACE" --config "$CONFIG"
```

Installation requires network access and compatible upstream binaries/wheels. A
nonzero installation status is not readiness. Existing pins are honored; do not
remove integrity controls or substitute a PATH tool to conceal a failed install.
No live Semgrep download or platform-specific installation has been verified here.

For a Go module, explicitly warm its full transitive module graph:

```sh
./sekscan prepare \
  --go-module /absolute/path/to/go-module \
  --yes --diagnostic-stderr \
  --home "$WORKSPACE" --config "$CONFIG"
```

The patched command uses the managed SDK's `go mod download all`, not just the
default lazy/direct prefetch. It may update go.sum; review changes. Repeat per
module. Source analysis still uses readonly module metadata, CGO disabled, local
packages and the selected toolchain. Go workspaces, private modules, build tags and
CGO may require further reviewed preparation/configuration. Do not assume this
command fixes source compilation errors or automatically runs go mod tidy.

## Rescan and inspect private diagnostics

```sh
./sekscan scan "dir:/absolute/path/to/project" \
  --project my-service \
  --home "$WORKSPACE" --config "$CONFIG" \
  --diagnostic-stderr --out ./security-report-retry
```

Depending on the failing phase, inspect locally:

- `logs/govulncheck-version-stderr-*.private.log`: failed version probe.
- `logs/govulncheck-stderr-*.private.log`: analysis stderr.
- `logs/gosec-processing-errors-*.private.log`: only gosec errors and statistics,
  not its full issues/source-snippet report.
- `logs/prerequisite-stderr-*.private.log`: failed uv/Go preparation commands.
- `logs/semgrep-version-stderr-*.private.log`: failed managed Semgrep version probe.

These files are opt-in, owner-readable on POSIX and bounded to 256 KiB plus a
truncation notice. Existing scanner stderr capture remains capped at 64 KiB. Error
messages can contain paths, source text or credentials. Do not publish private logs
as CI artifacts or send them without review/redaction. They are not included in
portable reports or shared database artifacts.

## Source references

The upstream code checked for these fixes:

- zizmor `LocalKey::best_relative_path` explicitly documents that returned paths
  may be repository-relative, not current-working-directory-relative:
  https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/src/registry/input.rs
  (Git blob `1b4ba307e7110968a2461602f47c199b73734006`).
- govulncheck's `newLocalClient` checks for `index/modules.json` to identify a v1
  local database:
  https://github.com/golang/vuln/blob/master/internal/client/client.go
  (Git blob `236c9d1b072dc5b0b4caf2c14fae3cb0b985afce`).

See TESTING.md for fixture-based validation and outstanding live acceptance.
