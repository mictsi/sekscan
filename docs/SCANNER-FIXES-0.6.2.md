# Semgrep runtime links and Go applicability — 0.6.2-preview

> Historical guide for the named release. Semgrep was removed in 0.6.5; use
> [SEMGREP-REMOVAL.md](SEMGREP-REMOVAL.md) instead of its old repair commands.

## What was fixed

**Semgrep:** the old preparation code accepted only symlinks to regular files. It
rejected every directory link with `runtime directory links are unsupported`.
uv's managed Python installations legitimately use directory aliases; Python layouts
can also use `lib64 -> lib`. This is a sekscan installer defect, not a finding in
the scanned application. The regression fixture reproduces the exact old error.

The installer now copies the staged runtime to a separate tree, materializing
internal directory/file links before import. It handles relative and absolute
in-bundle aliases, chains, and aliases appearing before their targets. The installed
bundle is link-free, relocatable on a compatible OS/architecture, and all expanded
files remain integrity-checked. External, broken and cyclic links are rejected.
Limits: 64 link hops per resolution, directory depth 128, 250,000 expanded entries,
100,000 files, 512 MiB per file and 2 GiB total file bytes. Duplicate aliases count
against these limits. Copy validation does not mutate the source staging tree; failed preparation is
cleaned up and is not published. Existing managed installations are not replaced
by a failed copy. Additional temporary disk space is needed.

**Go checks:** default `govulncheck` and `gosec` now require both a selected go.mod
and at least one `.go` file owned by that module. A go.mod/go.sum alone is not
sufficient. The previous selector could activate analyzers on metadata-only roots
and on empty parent modules whose only Go code belonged to separate nested modules.

No-input decisions happen **before** tool version probes or DB validation. Their
result is `status=skipped`, `required=false`, not `completed` and not `failed`.
This does not itself cause exit 2; other applicable scanners still determine the
overall policy and completion outcome. Previously reported Go findings do not become
resolved just because the Go analyzer is now skipped.

## Applicability rules

| Selected content | Default Go check result |
|---|---|
| JavaScript/TypeScript/Python/etc., no in-target Go modules | Skipped / not applicable |
| go.mod/go.sum but no module-owned Go source | Skipped / not applicable |
| Go source only in excluded paths or dependency/workspace caches | Skipped / not applicable |
| Empty root module and a nested Go module with source | Only the nested module is analyzed |
| Mixed-language repository with a real Go helper/service module | Analyze that Go module; do not infer one language for the entire repository |
| Go module with missing checksums, build errors, or unsupported build constraints | Failed/incomplete until corrected |
| Cannot inspect selected Go inputs safely (permissions, matching links, limits) | Incomplete; not presumed non-Go |

Discovery never searches parents outside the selected target. Sources are associated
with their nearest module marker, including an explicitly excluded marker, so a
nested module cannot reactivate its parent. Workspace bin/cache/log/data paths and
configured exclusions apply consistently to tool planning and execution. Dependency
directories node_modules/vendor/.venv/.git are not traversed. Within a selected Go
module, dot/underscore package directories and testdata do not count as source for
`./...`; filenames beginning with dot/underscore are ignored. Tests and
platform-specific `.go` files still establish that it is Go, but test/build-tag/CGO
coverage remains analyzer-specific. GOPATH-only code without go.mod is not selected.

Legacy custom extensions named govulncheck/gosec, or referencing their managed tools,
inherit `when: "go-modules"` if the selector was omitted. Explicit `when` values are
not overwritten. Custom commands, parsers, required flags and runtime settings are
preserved; review custom definitions that deliberately request `when: "all"`.

A log such as `Go module selected engine=govulncheck module=/path/to/module` now
identifies the actual analyzed module. A mainly TypeScript application can still
contain Go tooling: select the intended application subdirectory or explicitly
exclude unrelated tooling rather than turning a real Go error into a successful scan.

## Apply and recover

Build the extracted source on a connected machine:

```sh
bash scripts/build.sh
./sekscan version
# sekscan 0.6.2-preview
```

Or apply the patch to an unchanged 0.6.1 source tree and rebuild:

```sh
git apply --check /path/to/sekscan-0.6.2-preview.patch
git apply /path/to/sekscan-0.6.2-preview.patch
bash scripts/build.sh
```

Keep your existing workspace and configuration. No SQL migration, cache deletion,
policy reset, or automatic rewriting of historical results is needed.

```sh
WORKSPACE="/absolute/path/to/your/existing/workspace"
CONFIG="$WORKSPACE/sekscan.json"
# Use sekscan-expanded.json instead when that is your selected configuration.

./sekscan deps install semgrep \
  --home "$WORKSPACE" --config "$CONFIG" \
  --yes --diagnostic-stderr

./sekscan deps status semgrep \
  --home "$WORKSPACE" --config "$CONFIG"

./sekscan scan "dir:/absolute/path/to/application" \
  --project YOUR_EXISTING_PROJECT \
  --home "$WORKSPACE" --config "$CONFIG" \
  --diagnostic-stderr --out ./security-report-retry
```

The installation command uses managed uv/Python and still needs network access and
compatible binary wheels. A failing preparation is not readiness. Retry the targeted
installation rather than removing checksum pins or substituting system Python.
Private diagnostics may contain sensitive data; inspect them locally before sharing.
No Go cache preparation or `go mod tidy` is required for a non-Go target.

## When a real Go module still fails

The quoted error about module metadata/checksums does not alone establish whether
the selected application was incorrectly classified. Inspect the new module-path log
and private stderr. This patch does **not** map that error (or any generic exit 1) to
"not applicable". For a genuine module, prepare its dependency cache explicitly:

```sh
./sekscan prepare --go-module /absolute/path/to/go-module \
  --home "$WORKSPACE" --config "$CONFIG" --yes --diagnostic-stderr
```

This runs `go mod download all`; it may update go.sum. It does not automatically run
go mod tidy or repair source/build errors. Review metadata in a trusted development
environment when needed. Read-only scanning and checksum validation are unchanged.

## Sources and validation boundaries

- uv documents managed Python directory symlinks/junctions:
  https://docs.astral.sh/uv/concepts/python-versions/#minor-version-directories
- Go documents source/package matching conventions:
  https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns

These references were read on 2026-10-03. Local regression tests use controlled
runtime/scanner fixtures and the test-only system-SQLite adapter. No live download
of the user's Semgrep distribution or access to their repository was available.
The source package contains no downloaded tools, runtime bundles, CVE data or
production binary. See TESTING.md for current results and outstanding acceptance.
