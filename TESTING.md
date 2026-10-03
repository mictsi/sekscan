# Validation record — sekscan 0.6.5-preview

Date: 2026-10-03. This release removes the Semgrep integration. It does not include
production executables, scanner binaries, runtime downloads or vulnerability data.

## Results

| Check | Result |
|---|---|
| Application tests / named subtests | 399 passed, 2 external-database cases skipped, 0 failed |
| Release-helper tests / named subtests | 17 passed |
| Release-control Python tests | 18 passed |
| Race detector | Passed using the offline system-SQLite test adapter |
| go vet | Passed for the application and release helper |
| Statement coverage | 68.3% |
| Production application build | Blocked while downloading the configured Go toolchain; DNS/network failure |
| Browser/UI tests | No new run; UI assets and rendering templates are unchanged |

Counts include parent tests and named subtests, not individual assertions. The
removed Semgrep runtime has fewer tests than the previous release; its tests were
removed along with its implementation, not counted as current passing checks.
The two external-database tests require live PostgreSQL and SQL Server services.
Raw output and a machine-readable summary are retained in `docs/validation/v0.6.5/`.

## Removal regressions

- Fresh defaults, required tools, all-tools preparation planning, generated workspace
  configuration and scanner selection contain no Semgrep or automatic uv helper.
- Old true/false `checks.semgrep` values are accepted only for migration; emitted
  configuration omits the field. Unknown settings and wrong boolean types still fail.
- Legacy tool definitions and named/executable/managed aliases are removed before
  portable path validation. Old missing rules/executables do not block an upgrade.
- Old batch defaults and per-project Semgrep booleans are ignored and absent from
  generated plans; other per-project settings remain effective.
- Managed installation, import, runtime lookup and executable resolution reject
  retired scanner names before downloading or executing them.
- `config remove-semgrep` preserves remaining check flags, policy, project, storage
  and pins; it writes a new file and refuses to overwrite an existing destination.
- The original configuration, existing runtime files and old rules files are not
  deleted or overwritten. Deleted retired defaults are not recreated by `init`.
- A synthetic Python source project with a legacy required Semgrep extension scans
  to completion using the remaining fixture scanners; its report contains the
  migration notice and no Semgrep engine result.
- Historical Semgrep findings are not mutated or classified as remediated merely
  because the new run has no Semgrep engine.
- Non-retired custom extensions, including an explicitly used uv prerequisite,
  retain their definitions. The generic portable bundle importer remains tested.
- All six release targets, including Windows ARM64, remain in the canonical target
  manifest. The published-only, exact-tag release gates still pass their tests.

## Reproduce the local tests

The authoring environment has Go 1.23.2 on Linux/amd64. These commands select the
existing alternate test module and system SQLite bridge, not production drivers:

```sh
GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=1 \
  go test -modfile=go.offline.mod -tags=offline_sqltest -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=1 \
  go test -modfile=go.offline.mod -tags=offline_sqltest -count=1 -race ./...
GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=1 \
  go vet -modfile=go.offline.mod -tags=offline_sqltest ./...
(cd scripts/release && GOTOOLCHAIN=local GOPROXY=off go test -count=1 ./...)
python3 -m unittest discover -s scripts/tests -v
```

## Acceptance boundary

Actual upstream scanners and CVE databases were not downloaded or executed here.
Production database drivers, live PostgreSQL/SQL Server, hosted release uploads,
and native Windows/macOS acceptance remain unverified. The configured Go toolchain
could not be downloaded; no production binary or resolved go.sum is fabricated.
Run `bash scripts/build.sh` on a connected build machine, review dependency files,
and run the existing connected smoke tests before publishing binaries.

SQL schema, batch schema version, production Go module pins, and UI assets are
unchanged. The batch schema retains only a deprecated compatibility key for the
removed scanner. No historical assessment is rescanned or rewritten.
