# Release validation — 0.6.8 (2026-11-22)

- Go 1.27.4: module updater completed, module checksums verified, full application
  tests and vet passed.
- Production binary reports `sekscan 0.6.8 [production-drivers]`.
- Release builder tests and vet passed.
- All 23 Python launcher and release-event tests passed.
- KICS upstream 2.2.1 has no attached assets; retained the verified standalone
  2.1.20 pin. Live scanner and external SQL service tests were not rerun.
- SQLite libc remains paired at v1.80.1 as required by SQLite v1.63.0.
- Graph-only modules pruned by tidy are reported but not forced into go.mod.
- No release assets were published.

# Release validation — 0.6.6-preview (2026-11-07)

- Production build reports `sekscan 0.6.6-preview [production-drivers]`.
- Full application `go test ./...` and `go vet ./...` passed with Go 1.27.3.
- All four native launcher integration tests passed against the versioned binary.
- `bash -n run.sh` and `git diff --check` passed.
- Real KICS Linux/amd64 acceptance is recorded below; its optional live test was
  not rerun during this version-only validation. Live external database tests
  retain their existing skips. No release assets were published.

# Current change — standalone KICS (2026-10-11)

- Production-module `go test ./...` and `go vet ./...` passed with Go 1.27.1.
- The production application built successfully.
- The application installed KICS 2.1.20 and its matching rule assets from upstream
  into a temporary workspace, verifying both downloads and the resulting bundle.
- The actual Linux/amd64 KICS executable passed the adapter acceptance test:
  Terraform findings retain native severity and original locations; a plain npm
  package manifest is reported as not applicable.
- Regression tests cover rule-asset digest failure, rule tampering, bundle lock
  reuse, all six package names, isolated inputs, source-path containment,
  processing failures, redaction, and configuration/CLI/batch overrides.
- Native Windows/macOS scanner execution and live PostgreSQL/SQL Server remain
  outside this validation. External database tests retain their existing skips.

See [KICS](docs/KICS.md) for the optional live-test command and operational limits.
The earlier release record below is retained as historical evidence.

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
