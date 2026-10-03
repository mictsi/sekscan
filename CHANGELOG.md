# Changes

## 0.6.5-preview — 2026-10-03

- Remove Semgrep from built-in scanning, preparation, runtime provisioning,
  native readiness probes, default configuration and shipped starter rules.
- Ignore legacy Semgrep config/extension/batch settings without failing remaining
  scans; warn for workspace config migration and offer `config remove-semgrep`.
- Preserve other checks, policy, storage, tool pins and historical findings.
  Do not delete existing installations or workspace data automatically.
- Retain all six application release targets, including Windows ARM64.
- General multi-language SAST now requires a separately configured external analyzer.


## 0.6.4-preview — 2026-10-03

- Add Windows ARM64 to the application release builder and release-published workflow.
- Share one versioned target manifest between the Go packager and Python publisher;
  reject release sets missing their Windows ARM64 archive or carrying wrong build metadata.
- Enable native Semgrep debug diagnostics when explicitly requested; previous capture
  could retain only generic CLI errors while native RPC stderr stayed suppressed.
- Split readiness into managed imports, direct bundled-core startup/version, one-worker
  positive scan in an explicit temporary project, and SARIF/evidence validation.
- Persist per-attempt local readiness JSON and opt-in bounded private phase logs before
  failed staging is deleted. Keep source-bearing results out of the new summary.
- Check selected Semgrep Windows ARM64 wheel availability before runtime preparation;
  do not infer ARM support from x64 releases or silently use emulation/PATH tools.
- Add fixed permission/resource/loader/RPC error hints while preserving failures.
- No self-test bypass, automatic scanner disablement, database migration, Go module
  update or UI change. The user's specific native exit-2 cause remains unconfirmed.


## 0.6.3-preview — 2026-10-03

- Fix Semgrep launcher import-time CLI execution with a worker-safe main guard.
- Use the current embedded launcher for existing standard managed bundles without changing their integrity manifests.
- Add `deps test semgrep`, checking the bundled semantic-version dependency and a known-positive native scan. Preparation requires the native self-test.
- Run the built-in Semgrep adapter in the selected source directory with primary SARIF output and non-rewritten rule IDs. Preserve strict incomplete-scan handling and custom overrides.
- Retain bounded, opt-in Semgrep stdout/operational SARIF diagnostics and safe error classifications.
- Rewrite README.md/readme.med as a GitHub-facing usage guide.
- Add a release.published-only workflow with tag/commit and module-lock validation, all-platform packaging, checksum verification, and a separate publishing job. Refuse published immutable releases and conflicting existing assets.
- No SQL schema, Go module pins, default scanner enablement, or UI changes. Live Semgrep/user-source and hosted release execution remain unverified.

## 0.6.2-preview — 2026-10-03

- Fix Semgrep preparation rejecting uv/Python directory aliases. Materialize only
  in-bundle links through a bounded staged copy; reject external/broken/cyclic links
  and preserve the original preparation tree on failure. Import/checksum validation
  still rejects links and detects changed materialized alias content.
- Require module-owned Go source for Go analyzer applicability. Metadata-only roots,
  source outside the selected target, cache/vendor sources, and excluded modules no
  longer activate the checks. Respect nested module boundaries and Go package paths.
- Apply the same source exclusions to prerequisite planning and invocation. Default
  legacy Go extensions without a selector to `go-modules`; honor explicit selectors.
- Log selected Go module paths; not-applicable results stay skipped/not required,
  while actual analyzer failures stay incomplete and old findings remain unverified.
- Add regression tests for runtime alias installation/relocation/integrity, unsafe
  link/copy limits, non-Go scans, mixed-language repositories and module ownership.
- SQL schema, configuration versions, UI assets and production Go module pins unchanged.

## 0.6.1-preview — 2026-10-03

- Fix zizmor repository-relative source locations without allowing out-of-target files.
- Supply a complete probe-only local index for govulncheck version detection.
- Retain failed version-probe stderr and gosec JSON processing errors privately on opt-in.
- Add fixed, non-source-bearing Go module/toolchain and Python-wheel error hints.
- Prefetch the full Go module graph on explicit --go-module preparation.
- Log prerequisite preparation failures immediately; preserve required coverage failures.
- Synchronize source-package version and README/readme.med; no schema/UI/module-pin changes.

## 0.6.0-preview — 2026-10-03

- Enable Gitleaks/actionlint and conditional Hadolint, zizmor, govulncheck, gosec,
  and Semgrep checks by default. Respect explicit disable flags and custom definitions.
- Add Hadolint raw-binary managed installs, checksum verification, Dockerfile and
  Containerfile discovery, native JSON normalization and parse-failure detection.
- Add managed Go SDK, uv/Python/Semgrep bundles and govulncheck builds, independent
  of host PATH. Verify complete runtime file manifests and preserve relocation.
- Add portable Go vulnerability database snapshots, readiness/integrity validation,
  update/status/export/import, and a local-only govulncheck version probe.
- Add explicit Go dependency prefetch; analysis itself uses local readonly modules.
- Inspect gosec processing-error/statistics fields and SARIF error notifications.
  Redact source-bearing messages from default extensions' shared results.
- Add configuration upgrade, reviewed runtime-bundle import, batch/GitHub check
  overrides, local starter rules and connected acceptance instructions.
- SQL schema v1, batch schema v1 and app config v2 are retained. UI/design assets and
  production Go module pins are unchanged. Live integration remains unverified.

## 0.5.1-preview — 2026-10-03

- Adapt the complete UI to SekuraDesignMCP 3.0.2, pinned at
  `687bcdcf67d56a3bdfe3bbc4ff1ae863239e8c8a`; include a reference manifest and
  keep the upstream MIT attribution.
- Unify history, portfolio, project, comparison and report navigation through one
  escaped Go shell template. Adopt compact header/navigation geometry and the
  continuous content canvas.
- Separate parent navigation from disclosure controls, current-page markers from
  ancestor emphasis, and open report/comparison views from project children.
- Add accessible desktop collapse/tooltips and a responsive modal navigation drawer
  with inert background, focus confinement, Escape/scrim close and focus return.
- Align filter labels/hints/controls/feedback on shared tracks, including grouped
  actions and persistent project-suggestion indicators. Add table-scoped density.
- Add System appearance alongside four themes, RTL/reduced-motion/forced-color
  behavior, focusable table regions and report column sort semantics.
- Align browser error pages with the application shell while retaining HTTP/API
  contracts. Report import errors preserve the prior view and active filter.
- Expand consumer UI tests and refresh synthetic demos. Scanning commands, batch
  schema, SQL schema and module pins are unchanged; production build and native
  browser/service acceptance limits remain recorded in TESTING.md.


## 0.5.0-preview — 2026-10-03

- One batch manifest and embedded JSON Schema for directories and GitHub repos;
  strict validation, explicit settings precedence, sequential jobs, atomic summaries,
  fail-fast option and per-project reports/history.
- GitHub REST commit/archive acquisition without Git; canonical project inference,
  environment-only token handling, destination-restricted redirects, checksum cache,
  bounded safe extraction, and exact-commit offline reuse. Partial sources fail
  required coverage rather than appearing clean.
- `serve` now defaults to the all-project portfolio; explicit report-directory mode
  and `--history` compatibility retained. Latest-state daily aggregation prevents
  duplicate scan totals and separates incomplete/stale evidence.
- Dashboard/table tabs for portfolio, projects and comparisons; shared Sekura
  semantic design, themes, navigation, and portable-report tabs/state.
- Batch/source provenance stored in existing report JSON; SQL schema stays v1.
- Release ZIPs include the canonical schema, examples, guides and upstream MIT notice.
- Fixed inventory-only `--no-store` reports losing their explicit project identity.
- Production build, live upstream scanners/GitHub, remote databases and native
  platform runs remain unverified in the authoring environment; see TESTING.md.

## 0.4.1-preview

Added a visible exact project-key filter with bounded live suggestions in history,
project switching in the run dashboard, and `serve --history --project NAME` for a
fixed-project local view. Project identity is preserved across pagination, charts,
comparison links, and stored-run routes. Duplicate/invalid project filters and
wrong-project reports/comparisons are rejected. Switching projects clears old
comparison selections. Fixed mobile filter layout.

Added typed-target scan shorthand (`sekscan dir:/path --project NAME`) while keeping
project validation and named commands unchanged. The original explicit `scan`
syntax remains supported. Added resolved-target diagnostics and regression tests
for absolute/relative paths, spaces, trailing separators, and symlinks, including
managed scanner subprocess argument checks outside the workspace. No process-wide
working-directory change or source-root configuration discovery was introduced.

Corrected an existing history test to use a test-owned project identity instead of
attempting to rename the named demo report during import. Import immutability is
unchanged. Added project-filter CLI/SQL/HTTP/browser tests. Schema v1 and module pins
are unchanged. Source preview only; real scanner and production-driver validation
remain outstanding.


## 0.4.0-preview

Required explicit project names for every scan through `--project` or `project.key`,
including SQLite and `--no-store`; removed implicit local-path identity for new
scans. Existing immutable history and schema v1 remain unchanged. Baseline-file
scans and stored comparisons require matching named projects/namespaces.

Added project-first history, paged project/run summary queries for all three SQL
dialects, bounded trend APIs, five project graphs, two-run finding/component
comparisons, and before/after severity/category charts. Incomplete or changed
coverage and scanner versions keep absent findings unverified. Added filtering,
page sizes, page jump, and first/previous/next/last navigation across history,
comparison, and portable-report lists. Cross-page comparison selection works without
browser storage. Fixed run-report back links hidden by the portable sidebar.

Breaking API change: history JSON lists and `/api/scans` now use page envelopes
rather than bare arrays. Full comparison JSON export remains explicit.

Replaced platform-dependent archive packaging with a common standard-library Go
release helper, Bash/PowerShell wrappers, five-platform ZIP matrix, docs/config/
schema bundles, platform-specific README plus identical `readme.med`, source ZIP,
checksums, module inventory, and manifest. Build inputs are read-only and output is
published only after every requested target passes. The helper rejects test-only SQL
adapters/local module replacements and excludes live workspace data. Added release
packaging, comparison, pagination, and browser integration tests and documentation.

Source preview only: production dependencies, actual five-target executable builds,
live scanner/database integration, signing, and native non-host tests are outstanding.

## 0.3.0-preview

Fixed Syft directory exclusion prefixes and made blocked Grype dependency status explicit. Added safe diagnostic hints and opt-in private stderr logs, shared native scanner cache/environment configuration, managed-only portable execution by default, relative installation/lock metadata, platform and path containment checks, stricter Grype/Trivy database readiness, and independently reported DB update steps. Preparation now installs workspace copies regardless of system PATH and verifies newly installed versions.

Added optional managed actionlint workflow validation without system helper dependencies, consistent SQLite VACUUM INTO backups, and a rollback-capable connected Go-module updater. Selected Go 1.27.1; current direct database module versions were verified and retained, not independently upgraded beyond upstream SQLite/libc compatibility. Added relocation, invocation, database-readiness, diagnostic privacy and backup tests. SQL schema remains version 1.

This remains a source preview: production dependency resolution, real upstream scanner downloads and PostgreSQL/SQL Server integrations were not validated here.

## 0.2.0-preview

Renamed the executable/module/environment/configuration prefix to `sekscan` / `SEKSCAN_`. Added explicit/local configuration discovery, a workspace initializer, standard native and extension configs, configured tool/cache/log/data directories, per-invocation JSONL log rotation, native config hashing, managed custom GitHub release recipes, update inspection and preparation mode.

Added a versioned scan-history schema and SQL adapters for SQLite, PostgreSQL and Microsoft SQL Server; immutable transactional scan and SBOM storage; schema export/migration/status commands; history import/list/export; and a loopback history browser. Added SQLite transaction/concurrency tests and opt-in external-server integration tests.

This is source-only preview delivery. Production dependency builds and live PostgreSQL/SQL Server/scanner integration were not verified in the authoring environment. See TESTING.md.
