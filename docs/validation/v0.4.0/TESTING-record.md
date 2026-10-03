# Validation record — sekscan 0.4.0-preview

Date: **2026-10-02**. This records executed checks separately from outstanding
production acceptance. Machine-readable logs are in `docs/validation/v0.4.0/`;
older version directories are historical evidence, not new runs.

## Build boundary

This is a **source preview**, not a production binary release. The environment has
Go 1.23.2. The production module requires at least Go 1.26.0 and selects go1.27.1.
Attempting the selected toolchain failed at DNS access to `proxy.golang.org`; see
`production-toolchain-attempt.json`. There is no generated or fabricated `go.sum`.
The release script correctly rejected the unresolved module state instead of
publishing platform archives (`release-preflight.txt`).

Local Go tests used `go.offline.mod`, `GOTOOLCHAIN=local`, `GOPROXY=off`,
`CGO_ENABLED=1`, and the explicit **test-only `offline_sqltest` tag**. This excludes
the three production SQL drivers and uses a small CGo bridge to actual system SQLite.
It tests SQL, transactions, CLI workflows, and HTTP history behavior, not the
`modernc.org/sqlite` production-driver build. A test-only executable identifies
itself as such and is not distributed as the application. The release helper rejects
that tag, CGo builds, absent production modules, and local module replacements.

## Checks executed

| Check | Result and scope |
|---|---|
| Application Go tests | **145 passing test/subtest/fuzz-seed cases**, 90 passing top-level cases; 2 live-server subtests skipped |
| Application statement coverage | **58.9%**, 3050/5175 instrumented statements; includes test infrastructure |
| Application race detector | Passed for `offline_sqltest` |
| Application `go vet` | Passed for `offline_sqltest` |
| Release-helper Go tests | **15 passing test/subtest cases**, 10 top-level cases |
| Release-helper coverage | **49.1%**, 231/470 statements |
| Release-helper race detector / vet | Both passed |
| Portable dashboard browser smoke | **14 checks passed** |
| Project/history/comparison integration | **22 checks passed** |
| Bash, JavaScript, Python syntax | Passed for bundled scripts and UI assets |
| YAML / standard JSON config parsing | Passed |
| SQL schema exports | All three match bundled scripts apart from generated export timestamp; schema v1 unchanged |
| Standalone SQLite bootstrap SQL | Executed successfully against system SQLite; 7 application tables |
| Bash release target listing | Passed; reports the intended five targets |
| Release missing-module preflight | Refused as designed; no release directory published |
| PowerShell wrapper execution | **Not run**; PowerShell is unavailable here |

Passing counts exclude skipped PostgreSQL/SQL Server child cases. Parent tests and
fuzz seed entries appear separately in the Go JSON event stream; these are not
145 independent end-to-end scanner integrations. No new fuzz campaign, benchmark,
or scale certification is claimed.

## New coverage in this revision

Project validation rejects missing names, leading/trailing whitespace, control
characters, and overlong keys. It accepts quoted human-readable names and tests the
required project behavior even when persistence is disabled. Tests cover required
baseline identity and immutable report metadata.

SQLite query tests exercise project counts/latest summaries, deterministic paged
run ordering, exact project filters, empty/out-of-range pages, date/branch filtering,
truncation of trend windows, malformed pagination, escaped search, and namespace
isolation. SQL parameter binding and paging syntax cover the PostgreSQL/SQL Server
adapter paths without claiming execution against those servers. The optional live
server integration tests now include project pages, run pages, and trends in
addition to migration/write/read.

Comparison tests check finding and component states; before/after field evidence;
summary deltas; immutable input reports; package/version/license identity; ambiguous
fingerprints; different projects, namespaces, target kinds, report schemas, and
reversed pairs. Incomplete coverage, changed configs/checks/branches, application
versions, or scanner versions leave missing findings unverified. Database metadata
changes generate warnings. Different-version packages are not silently merged.

HTTP tests exercise page envelopes, project filtering, JSON/content escaping,
comparison restrictions, invalid query bounds, namespace scoping, and existing
Host/Origin/read-only protections. The history workflow script imports **synthetic**
records into real system SQLite through the test-only app, performs CLI queries and
exports, then fetches the live localhost routes and assets.

Browser checks cover project paging, page sizes, five project charts, comparison
selection across pages, two comparison charts, findings/component differences,
incomplete coverage warnings, run/date/branch filtering, per-report paging controls,
correct back-navigation, a 390-pixel mobile viewport, and no uncaught JavaScript
errors. The history server also passes orderly shutdown and log-file checks.

**Browser limitation:** managed Chromium blocks localhost address-bar navigation.
Playwright renders actual server HTML/CSS/JS with `set_content`; click/form navigation
is replayed over real HTTP by the test harness. This exercises rendered controls and
server responses but does not establish native full-navigation behavior, all CSP
behavior, browser persistence policies, or operating-system save dialogs. Portable
export bytes are inspected in memory. OS/platform browser testing remains necessary.

Release-helper tests use clearly synthetic file payloads for archive-structure
checks, never counterfeit production release binaries. They cover all five ZIP
layouts, executable mode metadata, identical README/readme.med content, configs and
empty workspace directories, sorted/repeatable ZIP entries, checksums, source
allowlists excluding live workspace secrets/data, symlink rejection, target/version
validation, build-environment sanitization, build-info verification, read-only module
integrity, and no-overwrite/missing-input guards. No genuine five-target production
compiler run or end-to-end reproducibility claim follows from these tests.

Existing regression coverage includes installer archive/checksum/version controls;
managed copies despite system PATH tools; relocated portable caches/configs;
Syft exclusion syntax and dependent Grype skip reasons; readiness checks; diagnostic
privacy; scanner parsers; application-license expressions and exceptions; SARIF/JUnit
exports; immutable SQLite snapshots/SBOMs; transaction/foreign-key/concurrency tests;
TLS/DSN guards; and consistent SQLite backups. Scanner fixture executables are
synthetic programs, not upstream security engines.

## Reproduce local checks

```sh
bash scripts/test-offline.sh
# Requires a C compiler and system SQLite development headers/library.

(cd scripts/release && GOTOOLCHAIN=local GOPROXY=off go test -count=1 ./...)
(cd scripts/release && GOTOOLCHAIN=local GOPROXY=off go vet ./...)

GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=1 \
  go build -modfile=go.offline.mod -tags=offline_sqltest \
  -o /tmp/sekscan-test-only ./cmd/sekscan

python scripts/browser-smoke.py --chromium /usr/bin/chromium
python scripts/history-smoke.py --binary /tmp/sekscan-test-only \
  --chromium /usr/bin/chromium
```

Browser tests require separately installed Playwright and a compatible Chromium.
Neither is a runtime dependency of sekscan or its release builder.

## Connected acceptance still required

```sh
bash scripts/build.sh
# Review and commit generated go.mod/go.sum; do not disable checksum verification.
go test -race ./...

# Dedicated disposable services; verified-TLS URL DSNs supplied through secrets.
export SEKSCAN_TEST_POSTGRES_DSN='postgresql://...'
export SEKSCAN_TEST_MSSQL_DSN='sqlserver://...'
bash scripts/test-databases.sh

# Explicitly downloads/executes real upstream scanner releases and scanner databases.
bash scripts/live-smoke.sh --yes "$PWD/sekscan"

bash scripts/build-release.sh --version 0.4.0-preview --targets all
```

The live database script requires both DSNs and does not provision services. Tests
leave synthetic data in those disposable databases. Validate target server versions,
TLS handshakes, SQL query compatibility, and multi-agent workloads before deployment.

The scanner smoke test prepares real managed tools/data, relocates the workspace,
performs an offline source scan, and snapshots SQLite. It has not run here. It is not
a substitute for representative real images, registries, language fixtures, expected
failure tests, optional SAST runtimes, or native tests on each advertised OS/architecture.

Production dependency compilation, real scanners/CVE databases, Windows/macOS native
execution, PowerShell invocation, hosted CI workflows, release signing/notarization,
full-history load testing, security penetration testing, and all-transitive module
updates remain unverified. Release hashes are not publisher signatures. No multi-user
hosted dashboard or authorization boundary is claimed.

## Demonstration data

`examples/demo-report` and dashboard screenshots contain **synthetic findings**.
`CVE-2099` identifiers, package/version observations, and comparison evidence in these
fixtures are fabricated for UI testing, not verified vulnerabilities. The screenshots
show functionality, not a real application's security posture.
