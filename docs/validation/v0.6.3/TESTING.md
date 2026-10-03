# Validation record — sekscan 0.6.3-preview

Date: 2026-10-03. Source update for Semgrep execution/readiness, the repository
README, and release-published-only automation. No production binary, scanner wheel,
runtime bundle, or CVE database is included in this source package.

## Results

| Check | Result |
|---|---|
| Application test / named-subtest entries | 435 passed; 2 external database tests skipped; 0 failed |
| Application race detector | Passed using the test-only system-SQLite adapter |
| Application go vet | Passed using the same test modfile/build tag |
| Statement coverage | 68.5% |
| Existing Go release helper | 15 test / named-subtest entries passed; go vet passed |
| Python release-control tests | 17 unittest methods passed, with additional subtest cases |
| Workflow YAML checks | Parsed; release.published-only trigger, permissions separation, and full action commit pins checked |
| Local documentation links | README and new guides checked; no missing local targets |
| Old launcher reproduction | 0.6.2 starts the synthetic CLI on worker import instead of returning |
| Patched launcher | Safe worker import plus an actual Python multiprocessing spawn exercise passed |
| CLI smoke | Version identifies 0.6.3-preview and TEST-ONLY drivers; missing Semgrep self-test returns JSON and exit 2 |
| Production build attempt | Toolchain download failed due to network/DNS restrictions; no production binary built |

Go counts include parent tests and named subtests, not individual assertions. The
external database skips require PostgreSQL/SQL Server services. Evidence is in
`docs/validation/v0.6.3/`. The UI and SQL schema are unchanged; no new browser run,
Windows/macOS native acceptance, or manual screen-reader test is claimed.

## Semgrep tests

- Synthetic wheel metadata and host test Python verify the published `pysemgrep`
  entrypoint, `__main__` guard, actual spawn worker startup, and relocation with spaces.
- Missing bundled semantic_version is rejected even when a host Python dependency
  could otherwise be imported. The production path still uses managed Python only.
- Existing checksummed runtime bundles use the current application launcher without
  being rewritten. Relocation and launcher-cache regeneration retain bundle integrity.
- Full preparation and explicit self-test require a known-positive synthetic native
  finding. Empty/invalid SARIF, no finding, failed invocation, and operational warnings
  or configuration errors are rejected. Version output alone cannot pass the check.
- A fixture native-engine failure leaves no installed current.json. Private diagnostics
  are captured separately and fixed error hints do not expose sentinel source content.
- Same-version verified bundles are reused rather than overwritten. Explicit custom
  command prefixes remain authoritative.
- The built-in adapter uses the selected source directory, primary SARIF output,
  stable rule IDs, and strict error handling. stdout, stderr and operational SARIF
  error channels are classified while the engine remains failed.
- The new `deps test semgrep` CLI does not require an application project name. It
  returns operational failure for missing tools and rejects unsupported tool self-tests.

These tests do **not** execute the real Semgrep 1.179.0 wheel/native engine. Go
orchestration uses controlled executor fixtures; Python tests use a synthetic CLI
and synthetic distribution metadata. The unsafe old launcher is a reproduced
application defect, but the user's original exit-2 cause remains unconfirmed without
private diagnostics. The source/rules/platform used in that scan were not provided.
A successful tiny self-test does not prove that every project rule or language works.

## Release-control tests

Tests use local temporary Git repositories, synthetic archive bytes, and mocked
GitHub CLI/API responses. They verify published-only events, stable/prerelease tag
validation, rejection of injected/invalid tags, exact commit matching, committed
module-file requirements, five-platform artifact sets, checksum/source seals,
no publication after a moved tag, immutable-release rejection, and no overwrite of
conflicting existing assets. A partial upload can resume only with matching digests.

No workflow was pushed and no GitHub release/assets were created. Hosted runner
execution, authenticated uploads, remote API behavior, full production cross-builds,
signing, and native-platform smoke tests remain connected acceptance work.

## Reproduce locally

The authoring environment provides Go 1.23.2 and Python 3.13.5 on Linux x86-64. Its
production toolchain/modules cannot be downloaded. The alternate modfile and
system-SQLite bridge are test infrastructure, not release drivers.

```bash
GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=1 \
  go test -modfile=go.offline.mod -tags=offline_sqltest -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=1 \
  go test -modfile=go.offline.mod -tags=offline_sqltest -count=1 -race ./...
GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=1 \
  go vet -modfile=go.offline.mod -tags=offline_sqltest ./...
(cd scripts/release && GOTOOLCHAIN=local GOPROXY=off go test -count=1 ./...)
(cd scripts/release && GOTOOLCHAIN=local GOPROXY=off go vet ./...)
python3 -m unittest discover -s scripts/tests -v
```

On a connected machine run `bash scripts/build.sh`, review/commit module files,
then use `deps test semgrep` and the recovery guide before scanning the real target.
The existing opt-in `scripts/live-smoke.sh` now also checks Semgrep after workspace
relocation. It was not run against live downloads in this environment.
