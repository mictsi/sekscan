# Semgrep readiness diagnostics and Windows ARM64 — 0.6.4-preview

> Historical guide for the named release. Semgrep was removed in 0.6.5; use
> [SEMGREP-REMOVAL.md](SEMGREP-REMOVAL.md) instead of its old repair commands.

## What the reported messages establish

`Semgrep was not installed because its native scan self-test failed` means that
preparation reached the runtime check but did not publish a managed installation.
Consequently `deps status semgrep` says **not installed**. The successful managed
zizmor, govulncheck and gosec entries do not need reinstallation for this error.

An exit code of 2 alone is not a diagnosis of the native failure. The user's raw
stderr, OS library details and runtime archive are not available here. This patch
**does not claim that the underlying native crash has been reproduced or repaired**.
It corrects a confirmed diagnostic defect and makes the failing stage observable
without treating incomplete preparation as success.

## Confirmed diagnostic defect and changes

Semgrep 1.179.0 only captures native RPC subprocess stderr when its log level is
DEBUG. The previous `--diagnostic-stderr` implementation saved existing CLI output,
but did not enable Semgrep's debug mode. Therefore even the private file could hold
only a generic RPC error rather than the native failure.

With 0.6.4, diagnostic mode passes `--debug` to the built-in Semgrep scan and to its
synthetic readiness scan. Normal logging remains unchanged. Custom extension
arguments remain authoritative; they are not silently rewritten.

The readiness probe is now divided into phases:

| Phase | Check | Interpretation on failure |
|---|---|---|
| `setup` | Controlled environment and temporary directory | Workspace, permissions or setup issue |
| `runtime-imports` | Managed Python, Semgrep metadata, semantic-version import and bundled core path | Missing/inconsistent bundle imports or metadata |
| `native-startup` | Execute the bundled core directly with `-version`; compare CLI/core versions | Native executable cannot start, or versions disagree; inspect native output |
| `selftest-scan` | One-worker scan of a synthetic Python file with explicit local rules and project root | Native/CLI scan execution failed; inspect the private debug output |
| `sarif-validation` | Parse SARIF, reject operational warnings/errors, require exactly the expected finding | Missing/invalid/incomplete evidence, even if the CLI returned zero |
| `complete` | Every check passed | Basic native readiness, not proof all languages/rules will work |

A failed test remains failed. There is no retry in a weaker mode, x64/PATH fallback,
self-test bypass, or automatic disabling of Semgrep. `--jobs=1` bounds the synthetic
test; it does not globally force the application's source scans to one worker.
The explicit project root isolates the test from ancestor source-control context.
These are deliberate controls, not asserted causes of the user's failure.

## Persistent local report

Every attempt that enters runtime readiness writes a unique local summary:

```text
logs/semgrep-readiness-<random>.json
```

The error returned to the CLI names this file. It records phase, status, version,
platform, completed checks, dependency/core metadata and any private diagnostic
paths. It survives removal of the failed staging directory. Core paths from failed
attempts may refer to removed staging; they are metadata, not installed locations.

The JSON contains no raw scanner output, full command line or environment dump.
It can contain local paths and error metadata, so review it before sharing. It is
written owner-readable on POSIX and is not a report/scan-history database artifact.
If the log directory cannot be written, `deps test --json` exposes `report_error`.
Failures before readiness begins (for example, download/unsupported-platform
errors or resolving a missing installation) do not create a readiness record.

With `--diagnostic-stderr`, output is captured privately:

| Log pattern | Evidence |
|---|---|
| `semgrep-runtime-imports-stderr-*.private.log` | Interpreter/import probe errors |
| `semgrep-native-startup-stderr-*.private.log` | Native executable startup errors |
| `semgrep-native-startup-stdout-*.private.log` | Native version/startup output |
| `semgrep-selftest-stderr-*.private.log` | Synthetic scan debug output, including available native RPC diagnostics |
| `semgrep-selftest-stdout-*.private.log` | Synthetic scan stdout |
| `semgrep-selftest-notifications-*.private.log` | Operational/configuration SARIF notifications, without the findings array |
| `semgrep-stderr-*.private.log` | Actual source-scan stderr, when opted in |

Empty streams do not create files. Existing output-size caps and private-file
permissions remain. Raw output can contain sensitive source, paths or credentials.
Never publish these logs as routine CI artifacts. Only fixed error classifications
are propagated into ordinary scanner error text. Review the phase and diagnostic
excerpt locally rather than posting an entire directory.

## Apply using the existing workspace

Build the new executable from the extracted source directory on a connected machine:

```bash
bash scripts/build.sh
./sekscan version
# sekscan 0.6.4-preview
```

Replace the old executable with that rebuilt file, then run in the **original
workspace**, preserving its current configuration discovery or explicit `--config`:

```bash
cd /home/ghost/lab/sekscan

./sekscan deps install semgrep \
  --home . \
  --yes \
  --diagnostic-stderr
```

Installation must succeed before `deps test` can inspect an installed bundle:

```bash
./sekscan deps status semgrep --home .
./sekscan deps test semgrep --home . --diagnostic-stderr --json
```

If preparation fails again, inspect the readiness-report path printed in the error.
The relevant phase-specific file contains the next diagnostic evidence; repeatedly
running `prepare --all` is not a substitute. Do not delete working scanners, databases,
checksums or policies. The same-version bundle integrity rules remain unchanged.
A native startup error may need a compatible upstream build or host-library/policy
correction, but choose the remedy only from the actual diagnostic evidence.

No SQL migration, source rescan, scanner-suite reset or Go dependency update is
required to install this application patch. No separate `semver` executable is
required. `semantic-version` is a Python dependency inside the managed bundle.

## Windows ARM64 releases

The release builder and publisher now share `scripts/release/targets.json`:

```text
linux/amd64    linux/arm64
windows/amd64  windows/arm64
darwin/amd64   darwin/arm64
```

After resolving/reviewing production module files, build all six targets or just ARM64:

```bash
bash scripts/build-release.sh --version 0.6.4-preview --targets all
bash scripts/build-release.sh --version 0.6.4-preview --targets windows/arm64
```

Use distinct output directories or run only the desired command; the builder does
not overwrite an existing release output directory. The Windows ARM64 archive is
`sekscan-0.6.4-preview-windows-arm64.zip`, containing native `sekscan.exe`, docs,
schemas and the clean portable workspace template.

The GitHub workflow still runs only for `release.published`, checks out the release
event's commit, verifies its tag and rejects conflicting existing assets. Its
`--targets all` and upload seal now require Windows ARM64. No release was uploaded
by this patch.

**Application targets and scanner platforms are distinct.** Semgrep 1.179.0 publishes
`win_amd64` but no `win_arm64` wheel. Windows ARM64 preparation checks the selected
version's PyPI metadata and rejects that unsupported native combination before
runtime download. Future wheels still require a compatible managed interpreter,
uv distribution and all dependencies; a wheel filename alone is not runtime acceptance.
Other scanners can also lack a Windows ARM64 asset. Do not treat an unavailable
required scanner as completed or silently run an x64 binary instead.

## References and validation

Verified on 2026-10-03:

- Native RPC capture policy: https://github.com/semgrep/semgrep/blob/v1.179.0/cli/src/semgrep/rpc.py
- Core selection: https://github.com/semgrep/semgrep/blob/v1.179.0/cli/src/semgrep/semgrep_core.py
- CLI debug, project-root, jobs and exit codes: https://docs.semgrep.dev/cli-reference
- Published 1.179.0 wheels: https://pypi.org/pypi/semgrep/1.179.0/json

Tests exercise orchestration, synthetic executables, direct Python launching,
private logging and release guards. No real Semgrep wheel/native scan ran in the
restricted authoring environment. A Windows ARM64 dependency-package test binary
was cross-compiled and inspected; it was not a production app or a native Windows
execution. See [TESTING.md](../TESTING.md) for the complete boundary.
