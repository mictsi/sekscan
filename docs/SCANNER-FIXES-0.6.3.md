# Semgrep scan readiness and recovery — 0.6.3-preview

> Historical guide for the named release. Semgrep was removed in 0.6.5; use
> [SEMGREP-REMOVAL.md](SEMGREP-REMOVAL.md) instead of its old repair commands.

The reported `scanner started ... semgrep version=1.179.0` shows that the executable
and Python CLI returned a version. It does not establish native-engine readiness.
Semgrep exit 2 is a general failure. With no private stderr or source, the exact
cause on the reported machine cannot be determined from those log lines alone.

## Implemented changes

- The Python launcher now uses a `__main__` guard, so spawn/forkserver workers can
  import it without recursively starting another CLI. A regression test demonstrates
  the old import-time failure; this is not proof it caused the user's Linux failure.
- Standard managed bundles use the current application's checksum-named launcher in
  `cache/launchers/`. The original `bin/semgrep/<version>` manifest and all runtime
  files remain unchanged. This avoids a same-version reinstall merely to fix launch.py.
- Built-in Semgrep runs with the selected source as working directory and uses
  `--sarif --output FILE` as its primary report. It no longer asks for additive
  SARIF alongside default text formatting. Rules still come from the explicitly
  selected native config, not automatic repository configuration.
- `--no-rewrite-rule-ids` keeps temporary/configuration path prefixes out of rule
  identities. Comparisons against old runs may show a one-time identity change;
  use a fresh baseline after review. No historical results are rewritten.
- Preparation tests Python imports, `semantic-version`, the bundled native engine,
  and a tiny positive scan before publishing a new runtime. Existing prepared
  standard bundles are also tested. A working version command is no longer enough.
- `deps test semgrep` repeats that isolated operational test without scanning a
  project. It fails when expected native-engine evidence is absent.
- Failed scans retain bounded stdout and SARIF invocation notifications in private
  local diagnostics when opted in. No raw messages, snippets, or credentials enter
  shared reports through the new error classifications. Generic exit 2 stays failure.

## Semgrep, semver, and semantic-version are different

The tool is **Semgrep**. Its wheel includes `semgrep-core`, the native analysis engine.
Its Python dependency is the package **semantic-version**, imported as
`semantic_version`. Semgrep 1.179.0 declares `semantic-version~=2.10.0`. It does not
require a separate Node.js `semver` command in bin. Do not install arbitrary packages
into system Python to repair a managed bundle.

The normal installed layout is:

```text
workspace/bin/semgrep/<version>/
  python/<managed-python-distribution>/.../python3.13 (or python.exe)
  site-packages/semgrep/
  site-packages/semgrep/bin/semgrep-core[.exe]
  site-packages/semantic_version/
  requirements.lock
  launch.py
```

The new runtime test reports the dependency's version and the selected core path.
It rejects a dependency imported from outside the bundle.

## Upgrade and diagnose without resetting the workspace

Build the extracted source on a connected machine:

```bash
bash scripts/build.sh
./sekscan version
# sekscan 0.6.3-preview
```

Then select the same workspace/configuration as the failing run:

```bash
WORKSPACE="/absolute/path/to/existing/workspace"
CONFIG="$WORKSPACE/sekscan.json"
# Use sekscan-expanded.json instead when that is the active configuration.

./sekscan deps test semgrep \
  --home "$WORKSPACE" --config "$CONFIG" \
  --diagnostic-stderr --json

./sekscan scan "dir:/absolute/path/to/application" \
  --project YOUR_EXISTING_PROJECT \
  --home "$WORKSPACE" --config "$CONFIG" \
  --diagnostic-stderr --out ./security-report-retry
```

An existing standard managed Semgrep installation uses the new launcher immediately.
A custom `tools.semgrep.command_args`, custom installation recipe, or same-name
`extensions[]` override remains authoritative. Review those definitions; the built-in
working-directory/output changes do not silently rewrite custom commands.

If the self-test passes but an application scan fails, inspect the selected local
rules, source parse/processing errors, and resource requirements. The synthetic test
is not validation of every configured rule or application language. Strict handling
of incomplete scans is retained.

For a missing installation:

```bash
./sekscan deps install semgrep \
  --home "$WORKSPACE" --config "$CONFIG" --yes --diagnostic-stderr
```

For a damaged/incompatible same-version bundle, stop scans and prepare processes,
back up its version directory and `bin/semgrep/current.json`, then move them aside
before a reviewed reinstall. Preserve policies/data/other tools. Installation will
not overwrite an immutable pinned runtime with different files. Updated runtime
contents require a newly reviewed checksum lock; do not bypass integrity checks.

## Private diagnostics

Under workspace `logs/`, depending on the failing stage:

| Pattern | Contents |
|---|---|
| `semgrep-version-stderr-*.private.log` | Failed version probe |
| `semgrep-selftest-stderr-*.private.log` | Failed synthetic test's stderr |
| `semgrep-selftest-stdout-*.private.log` | Failed synthetic test's stdout |
| `semgrep-stderr-*.private.log` | Actual analysis stderr |
| `semgrep-stdout-*.private.log` | Actual analysis stdout on failure |
| `semgrep-notifications-*.private.log` | Operational SARIF notifications |
| `semgrep-config-notifications-*.private.log` | Configuration SARIF notifications |

These files are bounded and owner-readable on POSIX. Private diagnostics may contain
sensitive paths/source/secrets; inspect and redact before sharing. They are not
published in report HTML or stored as new shared-database artifacts.

No SQL schema, production Go-module pins, batch schema, or UI assets changed.
Live Semgrep 1.179.0 execution on the user's machine remains acceptance work.
See [TESTING.md](../TESTING.md) for the exact local validation boundary.

## Primary references checked on 2026-10-03

- [Semgrep CLI flags and exit statuses](https://docs.semgrep.dev/cli-reference)
- [Semgrep 1.179.0 declared dependencies](https://pypi.org/pypi/semgrep/1.179.0/json)
- [Python safe importing of the main module](https://docs.python.org/3/library/multiprocessing.html#safe-importing-of-main-module)
