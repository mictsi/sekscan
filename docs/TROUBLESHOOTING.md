# Scanner and database troubleshooting

Semgrep was removed in 0.6.5; its previous errors no longer apply to the current
scanner suite. See [the removal guide](SEMGREP-REMOVAL.md).

For `runtime directory links are unsupported` or Go checks running against a
metadata-only/non-Go target, apply [0.6.2 fixes](SCANNER-FIXES-0.6.2.md).

For zizmor source-location failures, govulncheck version-probe failures, gosec
package-loading errors and missing Semgrep installations in 0.6.0, see
[0.6.1 scanner fixes and recovery](SCANNER-FIXES-0.6.1.md).

## Scanning a directory other than the current folder

In 0.4.0, the command must begin with `scan`:

```sh
./sekscan scan "dir:/home/ghost/github/SekuraDesignMCP/" --project SekuraDesignMCP
```

`./sekscan dir:/...` was rejected as an unknown command before any scanner ran.
This is distinct from a scanner failing to access a directory. In 0.4.1, an explicit
typed target is also accepted as scan shorthand:

```sh
./sekscan "dir:/home/ghost/github/SekuraDesignMCP/" --project SekuraDesignMCP
./sekscan scan "dir:../another application" --project other-application
```

The project key is still required, either through `--project` or `project.key` in
configuration. Bare paths without a type prefix still require the `scan` command.
Relative targets are resolved from the caller's working directory, not from
`--home`. Paths are made absolute and symlinks resolved before scanners are started.
The normal log now includes `scan target resolved` with the chosen path and project.

`--home` selects the workspace containing binaries, databases, logs, and config; it
does not select the source directory. Use the same workspace used for preparation:

```sh
./sekscan prepare --home ./workspace --all --yes
./sekscan scan "dir:/home/ghost/github/SekuraDesignMCP/" \
  --project SekuraDesignMCP --home ./workspace \
  --diagnostic-stderr --out ./security-report
```

The application does not change its working directory to the target or load a
configuration merely because it is inside that target. Existing local/CI config
selection rules still apply. Missing paths and wrong target types fail before tool
execution. Read/search permissions on the target and its contents are still required;
no blanket permission changes or elevation are performed.

If the explicit scan command still produces a scanner error, inspect the private
stderr file under the selected workspace's `logs/` locally. Review and redact it
before sharing: these diagnostics may contain secrets. The argument-routing tests
use synthetic scanner executables; they do not establish that a particular upstream
scanner version can read every package or file in a user's repository.


## Syft exits 1 and Grype is skipped

The 0.2.0-preview directory adapter supplied exclusions such as `.git` directly.
Syft requires directory exclusions to start with `./`, `*/` or `**/`. The 0.3.0-preview
adapter emits `./.git` and `./.git/**`, and uses absolute container-root exclusions
for image targets. A regression fixture now rejects the old argument shape.

The user's two log lines do not contain Syft's underlying stderr, so this defect
cannot establish the cause of every exit 1. Invalid native configs, permissions,
unsupported options, image credentials and unavailable targets can fail as well.

Grype depends on a successfully generated inventory. If Syft fails, Grype does not
run at all, including its DB auto-update. The new report explicitly says that it was
blocked by Syft rather than implying that Grype checked or downloaded its database.

After rebuilding the updated source:

```sh
sekscan prepare --home ./workspace --all --with-java --yes
sekscan db status --home ./workspace --all --with-java
sekscan scan dir:/path/to/project --project my-service --home ./workspace --diagnostic-stderr --out ./security-report
```

Inspect the `syft-stderr-*.private.log` in that workspace's `logs/` **locally**. Raw
scanner text may contain secrets and must be reviewed/redacted before sharing.
The normal application log returns fixed hints for common errors without quoting
arbitrary stderr into HTML, SQL or CI logs.

## Grype database not found after preparation

Use the same `--home` and trusted `--config` for preparation, status and scanning.
The scanner and DB updater now share one environment builder. Grype is directed to
`cache/grype/db`; both Trivy CLI arguments and environment use `cache/trivy`.
Default portable mode ignores system PATH copies and host-home caches.

`db update --all` attempts each selected data preparation step and reports failures
independently. It performs a readiness check afterward. Grype's normal online scan
still has DB auto-update enabled; offline mode disables that update and requires
usable local data. `db status` is read-only and does not repair/download the cache.

Check disk space, outbound HTTPS/proxy access, a valid trusted CA chain, registry
rate limits, and whether the binary and cached schema belong together. Do not turn
off certificate verification or DB-age checks merely to make a gate pass.

## Missing managed binaries

```sh
sekscan deps check --all --home ./workspace --json
sekscan prepare --all --update-tools --yes --home ./workspace
sekscan doctor --all --home ./workspace
```

A globally installed tool no longer satisfies preparation. The installer downloads
a separate checksum-verified executable into the selected workspace. Version or
checksum pins may intentionally prevent an upgrade; edit them through a reviewed
policy change. An unsupported OS/architecture or upstream asset layout produces an
explicit installation error, not an implicit PATH fallback.

## Production build/module downloads

The source selects Go 1.27.1 and needs at least Go 1.26 for the pinned SQLite module.
A compiler/module-download failure is separate from the scanner failure. Review
`docs/MODULES.md` and the retained validation output; the authoring container could
not download the production graph. Do not release the test-only SQLite executable.


## New default checks in 0.6

Old explicit false values remain effective. Use `config enable-default-scanners
--config OLD --out NEW` to generate a reviewed expanded config; select that file in
both `prepare` and `scan`. `prepare --all --yes` now includes Hadolint, workflow/source
analyzers and their supported workspace-local runtime recipes.

A required missing analyzer/runtime is an incomplete result, not silently skipped.
No discovered applicable input is not applicable; inspect the Scan health reason.
Use `--hadolint=false`, `--zizmor=false`, `--govulncheck=false`, or `--gosec=false` only as a deliberate coverage/policy choice. Inventory-only still
turns off all source analysis.

For Go DB errors, run `db update` and `db status` against the same workspace. Go's
vulnerability database is distinct from Grype's. For missing Go modules, explicitly
run `prepare --go-module /path/to/module --yes` before scanning; this may update
that project's go.sum. Analysis itself uses local/readonly modules, CGO disabled
and each module independently. Private modules, CGO projects, platform build tags,
or a Go version newer than the prepared SDK require reviewed prerequisites.

Semgrep is no longer installed or executed. Upgrading does not require fixing its
previous native runtime error; see [SEMGREP-REMOVAL.md](SEMGREP-REMOVAL.md).

Built-in govulncheck version probes use a local version-only DB so `doctor` does not
need to download the vulnerability snapshot just to identify the scanner version.
Use `db status` for real scan-readiness checks.
