# Default source scanners — 0.6.5-preview

## Go applicability

Go activation requires module-owned `.go` source, not merely a `go.mod` file or a
Go-based scanner installed under the workspace. With no applicable module, Go
checks are skipped/not required before resolving executables or databases. An empty
parent module does not inherit evidence from a nested module. Genuine Go compiler,
module metadata and checksum failures remain incomplete. See
[0.6.2 recovery](SCANNER-FIXES-0.6.2.md) for historical details; the current Semgrep removal is documented
in [SEMGREP-REMOVAL.md](SEMGREP-REMOVAL.md).

## Activation and result semantics

Normal directory scans, GitHub snapshots and batch entries inherit the same suite.
Existing explicit false values stay false. An explicit same-name `extensions[]`
definition replaces its catalog entry, preserving user configuration. In that case,
its own `required`, offline, arguments and parser settings govern execution.

| Check | Applies to | Output into sekscan | Native configuration | Prerequisites |
|---|---|---|---|---|
| Gitleaks | Directory/rootfs file snapshots | Secret findings | Generated config, or reviewed gitleaks.toml override | Managed gitleaks |
| actionlint | .github/workflows YAML files | Misconfiguration findings | config/actionlint.yaml | Managed actionlint; external helpers disabled |
| Hadolint | Dockerfile, Containerfile, prefix/suffix variants recursively | Native JSON → misconfiguration findings | config/hadolint.yaml | Managed hadolint; no Docker or CVE DB |
| zizmor | Workflows and action.yml/action.yaml files | SARIF → misconfiguration findings | Fixed offline/no-config invocation; custom definition for alternatives | Managed zizmor |
| govulncheck | Each discovered go.mod directory with its own Go source, including nested modules | SARIF → code findings | Managed local DB URL and controlled arguments | Managed govulncheck, Go SDK, prepared dependency cache and Go vulnerability DB |
| gosec | Each discovered go.mod directory with its own Go source, including nested modules | Native JSON → code findings | config/gosec.json | Managed gosec, Go SDK and prepared dependency cache |

Syft, Grype and Trivy retain their existing default responsibilities. Trivy's second
vulnerability matcher stays off unless explicitly enabled. Gitleaks scans current
files, not Git history. Source checks do not run against image/archive/SBOM targets;
rootfs additionally supports Gitleaks. A Dockerfile is not a built-container scan.

No matching input is **skipped / not required**, with its reason recorded. A missing
applicable tool, runtime, needed DB, invalid result, timeout, parse/processing error
or declared coverage failure produces **failed / required**, making the final scan
incomplete (exit 2). Findings from successful inputs are retained even if another
input fails. Policy failures from completed scans remain exit 1.

Hadolint is invoked once per selected Dockerfile, zizmor once per workflow/action,
and Go analyzers once per selected module. Configured exclusion paths and operational
bin/cache/log/data paths are excluded from discovery. Discovery also skips .git,
node_modules, vendor and .venv. Symlinks are not followed; matching symlinked files
fail coverage. Discovery is bounded at 250,000 entries / 1,024 matching file/module
inputs; split the project or use reviewed exclusions when the limit is reached.

Go `./...` analysis still loads imported packages. Discovery exclusions do not remove
individual Go files/imports from a call graph. GOPATH-only projects without go.mod
are not automatically selected. CGO is disabled, modules are analyzed independently
with GOWORK=off, and build constraints still affect coverage.

## First run

```sh
bash scripts/build.sh
./sekscan init --home ./workspace
./sekscan prepare --home ./workspace --all --with-java --yes
./sekscan doctor --home ./workspace --all
./sekscan db status --home ./workspace --all --with-java
./sekscan scan dir:/path/to/repo --project my-service --home ./workspace
```

The managed install/update mode downloads native scanners and the Go SDK. It builds
only the selected upstream govulncheck release using `go install` with Go module
checksum verification; it does not build the scanned project. `--yes` is explicit
approval to download and execute the selected prerequisites. No Python runtime or
Python package installer is provisioned by the default scanner suite. Compatible
native distributions are still required for each target platform.

## Existing workspace upgrade

```sh
./sekscan config enable-default-scanners \
  --config ./workspace/sekscan.json \
  --out ./workspace/sekscan-expanded.json
./sekscan config validate --config ./workspace/sekscan-expanded.json
./sekscan prepare --home ./workspace --config ./workspace/sekscan-expanded.json \
  --all --with-java --yes
./sekscan scan dir:/path/to/repo --project my-service \
  --home ./workspace --config ./workspace/sekscan-expanded.json
```

The output must not already exist. Policy, storage and tool pins are preserved, as
are non-retired explicitly configured extension overrides. Legacy Semgrep entries
are discarded; see [the removal guide](SEMGREP-REMOVAL.md). Defaults omitted from old configs
inherit the new true values; old explicit false values stay false until changed.
`init` and `prepare` never overwrite an existing native configuration.
SQL schema version 1, config version 2 and batch version 1 remain compatible.

## Controls and batch overrides

The main config supports these six source-check booleans:

```json
{
  "version": 2,
  "checks": {
    "gitleaks": true,
    "actionlint": true,
    "hadolint": true,
    "zizmor": true,
    "govulncheck": true,
    "gosec": true
  }
}
```

The corresponding scan/GitHub/batch CLI options accept `--name=false`. `--inventory-only`
turns off all source extensions. Applicability is automatic; it does not install
language prerequisites behind the user's back. `scan --install-missing --yes` can
install relevant missing tools, but normal scans do not upgrade executables or
prepare project dependencies. Prefer an explicit preparation step before CI scanning.

```json
{
  "version": 1,
  "defaults": {"hadolint": true, "gosec": true},
  "projects": [
    {"project": "api", "path": "../api"},
    {"repo_url": "https://github.com/your-org/service", "settings": {"gosec": false}}
  ]
}
```

## Go databases and dependencies

`prepare` / `db update` obtain the official Go vulnerability database bulk ZIP,
validate index/OSV membership, and store a checksummed snapshot under
`cache/govulncheck/<snapshot-sha>/`. `current.json` points to that local snapshot.
Go analysis always receives a local `file://` DB URL. Version probes also use a
small local DB because even a govulncheck version query can otherwise inspect its DB.
The local snapshot is included in database export/import and whole-workspace copies.
Freshness uses the download time, not the date of the latest published advisory.

Project dependencies are separate from the vulnerability database. Normal scans set
GOPROXY=off, GOTOOLCHAIN=local, GOFLAGS=-mod=readonly, GOWORK=off and CGO_ENABLED=0.
Warm needed modules explicitly on a connected machine:

```sh
./sekscan prepare --home ./workspace --go-module /path/to/go-module --yes
```

This runs `go mod download all` with the managed SDK and workspace module cache. It can
update go.sum; review that change. Repeat for each independently analyzed module.
It does not run project tests, generated code, installation hooks or a project build.
The built-in prefetch uses the public Go proxy/checksum service; private dependency
authentication needs a separately reviewed cache-preparation process. Do not pass
private package credentials to untrusted scanner jobs unnecessarily.

## Scope and suppressions

General multi-language SAST now requires an explicitly configured external analyzer.

Hadolint inline ignore pragmas are disabled by default; trusted native config can
still configure rule exclusions. gosec's native config disables inline nosec
suppression. zizmor deliberately runs offline audits only; network/API-dependent
audits are outside this default coverage. Scanner/ruleset changes remain security
policy changes, not cosmetic options.

## Privacy and failure handling

Hadolint parse failures (DL1000), gosec's `Golang errors` and zero-file statistics,
and SARIF unsuccessful execution/error notifications are not treated as clean runs.
Default extensions retain rule identifiers, severity and locations but redact
source-bearing messages/snippets from shared findings. Severity mapping for linters
is a policy convention, not CVSS or exploitability. govulncheck findings remain code
observations and do not silently reclassify Grype package vulnerabilities.

`--diagnostic-stderr` stores bounded raw stderr only in private local log files.
Those files may contain secrets and must not be published with reports. Portable
paths and offline options do not create an OS/network sandbox. Enforce permissions,
process limits and network isolation externally when required.

## Validation boundary

The source includes parser, controlled invocation, update/checksum, runtime-recipe,
relocation, database-export/import and regression tests. These use fixture executors,
not downloaded analyzers. Run the opt-in `scripts/live-smoke.sh --yes /path/to/sekscan`
on each connected target platform before approving a release. It prepares the expanded
suite, relocates its workspace and scans Go/Python/Docker/workflow inputs offline.
See [TESTING.md](../TESTING.md) for measured results and outstanding acceptance.

## Upstream interfaces consulted

- Hadolint CLI/configuration: https://github.com/hadolint/hadolint
- gosec native JSON and configuration: https://github.com/securego/gosec
- govulncheck: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
- Go DB API and bulk download: https://go.dev/doc/security/vuln/database
- zizmor: https://docs.zizmor.sh/

These are upstream references, not claims of live integration validation.

## 0.6.1 troubleshooting

See [scanner fixes](SCANNER-FIXES-0.6.1.md) for repository-relative zizmor paths,
local govulncheck version-probe schema, explicit transitive Go dependency prefetch,
and opt-in structured gosec processing diagnostics. Default activation is unchanged.

## Semgrep removal and existing workspaces

Semgrep support was removed in **0.6.5-preview**. Scans, `prepare --all`, update
checks and default prerequisite status no longer select it. The Python runtime
installer, launcher, native self-test and starter rules are no longer shipped.
There is no Semgrep replacement automatically enabled: general multi-language SAST
now requires a separately configured analyzer. Go SAST remains available via gosec.

Older `checks.semgrep` settings (true or false), Semgrep tool definitions and named
Semgrep extensions are ignored with a migration warning. Their unused built-in uv
helper is removed from the effective configuration too. Other scanners, policies,
version pins, custom integrations and database settings are preserved.

An optional cleanup command writes a **new** configuration without retired entries:

```bash
./sekscan config remove-semgrep --home ./workspace \
  --out ./workspace/sekscan-clean.json
./sekscan prepare --home ./workspace \
  --config ./workspace/sekscan-clean.json --all --yes
```

Rebuilding and using the new executable is enough; rewriting the configuration is
not required. Batch manifests still accept the deprecated boolean `semgrep` key as
an ignored compatibility field. The CLI flag `--semgrep` and native `deps test`
command are removed. An explicit `deps install semgrep` request returns a removal
message without downloading anything.

No scan history, findings, scanner files or caches are deleted automatically.
Historical Semgrep findings remain visible; removing a scanner does not establish
that its previous findings were fixed. No SQL migration is required. Old private
Semgrep logs should not be shared or published as normal artifacts.
