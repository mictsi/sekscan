# Configurable scanners and prerequisites

The default source catalog now enables Hadolint, zizmor, govulncheck, and gosec on applicable inputs. Gitleaks/actionlint are also enabled by default. See [DEFAULT-SCANNERS.md](DEFAULT-SCANNERS.md) for prerequisites and upgrade instructions.

Built-in inventory/native-output parsing remains Go code. Execution settings, native config files, version probes and GitHub release installation recipes are data. Additional scanners that produce SARIF 2.1.0 can join the normalized report without recompiling sekscan.

## Built-in native settings

In a root `sekscan.json`:

```json
{
  "version": 2,
  "tools": {
    "trivy": {
      "version": "latest",
      "native_config": "config/trivy.yaml",
      "extra_args": ["--quiet"]
    }
  }
}
```

Explicit CLI arguments control output location/format, required scanner selection and gate behavior. The extra-argument validator rejects common overrides of these options. It is not a complete semantic validator of every present/future upstream flag. Native configs and permitted options can still change exclusions, enrichment or coverage; review them as security policy. They are not safe inputs from an untrusted pull request.

Native config files must be regular readable files within the configured size limit; their content hashes are recorded in the engine run. Existing native configs are never overwritten by `init` or `prepare`. A tool needing several native files can receive additional reviewed arguments; sekscan does not invent a generic configuration model for every scanner.

## SARIF extension

```json
{
  "version": 2,
  "extensions": [{
    "name": "company-sast",
    "executable": "bin/company-sast/company-sast",
    "native_config": "config/company-sast.json",
    "args": ["scan", "--config", "{native_config}", "--format", "sarif", "--output", "{output}", "--", "{target}"],
    "version_args": ["--version"],
    "targets": ["dir"],
    "success_codes": [0, 1],
    "working_directory": "isolated",
    "output_source": "file",
    "timeout": "10m",
    "required": true
  }]
}
```

`company-sast` is hypothetical. Use the actual executable's documented argv and completed-analysis exit codes. Exit 1 must not be accepted generically: for some tools it means execution failure, not findings.

Each argument is passed separately without shell expansion. Placeholders are `{target}`, `{output}`, `{sbom}` (completed Syft JSON inventory), and `{native_config}`. A required missing SBOM/native config fails the extension. `output_source` may be `file` (default) or `stdout`; stdout must contain only valid SARIF, not progress logs or streaming JSON. A SARIF invocation explicitly reporting unsuccessful execution fails the engine. The adapter cannot infer coverage that a scanner does not describe.

Working directory is isolated by default. `working_directory: "target"` is explicitly available only for directory/rootfs targets, useful for module-aware Go tools. That can expose project-local configuration/tooling to the analyzer and is a deliberate trust decision. Explicit executable paths with separators and native config paths resolve relative to the selected JSON file; a bare executable name uses PATH only when `portable: false`. Default portable mode requires a managed `tool` reference or a workspace-bin executable; system tool paths are not permitted.

Generic extension results use category `code` by default with engine-prefixed rules. `category` may instead select `misconfiguration` or `vulnerability`. A govulncheck result is therefore not reconciled into Grype package vulnerabilities or used to declare other findings unreachable. Scanner-specific code-flow graphs and every SARIF property are not preserved by the minimal adapter. Do not treat it as a full SARIF round-trip repository. General SARIF messages may contain secrets; set `redact_messages: true` to omit source-bearing title/message text. Default catalog definitions enable this. Additional SARIF properties and external tool output still require review.

Custom extensions are disabled in offline mode unless `offline: true` is explicitly
set. This declares support; it does not sandbox the program or enforce egress. All
default catalog source analyzers use local/offline execution. Inventory-only disables
all source extensions.

`when` selects `all` (normally the omitted default), `source`, `go-modules`,
`workflows`, or `dockerfiles`. Since 0.6.2, an omitted selector on an extension
named `govulncheck`/`gosec`, or referencing one of those managed tools, defaults to
`go-modules`. This repairs unconditional activation from legacy examples. Explicit
selectors (including `all`) remain authoritative; args/working-directory/runtime
requirements are still owned by that custom definition.

`go-modules` selects each non-excluded go.mod directory with its own visible `.go`
source. Nested modules are separate ownership boundaries; source under Go-ignored
package paths cannot activate the parent module. Applicability does not execute Go,
load dependencies or validate compilation. Real Go analysis failures do not become
not-applicable results.
No applicable inputs means skipped/nonrequired. `{inputs}` expands into separate argv
elements; file/module selectors run once per input. `{govulndb}` is reserved for the
built-in govulncheck adapter, which verifies its local snapshot first. A custom adapter
can use an explicit reviewed DB location. `requires_tools` lists managed runtime
prerequisites. `parser` may be `sarif` (default), `hadolint-json`, or `gosec-json`.
These are named built-in parsers, not an arbitrary JSON transformation language.

`checks.NAME=false` disables a catalog default. It does not disable an explicit
custom `extensions` entry of the same name. Such an entry replaces the catalog
entry and supplies its own required/offline/parser behavior. Duplicate custom names
are rejected. Builtin implementation markers are not user-supplied JSON fields.

## Managed tools referenced by extensions

Replace `executable` with `tool: "company-sast"` to resolve a managed tool entry. The tool's native config is inherited when the extension does not override it. Core built-in `extra_args` are not automatically appended to custom extensions: their `args` vector defines the invocation.

```json
{
  "tools": {
    "company-sast": {
      "version": "1.2.3",
      "version_args": ["--version"],
      "install": {
        "repository": "your-organization/company-sast",
        "executable": "company-sast",
        "assets": {
          "linux/amd64": "company-sast_{version}_linux_amd64.tar.gz",
          "windows/amd64": "company-sast_{version}_windows_amd64.zip"
        },
        "checksums": "company-sast_{version}_checksums.txt"
      }
    }
  }
}
```

This is a template, not a published scanner. Assets must be safe basenames and are selected explicitly by OS/architecture. `{version}` omits a leading `v`; `{os}`/`{arch}` use Go names. The archive must contain the exact executable at its root (`.exe` on Windows). SHA-256 checksum manifests, independently configured archive pins and available GitHub asset digests are checked. Custom recipes do not support arbitrary download hosts, nested executable layouts, shell install hooks or publisher-signature validation. Special built-in recipes support Hadolint raw executables, zizmor/uv release-asset digests, the Go SDK and fixed govulncheck runtime preparation. These do not enable arbitrary package-manager command strings in JSON.

`config/tools-gosec.json` is a real release-layout example verified against gosec's published release listing, but it has not been downloaded/tested live here. It describes the release installer; `checks.gosec` now enables a native JSON adapter. That adapter inspects `Golang errors` and file statistics, because `-no-fail` alone is not proof of completed analysis.

## Built-in workflow validation

actionlint is enabled by default when workflows exist; `--actionlint=false` disables its managed standalone adapter. `prepare --all`
installs it under bin. The adapter uses an explicit trusted configuration, disables
ShellCheck/Pyflakes helpers and converts structured findings into misconfiguration
results. Policy severity is mapped to medium, not a CVSS claim. Source-bearing
messages are omitted from shared reports; rule identifiers and locations are retained.
This built-in adapter can run offline and does not require a local Git executable.

## Default configurations and runtimes

The `extensions-go.json` and `extensions-workflows.json`
examples now select managed built-in checks and local configs. They no longer require
`portable: false` or preinstalled PATH tools. They remain selectable standalone
configuration files, not auto-merged include/profile fragments. Other unspecified
settings inherit the full application defaults.

General multi-language SAST requires an explicitly configured analyzer. Go analysis uses prepared local module caches and a managed SDK, not network
dependency installation during the scan. The current standard govulncheck and zizmor
adapters do not accept `native_config`; use their supported extra arguments or a
reviewed custom definition rather than an ignored config file.

## Import a reviewed portable bundle

For a platform/runtime distribution you provision independently:

```sh
sekscan deps import company-sast --home ./workspace \
  --from /path/to/reviewed-bundle --executable company-sast \
  --command-args '["--rules","{tool_dir}/rules.json"]' \
  --version 1.2.3 --yes
```

This is a layout/version example, not a real published scanner release. The bundle
must contain the executable, referenced rules and all required runtime dependencies.
Configure the trusted tool entry before importing it.
The importer copies regular files only, refuses symlinks/path traversal and records
an exact SHA-256 file manifest. Runtime prefixes use `{tool_dir}` after relocation.
`tools.NAME.command_args` can override a bundle prefix and is trusted executable
configuration. Importing grants local execution permission; hashes do not prove that
the supplied software is trustworthy.

For imported or assembled runtime bundles, the tool's SHA256 pin is the SHA-256 of
canonical JSON mapping relative file paths to file hashes, not the original upstream
archive digest. `deps lock` records this value. Native scanner archive pins retain
their existing meaning. Version and target platform metadata must match on reuse.

The complete runtime prefix and file tree are verified before scanning. Changed,
missing, additional or symlinked files invalidate a bundle. The source release contains
no downloaded runtimes or scanner executables. See [PORTABLE.md](PORTABLE.md) and
[TESTING.md](../TESTING.md) for preparation and validation boundaries.

## Removed scanner compatibility

Named Semgrep tool/extension entries are retired and ignored. They cannot be
re-enabled by a legacy checks flag. Other external SARIF adapters remain supported;
see [SEMGREP-REMOVAL.md](SEMGREP-REMOVAL.md).
