# Building release ZIPs

The release builder creates **ZIP archives for every supported target**, with the
application executable, documentation, examples, standard configs, and database
schemas. Use the Bash or PowerShell entrypoint from a trusted source checkout.
A separate standard-library-only Go helper under `scripts/release/` performs the
same validation and packaging on either host; Python, Node, zip, Docker, and a C
cross-compiler are not required by this builder.

For automatic GitHub release publication, see [RELEASE-WORKFLOW.md](RELEASE-WORKFLOW.md).
Only that workflow requires Python/GitHub CLI; the local Go builder below does not.

## Supported target matrix

| Target | Executable |
|---|---|
| `linux/amd64` | `sekscan` |
| `linux/arm64` | `sekscan` |
| `windows/amd64` | `sekscan.exe` |
| `windows/arm64` | `sekscan.exe` |
| `darwin/amd64` | `sekscan` |
| `darwin/arm64` | `sekscan` |

`--targets all` means these six application targets, not every GOOS/GOARCH supported
by Go. Unsupported pairs are rejected. Availability of an upstream scanner release
is separate from compiling the application; `prepare` verifies scanner prerequisites
on the selected platform. A cross-compiled binary is not proof of native execution.

## Prerequisites and dependency bootstrap

Use the supported Go toolchain selected by the repository's `go.mod`; this snapshot
requires Go 1.26.0 or newer and selects go1.27.1. Install Bash on Linux/macOS or use
PowerShell on Windows. Permit required module/toolchain downloads, or prepopulate
verified module and compiler caches through your approved offline process.

The source preview has no fabricated `go.sum`. Bootstrap on a connected machine:

```sh
bash scripts/build.sh
# Review and commit go.mod and go.sum before proceeding.
```

Windows PowerShell:

```powershell
go mod tidy
if ($LASTEXITCODE -ne 0) { throw 'Dependency resolution failed' }
go mod verify
if ($LASTEXITCODE -ne 0) { throw 'Module verification failed' }
go test ./...
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
go vet ./...
if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
# Review and commit go.mod and go.sum before proceeding.
```

Updating module versions is a separate reviewed operation using
`scripts/update-modules.sh` or `.ps1`. The release builder does **not** run
`go get -u`, `go mod tidy`, or rewrite module pins/checksums. It requires a nonempty
`go.sum`, uses read-only module mode, and rejects local filesystem replacements.
It checks module-file hashes again before publication to detect mutation.

## Build every release target

From the source directory:

```sh
bash scripts/build-release.sh --version 0.6.5-preview --targets all
```

```powershell
.\scripts\build-release.ps1 --version 0.6.5-preview --targets all
```

The helpers can also be called from another working directory; source-relative paths
are resolved using the wrapper location. Flags are the same on Bash and PowerShell.
Version defaults to the value in `internal/cli/cli.go`.

```sh
bash scripts/build-release.sh --list-targets
bash scripts/build-release.sh --version 0.6.5-preview --targets linux/amd64,windows/amd64
bash scripts/build-release.sh --version 0.6.5-preview --out dist/review-build
bash scripts/build-release.sh --help
```

Output defaults to `dist/VERSION/`. A relative `--out` is relative to the source root.
An existing destination is rejected rather than overwritten. Choose a new output
path for a rebuild. Output inside source directories that are packaged recursively
is rejected. Source archives are included by default; `--source=false` disables that
additional archive. `--skip-tests` explicitly skips host tests/vet and records the skip
in the release manifest; do not use it for a reviewed production release.

## Output and archive contents

```text
dist/0.6.5-preview/
  sekscan-0.6.5-preview-linux-amd64.zip
  sekscan-0.6.5-preview-linux-arm64.zip
  sekscan-0.6.5-preview-windows-amd64.zip
  sekscan-0.6.5-preview-windows-arm64.zip
  sekscan-0.6.5-preview-darwin-amd64.zip
  sekscan-0.6.5-preview-darwin-arm64.zip
  sekscan-0.6.5-preview-source.zip
  release.json
  SHA256SUMS.txt
```

Each runtime ZIP contains a single `sekscan-VERSION-OS-ARCH/` directory:

```text
sekscan[.exe]
README.md                 Platform/version-specific instructions and examples
readme.med                Identical alias, as requested
SOURCE-README.md           Complete repository instructions
TESTING.md
CHANGELOG.md
sekscan.json               Clean default config; project.key intentionally blank
config/                   Standard native scanner/database/extension configs
docs/                     Including HISTORY.md and RELEASING.md
examples/                 Configs, CI examples, and synthetic demonstration
schema/                   SQLite, PostgreSQL, SQL Server initial schemas
bin/                      Empty; managed tools installed by prepare
cache/                    Empty; native scanner databases installed by prepare
logs/                     Empty; operational logs generated later
data/                     Empty; SQLite history created when used
BUILD-INFO.json            Target, version, binary digest, bundling/signing status
GO-MODULES.json            Resolved application module graph
SHA256SUMS.txt             Per-file digests inside this ZIP
```

Any root LICENSE/NOTICE files present are copied. Review linked dependencies and
provide required third-party license notices before redistributing a production build. The source ZIP uses an explicit
allowlist and excludes live workspace files, logs, caches, binaries, `.env`, and
active main configuration. Tests/fixtures, documentation, the CLI source, all scripts,
`go.mod`, and reviewed `go.sum` are included. Inspect custom files under packaged
source directories before publishing; an allowlist does not sanitize their contents.

Scanner applications and their vulnerability databases are **not pre-bundled** by
this cross-platform release script. After extracting a platform ZIP:

```sh
./sekscan prepare --home . --all --update-tools --with-java --yes
./sekscan scan dir:/path/to/source --project payments-api --out security-report
./sekscan serve --history
```

The managed-copy requirement remains intact: preparation downloads to `bin/` and
`cache/` rather than using PATH tools. To distribute a prepared offline workspace,
prepare and validate it on the matching OS/architecture, stop all writers, then
package it separately. Never include credentials, private logs, or user history by
accident. PostgreSQL/SQL Server remain external services.

## Validation, atomic publication, and logs

The builder verifies modules, reads the resolved dependency graph, runs host tests
and vet for the application and helper, and cross-compiles with CGo disabled. Build
flags include `-trimpath`, `-buildvcs=false`, and the selected application version.
It inspects each output executable's Go build metadata to verify its target,
production database modules, and absence of the `offline_sqltest` tag or local-module
replacements. Test-only adapters are never accepted as release binaries.

When the selected matrix includes the build host, the builder runs that binary's
`version` command and checks the expected version. Other targets require separate
native smoke/integration tests. Native tests, database integration, scanner runs,
signing, and notarization are not implied by cross-compilation.

Build logs are written to source `logs/build-release-VERSION-*.log` and the terminal.
A validation failure before log initialization is printed to the terminal. Output is
staged beside the destination and published only after every requested build/archive,
module integrity check, manifest, and checksum succeeds. A failed run does not publish
a partially complete release directory. Preserve build logs privately as needed.

The builder sets `GOWORK=off`, controls compiler target flags, and discards conflicting
`GOFLAGS`; use an audited source/module graph rather than injecting alternate build
modes. The PowerShell wrapper restores its working directory and changed environment
variables before exiting with the builder status.

## Integrity and reproducibility

`SHA256SUMS.txt` at release root covers every archive and `release.json`; inner
checksums cover the runtime/source payload excluding the checksum file itself.
Verify before extracting or executing:

```sh
cd dist/0.6.5-preview
sha256sum --check SHA256SUMS.txt
```

PowerShell, from the same release directory:

```powershell
Get-Content SHA256SUMS.txt | ForEach-Object {
    $expected, $name = $_ -split '\s+', 2
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $name.Trim()).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Checksum mismatch: $name" }
}
```

Archive entries are sorted, use normalized modes, preserve executable permission,
and use a controlled timestamp. `SOURCE_DATE_EPOCH` selects that timestamp:

```sh
SOURCE_DATE_EPOCH=1790985600 bash scripts/build-release.sh --version 0.6.5-preview
```

```powershell
$env:SOURCE_DATE_EPOCH = '1790985600'
.\scripts\build-release.ps1 --version 0.6.5-preview
Remove-Item Env:SOURCE_DATE_EPOCH
```

ZIP fixture tests confirm deterministic packaging for identical inputs. Exact repeat
builds of real binaries additionally depend on identical toolchains, source, module
graphs, timestamps, and build inputs; end-to-end cross-host reproducibility has not
been demonstrated here. ZIP permissions may not survive every extraction utility;
`chmod +x sekscan` repairs the Unix executable bit after trusted extraction.

Outputs are **unsigned**. Hashes detect mismatches relative to a trusted manifest but
do not establish publisher identity. Add your release-signing/notarization pipeline
before distributing an organization-approved production build.

## Preview validation boundary

This revision's helper tests validate packaging and rejection logic with synthetic
fixtures. The authoring environment could not resolve the production compiler/module
graph, so it did not produce genuine six-target executable ZIPs. PowerShell was
reviewed but not run there. See [../TESTING.md](../TESTING.md) for exact executed checks
and the outstanding live scanner/database/platform acceptance tests.


## 0.5 payload additions

Platform/source ZIPs include `schema/batch.schema.json`, batch examples,
`docs/BATCH.md`, `docs/UI.md`, and `third_party/SekuraDesignMCP-LICENSE`.
The default `serve` entrypoint is the portfolio dashboard; `serve DIRECTORY` remains
available. The batch source cache is runtime data and is not copied from the build
machine into a release. Populate managed tools/CVE data with `prepare`, and acquire
needed repository commits online before transferring an offline workspace.

## 0.6.4 target and prerequisite boundary

`scripts/release/targets.json` is the canonical six-platform list. The Go release
builder embeds it, and the publication validator loads the same tagged file. A
release missing its Windows ARM64 archive fails validation. Include this file when
copying the workflow helpers; the full source ZIP contains the complete set.

To build Windows ARM64 alone after resolving/reviewing the production dependencies:

```bash
bash scripts/build-release.sh --version 0.6.5-preview --targets windows/arm64
```

An ARM64 application executable does not imply native availability of every external
scanner or runtime. Native assets must exist for each selected scanner; no emulation,
system-tool substitution or automatic required-check disablement is introduced.
Semgrep is removed from all scanner platforms. See [validation](../TESTING.md) for
the distinction between cross-compilation and native runtime acceptance.
