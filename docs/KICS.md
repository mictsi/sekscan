# Standalone KICS

KICS is enabled by default for directory scans containing candidate IaC files,
including downloaded GitHub snapshots. It supplements Trivy misconfiguration
checks; it does not replace application SAST, Grype, or Gitleaks.

After rebuilding sekscan:

```sh
./sekscan deps install kics --home ./workspace --yes
./sekscan scan dir:/path/to/project --project my-project --home ./workspace --offline
```

The scan also needs its other configured tools and databases prepared. `prepare
--all --yes` includes KICS. Disable it with `--kics=false`, `checks.kics=false`, or
the `kics` boolean in batch defaults/per-project settings. Omitted settings inherit
the enabled default; existing explicit false settings remain false.

## Installation and portability

The default pin is **2.1.20**. On 2026-10-11 this release provides native Linux,
macOS, and Windows archives for amd64/arm64, whereas the newer 2.1.21 and 2.2.0
release records have no attached native packages. Selecting an unavailable
version fails explicitly; there is no silent fallback or container installation.

The installer verifies the executable archive against `checksums.txt` and the
matching `extracted-info.zip` rule archive against its GitHub SHA256 asset digest.
Both are extracted with bounded, regular-file-only extraction. The complete
installation is hashed and verified on reuse, including queries and libraries.
For KICS, `tools.kics.sha256`/`deps lock` pins the canonical **bundle file manifest**,
not either downloaded archive. These checks are not publisher-signature validation.

The resulting workspace bundle requires neither Docker nor a Checkmarx account.
Version probes and scans disable Sentry crash reporting. Scans use local rules,
disable remote descriptions and OpenAPI reference resolution, and disable KICS
secret scanning (Gitleaks/Trivy retain that role). These options are not an OS
network sandbox. Offline operation requires the complete bundle to be present.

## Inputs and report behavior

The `iac` selector discovers `.tf`, `.tfvars`, `.yaml`, `.yml`, `.json`, `.jsonc`,
`.template`, `.proto`, and Dockerfile/Containerfile name variants. These are
candidates: KICS decides which supported IaC platforms they represent. Ordinary
package manifests can yield a skipped/not-applicable engine result, not a clean
security assessment. Image and SBOM targets do not activate this source adapter.

Selected files are copied into an isolated snapshot preserving relative paths.
Configured/workspace exclusions and dependency directories are excluded; matching
symlinks are rejected. Discovery permits at most 1,024 candidate files; each file
is limited to 5 MiB and the snapshot to 256 MiB. Exceeding limits fails coverage.
Cross-file analysis is limited to the selected files. Referenced files outside
the snapshot and unsupported file formats are not included. KICS inline ignore
directives and query behavior can further limit coverage.

An explicit trusted `tools.kics.native_config` may configure KICS. Otherwise an
empty configuration is generated outside the source tree. The adapter controls
input paths, local asset paths, JSON output, network-related options, and exit
handling. `tools.kics.extra_args` is rejected; use a reviewed custom extension
when a different execution contract is required.

The native JSON parser keeps CRITICAL/HIGH/MEDIUM/LOW/INFO severities (TRACE maps
to INFO), rule IDs, and source locations. It omits resource values and snippets.
File/query failures and inconsistent counters make coverage incomplete even if
the process succeeds; already parsed findings remain available. Findings remain
engine-specific and may overlap with Trivy or Hadolint.

## Verification

Tests cover bundle verification and tampering, platform names, input isolation,
symlink/path rejection, severity preservation, redaction, partial processing
failures, and adapter invocation. The optional real-scanner acceptance test is:

```sh
SEKSCAN_KICS_TEST_BUNDLE=/path/to/verified/kics-bundle \
  go test ./internal/scan -run TestKICSLive -v
```

The bundle must contain `kics` (or `kics.exe`) and the matching `assets/` directory.
Linux/amd64 acceptance uses a Terraform misconfiguration and a non-IaC package
manifest. Native Windows/macOS execution requires separate platform validation.

Upstream references: [release packages](https://github.com/Checkmarx/kics/releases/tag/v2.1.20),
[CLI](https://docs.kics.io/latest/commands/), and
[JSON result fields](https://docs.kics.io/latest/results/).
