# Standard configuration files

Installed by `sekscan init` and `prepare`; existing files are never overwritten.
The default suite enables Gitleaks, actionlint, Hadolint, zizmor, govulncheck, gosec
when applicable. Explicit false values/custom definitions are preserved.

| File | Use |
|---|---|
| syft.yaml, grype.yaml, trivy.yaml | Core scanner-native settings |
| actionlint.yaml | GitHub Actions validation; external helpers disabled |
| hadolint.yaml | Dockerfile/Containerfile lint rules; no local Docker daemon required |
| gosec.json | Go source checks, with inline nosec suppression disabled by default |
| gitleaks.toml | Optional override of generated Gitleaks config/exclusions |
| sqlite.json, postgres.json, mssql.json | Standalone scan-history backend configurations |
| extensions-go.json, extensions-workflows.json | Standalone examples of the default checks; not auto-merged includes |
| tools-gosec.json | Alternative declarative gosec release recipe; the built-in native adapter now supplies analysis |

The generated root sekscan.json references config/hadolint.yaml and config/gosec.json. Native paths in this directory's examples are relative
to those example files. Do not copy paths unchanged into another directory.

Use `config enable-default-scanners --config OLD --out NEW` to enable the expanded
suite in an existing configuration without overwriting it. Review rules/permissions
and preserve your organization policies. `prepare --all --yes` provisions managed
tools and supported runtimes; system PATH tools do not satisfy portable prerequisites.

Missing applicable tools/data make required scans incomplete. No matching input is
explicitly not applicable. All default source analyzers can run with local scan data;
custom offline extensions must declare `offline: true`. This is not a sandbox.

Go analysis uses the workspace SDK/dependency cache with network resolution off and
CGO disabled. `prepare --go-module PATH --yes` is an explicit dependency-download
step and may update go.sum.
No live upstream installation or platform compatibility is certified by these
configuration files. Read the package's DEFAULT-SCANNERS.md and TESTING.md.

Semgrep defaults and Python setup are removed. Existing unused files are not deleted
automatically; legacy settings do not reactivate the scanner.
