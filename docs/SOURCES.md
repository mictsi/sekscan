# Primary interface references

Consulted during implementation on 2026-10-02. These describe upstream interfaces; reading them is not a substitute for compiling the production dependency graph or testing live scanner/server versions.

## Storage and Go drivers

- SQLite deployment choices and local versus shared storage: https://www.sqlite.org/whentouse.html
- SQLite production driver: https://pkg.go.dev/modernc.org/sqlite
- Pinned SQLite module requirements: https://gitlab.com/cznic/sqlite/-/raw/v1.60.1/go.mod
- pgx database/sql interface: https://pkg.go.dev/github.com/jackc/pgx/v5/stdlib
- Pinned pgx module requirements: https://raw.githubusercontent.com/jackc/pgx/v5.11.0/go.mod
- Microsoft's SQL Server Go driver: https://github.com/microsoft/go-mssqldb
- Pinned SQL Server driver requirements: https://raw.githubusercontent.com/microsoft/go-mssqldb/v1.11.2/go.mod

## Scanners and extension templates

- Syft CLI: https://oss.anchore.com/docs/reference/syft/cli/
- Grype CLI: https://oss.anchore.com/docs/reference/grype/cli/
- Grype configuration: https://oss.anchore.com/docs/reference/grype/configuration/
- Trivy filesystem CLI: https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/
- Trivy image CLI: https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/
- Trivy license scanner: https://trivy.dev/docs/latest/scanner/license/
- Gitleaks CLI/configuration: https://github.com/gitleaks/gitleaks
- Go vulnerability management: https://go.dev/doc/security/vuln/
- govulncheck output formats/exit semantics: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
- zizmor usage/exit behavior: https://docs.zizmor.sh/usage/
- zizmor CLI switches: https://docs.zizmor.sh/quickstart/
- Semgrep CLI options and exit behavior: https://docs.semgrep.dev/cli-reference
- gosec checker: https://github.com/securego/gosec
- gosec release asset naming example: https://github.com/securego/gosec/releases/expanded_assets/v2.29.0
- gosec exit semantics: https://raw.githubusercontent.com/securego/gosec/master/cmd/gosec/main.go
- SPDX expressions: https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/

## Pipelines

- GitHub Actions checkout: https://github.com/actions/checkout
- GitHub Actions Go setup: https://github.com/actions/setup-go
- GitHub artifact publishing: https://github.com/actions/upload-artifact
- Azure Go tool acquisition: https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/reference/go-tool-v0?view=azure-pipelines
- Azure Pipeline Artifact task: https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/reference/publish-pipeline-artifact-v1?view=azure-pipelines
- Azure Publish Test Results: https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/reference/publish-test-results-v2?view=azure-pipelines

Production CI should use reviewed action commit SHAs, supported Go patches and tested scanner version locks. Azure Pipeline Artifacts are for Azure DevOps Services; on-premises Server installations need their supported Build Artifacts task instead.

## 0.3.0 fixes, portability and module verification

- Syft required exclusion prefixes by target type: https://oss.anchore.com/docs/guides/sbom/file-selection/
- Syft native cache/environment configuration: https://oss.anchore.com/docs/reference/syft/configuration/
- Grype native database update, status and age semantics: https://oss.anchore.com/docs/guides/vulnerability/database/
- Grype status path example: https://oss.anchore.com/docs/contributing/grype/
- Trivy air-gapped databases, embedded checks and offline behavior: https://trivy.dev/docs/latest/advanced/air-gap/
- actionlint command line and JSON templates: https://github.com/rhysd/actionlint/blob/main/docs/usage.md
- actionlint formatter/completion behavior: https://raw.githubusercontent.com/rhysd/actionlint/main/linter.go
- SQLite consistent `VACUUM INTO` snapshots: https://sqlite.org/lang_vacuum.html
- Go latest stable release metadata: https://go.dev/dl/?mode=json
- pgx latest release: https://github.com/jackc/pgx/releases/latest
- SQL Server Go driver latest release: https://github.com/microsoft/go-mssqldb/releases/latest

These references support interface choices, not a claim that actual latest tool
releases or production Go modules were downloaded or executed in this environment.

## 0.6 default source scanner interfaces (reviewed 2026-10-03)

- https://github.com/hadolint/hadolint — CLI JSON, no-fail, explicit config and ignore pragma controls.
- https://github.com/securego/gosec — native `Golang errors` / Stats completeness and nosec config.
- https://go.dev/doc/security/vuln/database — ZIP snapshot, file:// database API and freshness semantics.
- https://github.com/golang/vuln/blob/master/internal/scan/run.go — DB inspection occurs before the -version early return; use a version-only local DB.
- https://docs.semgrep.dev/cli-reference — strict/CE/local-rule/SARIF options; .semgrepignore still affects --no-git-ignore scans.
- https://docs.zizmor.sh/usage/ — offline SARIF and strict input collection.
- https://docs.astral.sh/uv/reference/cli/ — managed Python install, hash-locked wheels and target-directory installation.

Native platform acceptance remains separate from upstream API review and fixture tests.

Semgrep wheel entry points: `cli/pyproject.toml` publishes
`pysemgrep = semgrep.console_scripts.pysemgrep:main`; the managed launcher resolves
that entry point from the installed distribution metadata. `cli/src/semgrep/__main__.py`
rejects `python -m semgrep`, so it is not used. Upstream source reviewed via the
connected repository, not inferred from module naming.

## Retired integrations

Semgrep/Python references above document earlier versions only. That integration
was removed in 0.6.5. They are not current preparation or scanning instructions.
