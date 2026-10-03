# Architecture

`cmd/sekscan` → CLI runtime/config discovery/logging → external scanner orchestration → normalized report/policy → portable reports and optional scan-history transaction.

Modules:

- `internal/config`: strict JSON, workspace resolution, tool/extension settings and policy validation.
- `internal/workspace`: embedded standard configs; non-overwriting workspace initialization.
- `internal/deps`: trusted release download/checksums, managed executables, version probes and update checks.
- `internal/runner`: no-shell argv execution, environment filtering, cancellation and output caps.
- `internal/scan`: Syft/Grype/Trivy/Gitleaks invocation, native config hashes, inventory/findings parsing and generic SARIF extensions.
- `internal/policy`: application license scope, SPDX-style decisions, severity gates, exceptions and baselines.
- `internal/dbstore`: database/sql repository, three dialects, embedded checksum-versioned migrations, immutable transactional snapshots and SBOM blobs.
- `internal/report`: versioned JSON, self-contained dashboard, SARIF, JUnit and Markdown output.
- `internal/server`: loopback read-only report serving and Host/Origin boundary.
- `internal/cli`: prepare/storage/history commands and server-rendered history index.

Database drivers are compile-time Go dependencies, separate from external scan executables. All production drivers are imported by `internal/dbstore/drivers.go`. The `offline_sqltest` build tag replaces them with a limited system-SQLite test adapter for restricted environments; it is not a deployable alternative driver mode.

The single-report dashboard stays fully self-contained. Database history provides a separate index and loads each selected report into that dashboard. It does not make browser JavaScript connect to SQL directly. Read/write credentials never appear in report HTML.

Scan inventory and policy behavior remain local-first. History failure can be mandatory or optional according to config; neither failure mode silently loses the local report. Scanner caches are intentionally not represented in the history schema and are updated through external tools' native interfaces.

Not implemented: authenticated hosted service, tenant authorization/RLS, database server provisioning, automatic retention, write queues, config includes/profiles, arbitrary output mapping DSL, or signed attestations. Review TESTING.md for actual execution coverage rather than treating architecture support as live-server certification.
