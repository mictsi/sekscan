# Scan-history database schema

Schema version **1**, unchanged through sekscan 0.4.0-preview. This schema belongs to sekscan scan history, not Grype/Trivy vulnerability catalogs. External scanners retain their own native caches under `cache/`.

## Backends

`sqlite`: local file, default `data/sekscan.db`, production driver `modernc.org/sqlite`. Foreign keys, a busy timeout and WAL mode are requested on each connection. A process uses one database connection; transactions serialize SQLite writes. Keep the file on a local filesystem. Do not use a network share as a substitute for PostgreSQL/SQL Server.

`postgres` / `postgresql`: `pgx/v5/stdlib`, URL DSN in the configured environment variable, verified TLS by default.

`mssql` / `sqlserver`: Microsoft's `go-mssqldb`, URL DSN in the configured environment variable, encrypted transport and certificate verification by default. JSON validation uses SQL Server `ISJSON`.

Provision the database separately. Use a dedicated PostgreSQL schema/search path or database. The unqualified table names use the connection's default schema: keep it consistent across migration, writer and reader identities. On SQL Server use the same default schema, normally `dbo`, for those identities. This release does not provision users, databases, cloud identities or certificates.

## Tables and relationships

| Table | Primary key / relationship | Purpose |
|---|---|---|
| `sekscan_schema_migrations` | `version` | Applied migration version, content checksum and application timestamp. |
| `sekscan_projects` | `id`; unique `(namespace, project_key)` | Stable project identity and repository metadata. ID is the hash of namespace/key. |
| `sekscan_scans` | `id`; FK `project_id` | Immutable full report, target/revision/branch, coverage and gate status, indexed summary, payload hash. |
| `sekscan_engine_runs` | `(scan_id, ordinal)`; FK scan | Engine version/status/timing, configuration and executable hashes in JSON evidence. |
| `sekscan_components` | `(scan_id, component_id)`; FK scan | Package identity, ecosystem, scope, PURL and complete package/license evidence. |
| `sekscan_findings` | `(scan_id, ordinal)`; FK scan | Findings and resolved-baseline entries, fingerprint, severity/category/scope/decision, complete evidence. |
| `sekscan_artifacts` | `(scan_id, name)`; FK scan | Optional Syft/CycloneDX/SPDX JSON SBOM bytes, media type, byte count and hash. |

```text
sekscan_projects
    └── sekscan_scans
            ├── sekscan_engine_runs
            ├── sekscan_components
            ├── sekscan_findings
            └── sekscan_artifacts

sekscan_schema_migrations   (schema administration)
```

Child scan records cascade on scan deletion. There is no user-facing delete command in this release. `findings.component_id` is a logical reference, not a foreign key: source/config findings can lack a component, and resolved baseline findings may refer to components absent from the current inventory. Full JSON evidence preserves that distinction.

SQL Server namespace and project-key columns use a binary collation so shared identities remain case-sensitive like their Go hashes. Treat keys as stable identifiers, not display labels. Do not change the spelling/case of a shared project key between agents.

## Data representation

Timestamps used for indexing are fixed-width UTC strings with microsecond precision, for example `2026-10-02T12:00:00.000000Z`. They are always generated through one formatter and can be sorted lexically. Full JSON retains the report's original timestamps. They are not native SQL timestamp columns; cast explicitly in custom analytical queries if needed.

SQLite/PostgreSQL use TEXT JSON; SQL Server uses NVARCHAR(MAX). JSON-validity checks are present in each dialect. Keeping the full report as text preserves its exact serialized bytes for SHA-256 integrity checks rather than relying on database JSON reserialization. Structured scalar columns and indexes support ordinary history filtering. SBOM bytes use BLOB/BYTEA/VARBINARY(MAX), respectively.

Indexes cover project/time, status/time, finding fingerprint, finding severity/decision/category within a scan, and component scope. Full-text search across every finding in the entire database is not implemented. The history search covers project key, revision and target; the opened per-scan dashboard searches findings/components.

The storage limit is 64 MiB for a normalized report; SBOM artifacts default to 64 MiB each and are configurable up to 256 MiB, with a 256 MiB total artifact-set cap. Large deployments should size storage and retention appropriately. Database blobs contain only the three supported SBOM filenames, not arbitrary files or original scanner stderr.

## Migration

The backend SQL scripts in `schema/` include transaction wrappers and a matching migration-ledger insert. They are **initial bootstrap scripts for an empty, dedicated database**, not idempotent maintenance scripts. Do not apply all three dialects or repeatedly run a bootstrap script.

```sh
sekscan storage schema --driver sqlite --out sqlite.sql
sekscan storage schema --driver postgres --out postgres.sql
sekscan storage schema --driver mssql --out mssql.sql

# Preferred operational path; checks already-applied versions and checksums.
sekscan storage migrate --config config/postgres.json
sekscan storage status --config config/postgres.json
```

The application embeds the same migration body. It rejects unknown/newer versions or changed checksums. Never edit a migration after it has been applied; add a new migration and application support for future changes. Version 1 is the only implemented migration in this preview.

PostgreSQL uses transaction advisory locks and SQL Server uses transaction-owned `sp_getapplock` locks for migrations/project writes. SQLite uses immediate transactions. Writes insert an entire scan, engines, components, findings and artifacts atomically. An existing scan ID is accepted only when the normalized payload and artifact set are identical; other reuse returns a conflict rather than overwriting evidence.

## Identity and permissions

All new scans require an explicit stable project name via `--project NAME` or
`project.key`, including SQLite and scans with persistence disabled. Keys are
case-sensitive within `project.namespace`; the same namespace/key pair produces the
same project ID across agents. Each scan has its own immutable run ID. The CLI flag
overrides configuration. Multiple checkout paths for the same project must use the
same key. The application no longer derives a new project key from a local path.
Historical path-derived records remain readable, without automatic merges or renames.
Repository URIs are descriptive metadata, not authentication.

Run remote migration with a dedicated administrator identity. Routine writers need the appropriate CONNECT/schema access and SELECT/INSERT permissions on application tables, plus permission to acquire the documented advisory/application locks; they do not need schema creation or report UPDATE/DELETE permissions. Readers of already-migrated server databases need SELECT permissions. Scope these privileges with your DBA and server-specific role model; no GRANT statements are silently run by the application.

**Namespace filtering is not authorization or row-level security.** Anyone with table access can query other namespaces. Use separate databases/roles, or an independently designed row-level-security layer, where teams must be isolated. The CLI does not set tenant security context in the database and does not implement SSO, sessions or RBAC.

Do not trust application hashes as signatures. They detect accidental changes relative to the recorded hash, not a malicious database writer who can change both the payload and hash. A shared database is an audit store for trusted writers, not an attestation service.

## Credentials, backups and failures

Only URL-style DSNs are accepted. Provide them through `storage.dsn_env`, default `SEKSCAN_DB_DSN`. DSNs are not logged. Driver error details are deliberately withheld because they may contain credentials or query data; use protected server-side diagnostics when investigating connectivity.

Verified TLS is the default. `allow_insecure_tls=true` exists only for explicitly approved local tests. Use a current trusted server certificate and URL-encoded passwords. This integration does not configure managed identity or database service accounts for you.

`storage.required=true` means failed persistence makes the final local scan report incomplete (exit 2). With `required=false`, reports record a warning and preserve the scanner policy result. There is no offline write queue, automatic server failover or deferred background upload; use `storage import` for an explicit retry.

Use your database's supported backup, encryption and retention mechanisms. For SQLite, use the SQLite backup API/tooling or stop all writers and preserve a consistent database/WAL state; copying an actively written main file alone is not a reliable backup strategy. There is no automatic retention/purge command yet. Deleting a scan through a reviewed administration procedure cascades its child records; project rows remain until separately removed.

## Validation boundary

Local tests exercised the SQL against actual system SQLite through a test-only database/sql bridge, including foreign keys, rollback, concurrent/independent connections, artifact identity, migration checksums, search, scoping and full-report round trips. This is not verification of the production modernc driver build.

PostgreSQL and SQL Server implementations, migrations and integration tests are included but were not connected to live servers in the authoring environment. Validate against your actual server versions before deployment:

```sh
# Dedicated disposable databases only.
export SEKSCAN_TEST_POSTGRES_DSN='postgresql://...'
export SEKSCAN_TEST_MSSQL_DSN='sqlserver://...'
# For explicitly insecure localhost test services only:
# export SEKSCAN_TEST_ALLOW_INSECURE=1
bash scripts/test-databases.sh
```

The script requires both DSNs rather than silently accepting skipped integrations. It does not create or install database servers.

## Portable SQLite snapshots (0.3)

`sekscan storage backup --out snapshot.db` uses SQLite VACUUM INTO to create a
consistent snapshot of a live local history store. It refuses existing destinations
and is not available for PostgreSQL or SQL Server. Stop destination connections
before restoring it; never combine it with old WAL/SHM files. Schema version remains
1, so existing 0.2/0.3 data requires no additional table migration for the 0.4 history features.

## Project history and analytics (0.4)

The existing unique `(namespace, project_key)` constraint and project/time indexes
support project-first history. The new project summary query uses window functions
to obtain counts and the latest run; project/run result sets use parameterized SQL
paging with deterministic ID tie-breakers. The trends API reads at most 200 matching
summary rows and labels truncation rather than fetching every stored report.

Comparison reads two report snapshots in memory and pages their computed differences;
it does not rewrite persisted findings or require a comparison table. Existing
`summary_json`, engine coverage, and package/finding evidence supply the dashboard.
No physical columns/indexes or migration checksums were altered. See
[HISTORY.md](HISTORY.md) for paging, time filters, coverage rules, and API changes.


## Batch, GitHub provenance and portfolio queries (0.5)

SQL schema version remains **1**. No migration or new authentication behavior is
introduced. Each attempted batch assessment is a separate immutable scan under its
project; projects are still keyed by namespace + project key. GitHub inference uses
lowercase `owner/repository`; explicit overrides can join previously named history.

The existing scan JSON snapshot stores optional `batch_id` and `source` metadata:
provider, repository, requested/resolved ref, full revision, subdirectory and archive
SHA-256. These are not new indexed columns. The batch-level summary remains an
output JSON artifact; there is no dedicated batch scheduling/queue table. Unattempted
entries have no scan row. Source archives stay in the local portable cache, not in
shared SQL tables. Token values are never persisted.

Portfolio analytics query stored scan summary rows using a latest-state seed and
in-window events, with an explicit 50,000-observation limit. They do not need to read
full report blobs. Latest incomplete runs remain distinct and do not become clean
counts. Read [HISTORY.md](HISTORY.md) for daily/window/filter semantics. SQL generated
for PostgreSQL and SQL Server still requires testing against live services.
