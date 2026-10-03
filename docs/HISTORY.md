# Project history, comparisons, and pagination

Updated for **sekscan 0.5.1-preview** (history introduced in 0.4). History is a read-only view of immutable
stored scan results. It does not rerun scanners, recompute policy, or prove that
an application is secure.

## Project identity is required

Every new scan requires `--project NAME` or a nonempty `project.key` in the selected
configuration. This applies to SQLite, PostgreSQL, SQL Server, `--no-store`, and
inventory-only scans. A missing project returns exit code 2 before scanner execution.

```sh
sekscan scan dir:../payments --project payments-api --branch main --revision COMMIT_ID
sekscan scan image:payments:build-123 --project payments-api --out image-report
```

```json
{
  "version": 2,
  "project": {
    "namespace": "engineering",
    "key": "payments-api"
  }
}
```

The CLI flag overrides the configured key. Names may contain internal spaces; quote
these on the command line. They must be nonempty, at most 256 UTF-8 bytes, have no
leading/trailing whitespace, and contain no control characters. Names are
case-sensitive, stable keys within a namespace, not automatically inferred checkout
paths. Use the same namespace/key on every CI agent. The existing database project
ID is derived from that pair; each run retains its independent scan ID.

Existing named or path-derived project records remain readable. No historical rows
are automatically renamed, merged, or migrated. New local scans must explicitly name the
project. GitHub mode can infer lowercase `owner/repository`; batch entries can
override it. Inference never renames existing history. An older report without a project can be imported with
`storage import REPORT_DIRECTORY --project NAME`; an existing immutable named report
cannot be silently reassigned. Choose a reviewed migration procedure for historical
merges rather than modifying evidence through normal scan/import commands.

A file baseline passed with `scan --baseline` must also identify the same project
and namespace. For older unnamed report files, import them with a project and export
the stored result before using it as a baseline.

## Filter by project (0.4.1)

The project directory and per-project run dashboard include a **Project key (exact)**
field. Type part of a key to request suggestions from the namespace-scoped project
API, then select or enter the full key. Suggestions are limited to 25 matches per
request; type more to narrow them. The field also works without JavaScript by
entering the exact key manually. The separate search field is a text search and is
combined with, not substituted for, the selected project.

An empty project field on the project-directory page shows all projects in the
current namespace. The run dashboard requires a project. Applying filters resets
the list to page 1. Page navigation, page-size changes, page jumps, run links, and
comparison links retain project identity; switching projects discards comparison
IDs selected for the old project. The per-project trend view is restricted to that project; the new portfolio
dashboard aggregates latest project states across the selected namespace.

```sh
sekscan history projects --project payments-api --page-size 25 --json
sekscan history list --project payments-api --page 2 --page-size 25 --json
sekscan history trends --project payments-api --trend-limit 50 --json
sekscan history compare BASE_RUN_ID HEAD_RUN_ID --project payments-api
sekscan history export RUN_ID --project payments-api --out exported-report

# Fix this local history viewer to one project.
sekscan serve --history --project payments-api
```

`serve --history --project NAME` fixes the project filter for that server process.
The field is read-only, requests for another project are rejected, and run reports,
JSON, and SBOM artifacts must match the selected project. Restart without `--project`
to browse all projects in the configured namespace. This is a local presentation
filter, **not authentication, database authorization, or a multi-tenant service**.
`serve --project NAME` works without `--history`; the flag is a compatibility alias
for the new history default.

HTTP examples (URL-encode keys containing spaces or punctuation):

```text
/?tab=projects&project=payments-api
/projects?project=payments-api&tab=runs&page=2&page_size=25
/api/projects?project=payments-api
/api/scans?project=payments-api&page=2&page_size=25
/api/trends?project=payments-api
/api/compare?project=payments-api&base=BASE_RUN_ID&head=HEAD_RUN_ID
/scans/RUN_ID/results.json?project=payments-api
```

Unknown exact keys return empty project/run lists, not results from other projects.
Duplicate `project` query parameters and invalid keys are rejected. Comparisons and
exports reject IDs belonging to another project. Existing SQL filters are reused;
no database migration is needed. SQL equality follows the database's collation;
this patch does not alter database collation or identity rules.

## Start the dashboard

```sh
sekscan serve
sekscan serve --config config/postgres.json
sekscan serve --project payments-api
sekscan serve ./security-report
```

With no report directory, the starting page is **Security portfolio / Dashboard**.
It shows all projects with history in the configured namespace, regardless of a
configured default scan project. Use the Projects tab for the paginated directory
and All runs for the paginated cross-project list. Select a project for its separate
Dashboard and Runs tabs; open a run for findings, licenses, components, and coverage.
Stored report pages share the same design and link back to the project. Supplying an
explicit report directory retains the standalone report-server behavior.

The server remains loopback-only, read-only, and protected by Host/Origin checks.
It has no multi-user sign-in, role-based authorization, or cross-team access policy.
A namespace restricts application queries but is not a database security boundary.

## Portfolio dashboard (0.5)

The default dashboard has four summary tiles and four charts: reported findings,
project assessment states, severity totals, and evidence freshness. Choose a
7/30/90-day window, exact project, project-name search, branch, target kind and/or
UTC date range. Custom windows must span 1–90 days.

Each UTC day is evaluated using the **latest matching run per project**, carrying
its state forward until the next run. There is no repeated-count inflation from
rescanning the same project. Today ends at the current instant; past days end just
before the following midnight. Current totals are the last point in the selected
window, so a historical end date intentionally shows historical state.

A project's incomplete latest snapshot counts as incomplete and is excluded from
finding/component totals. It is **not** a zero-findings clean scan, and the query
never silently substitutes an older successful assessment. Count-series lines are
split when the complete-project population changes. Findings are not deduplicated
across different projects. Snapshots older than seven days count as stale, not
necessarily vulnerable; this threshold is currently fixed.

Projects with older scans are seeded at the start of the graph. SQL loads at most
50,000 relevant observations (latest pre-window seed per project plus in-window
runs), not every full report or finding row. Exceeding the bound produces a visible
error and requires narrower filters; it never publishes partial portfolio totals.
Totals are independent of table pagination. Filters can mix source/image targets,
branches, policies and database snapshots unless narrowed; changes in population
or scanner data are not proof of remediation.

```sh
sekscan history portfolio --days 30 --json
sekscan history portfolio --project payments-api --branch main --kind dir --days 7
sekscan history portfolio --from 2026-09-01 --to 2026-09-30 --json
```

```text
GET /api/portfolio?days=30
GET /api/portfolio?project=payments-api&branch=main&kind=dir&days=7
GET /?tab=overview
GET /?tab=projects&page=1&page_size=25
GET /?tab=runs&page=1&page_size=25
GET /projects?project=payments-api&tab=runs
GET /compare?base=BASE_ID&head=HEAD_ID&tab=findings
```

`/api/portfolio` returns `current`, daily `points`, `from`, `to`, `days`,
`stale_after_days`, `latest_observed_at`, `observations`, and a caveat `note`.
Unlike list APIs, this is a bounded series, not a pagination envelope. Status
filters are rejected on portfolio analytics because excluding failed runs could
misrepresent the latest state. A fixed-project server applies the same project
constraint to this API. No SQL schema migration is required.

## Project dashboard

Project cards show the latest available scan summary and the incomplete-run count
within the selected trend window. Five local SVG charts show:

1. Total findings, policy failures, and review items.
2. Findings by severity.
3. Findings by category.
4. Discovered component count.
5. Scan duration in seconds.

Chart points link to the underlying run. Graphs are chronological; run tables are
newest-first. Incomplete runs are visibly marked and interrupt line-series segments,
so a failed scan with few findings is not presented as an improvement. A mixed-branch
or mixed-target-kind warning prompts narrower filters.

Select branch, target kind, search text, and inclusive UTC date range for project
views. Status is a run-table filter and is cleared when switching to the Dashboard
tab so an older passing run cannot silently hide a newer failure. The default trend window contains the **latest 50
matching runs**, capped at 200. The UI exposes 30/50/100/200. It clearly indicates when
more matching runs exist. These are individual run observations, not averaged daily
buckets or a full-history analytics warehouse. Paging the run table does not change
the trend window.

Counts can change because of dependency changes, new advisories, tool versions,
configuration, target coverage, and incomplete execution. A falling graph is not
by itself proof of remediation. Compare compatible runs and inspect their evidence.

## Comparing two runs

Select **Baseline** on an earlier run and **Candidate** on a later run, including
across different pages. The selected IDs persist in navigation URLs; session storage
is an optional convenience, not a requirement. The inputs also accept explicit IDs.

```sh
sekscan history compare BASE_ID HEAD_ID --project payments-api
sekscan history compare BASE_ID HEAD_ID --change new --severity high --page-size 25
sekscan history compare BASE_ID HEAD_ID --view components --page 1 --page-size 50 --json
sekscan history compare BASE_ID HEAD_ID --out comparison.json
```

The pair must be distinct, ordered earlier-to-later, belong to the same named
project and namespace, use supported report schemas, and have the same target kind.
A source-directory run is not compared directly with an image run. The comparison
Summary tab shows before/after values, numeric deltas, paired severity/category
charts and compatibility warnings. Separate Findings and Components / licenses
tabs provide the paginated evidence, search and filters.

| Finding state | Interpretation |
|---|---|
| `new` | Fingerprint exists only in the candidate snapshot; not necessarily newly introduced code. |
| `changed` | Same fingerprint but tracked evidence or policy fields differ. |
| `unchanged` | Same fingerprint and tracked fields. |
| `resolved` | UI says **No longer reported**: absent in candidate with comparable recorded coverage; not proof of a fix. |
| `unverified` | Absent, but coverage or metadata is insufficient to infer disappearance safely. |

Changed fields include severity, decision, decision reason, exception, scope, title,
description, locations, and reported fixed versions. This is a normalized finding
comparison, not a byte-for-byte diff of every raw engine observation. Component
comparison uses package identity/version/ecosystem/scope and preserves license
changes. Version changes create separate identities rather than being merged as the
same package occurrence. Component states are `added`, `changed`, `unchanged`,
`removed`, and `unverified`.

Incomplete runs, differing configuration hashes, branches, sekscan versions,
scanner versions, scanner sets, required status, native configurations, enabled
checks, or failed/skipped scanners make absence conservatively **unverified**.
Configuration hashes may differ even for harmless workspace-path changes; the UI
does not guess that those changes are safe. Different target locations/references
and changed recorded vulnerability-database metadata generate additional warnings.
Database changes alone do not block comparison: advisory additions/removals may
explain a difference, so even a comparable result is only a snapshot observation.

Findings without a trustworthy engine/check coverage match are not automatically
resolved. Missing/duplicate finding fingerprints reject the pair rather than hiding
ambiguous records. Inputs are immutable; no comparison overwrites a scan or changes
its CI policy outcome.

## Paging and CLI output

```sh
sekscan history projects --page 1 --page-size 25 --json
sekscan history list --project payments-api --branch main --page 2 --page-size 25 --json
sekscan history list --project payments-api --from 2026-09-01 --to 2026-09-30 --kind dir
sekscan history trends --project payments-api --branch main --kind dir --trend-limit 100 --json
sekscan history export RUN_ID --out restored-report
```

Projects, runs, and comparison lists have first/previous/next/last navigation,
page-size controls, and page jump. The portable per-scan dashboard offers equivalent
paging for findings, licenses, inventory, and baseline changes. Filters reset paging.
Default size is 25. The API and CLI accept sizes 1..200; UI sizes are
10/25/50/100/200. Pages start at 1. Offset is bounded at 100,000; narrow filters rather
than traversing an unbounded result. The legacy `--limit` and `--offset` remain
supported; do not combine a nonzero offset with a page other than 1.

**Breaking change:** `history list --json` and `/api/scans` now return a page envelope,
not the old bare JSON array. Update integrations to consume `items`:

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 25,
  "page_count": 0,
  "offset": 0,
  "has_next": false,
  "has_previous": false
}
```

`history compare --json` includes comparison metadata and the requested page.
`history compare --out FILE.json` instead writes the **entire unfiltered comparison**;
it is an explicit full export, not just the visible page. Large exports may be
sensitive. `history trends --json` returns a bounded `points` array plus
`total_matching_runs`, `limit`, `truncated`, and a caution note.

## Local read-only API

```text
GET /api/projects?page=1&page_size=25&q=payments
GET /api/scans?project=payments-api&page=2&page_size=25&branch=main&kind=dir
GET /api/trends?project=payments-api&trend_limit=100&from=2026-09-01&to=2026-09-30
GET /api/compare?base=BASE_ID&head=HEAD_ID&view=findings&page=1&page_size=25&change=new
GET /api/compare?base=BASE_ID&head=HEAD_ID&view=components&page=1&page_size=25
```

Project/run lists are paged **in SQL**, retrieving summary rows rather than every
report blob. SQL uses stable ordering with an ID tie-breaker, and parameterized,
escaped search. Lists reflect current data: concurrent imports can shift offset pages;
there is no transaction snapshot token shared across separate page requests.

Comparison loads the two bounded report snapshots, computes a deterministic diff in
memory, and pages its response. It does not stream a SQL-side full-history diff.
The portable HTML dashboard necessarily holds its report in browser memory and
paginates locally. These different execution models are intentional.

The server always uses its configured namespace and does not accept a request-level
namespace override. It never exposes arbitrary local files or write endpoints.

## Schema and deployment

Database **schema v1 is unchanged**. Existing project, run-summary, engine, component,
finding, and artifact data supports these features without rewriting migrations.
Do not edit the checksum of an already applied schema. New PostgreSQL/SQL Server
paging and aggregation queries have unit/dialect coverage and opt-in live tests;
validate them with `scripts/test-databases.sh` on disposable services before rollout.
See [DATABASE.md](DATABASE.md), [SECURITY.md](SECURITY.md), and [../TESTING.md](../TESTING.md).

## Screenshots

Synthetic demonstration data only: [Projects](history.png),
[project trends and paged runs](project-trends.png), and
[two-run comparison](run-comparison.png).


## Sekura 3.0.2 navigation and table density

History, reports and comparisons use one shared shell. Project pages appear under
a separately expandable Projects branch; expansion does not navigate. Reports and
comparisons appear in Open view. On smaller viewports the navigation is a modal
drawer; Escape closes it and returns focus. Desktop navigation can collapse.

Table density affects only the table, not surrounding filters or text size.
Project keys, selected comparison runs, paging and filtering keep their existing
meaning. Appearance includes four explicit themes and System. See [UI behavior](UI.md)
and [migration instructions](DESIGN-MIGRATION-3.0.2.md). Old standalone HTML must be
regenerated from JSON to receive new assets; stored history renders them directly.
