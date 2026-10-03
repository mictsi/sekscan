# Sekura 3.0.2 consumer migration

Application: sekscan 0.5.1-preview. Previous application: 0.5.0-preview.
Reference: https://github.com/mictsi/SekuraDesignMCP at
`687bcdcf67d56a3bdfe3bbc4ff1ae863239e8c8a`, package 3.0.2 (2026-10-03).
Previous reference: `73d22913fa513d40926b5639096dd951d3d1fcbb`.

## Inventory and changes

| Surface | Change | Preserved behavior |
|---|---|---|
| Shared shell | One Go template instead of separate history/report markup; compact header/rail; neutral canvas | Safe escaping, loopback viewer, read-only data |
| Navigation | Parent link plus separate disclosure; guide line; exact current marker; separate Open view | Ordinary URLs, project keys, browser Back destinations |
| Mobile | Modal drawer, inert background, scrim, keyboard confinement and focus return | Page content, selected run and filters |
| Portfolio | Four-track filters, aligned actions, continuous metrics | Latest-run-per-project aggregates, incomplete/stale warnings |
| Projects / runs | Table-only density, aligned comparison selector, shared paging treatment | Server-side pagination and comparison selection across pages |
| Comparison | Shared heading, fields and table controls | Summary/evidence tabs, coverage caveats, finding/component semantics |
| Stored / portable report | Shared shell, visible labels, named evidence dialog, inline import errors | Filter/sort/page/export/import behavior and standalone operation |
| Error / empty states | Shared browser error shell and recovery actions | Original HTTP statuses; API errors remain non-HTML |
| Themes | Four explicit themes plus System, logical RTL and forced colors | Existing best-effort theme preference; no runtime network dependency |

The palette and semantic upstream source blobs were unchanged between the two
reviewed references; the important maintenance changes were navigation hierarchy
and composition/field alignment. The application also removes its older custom
shell dimensions and literal per-view control sizing. This does not mix two full
upstream CSS bundles or introduce a second controller owner.

## Compatibility

There is **no SQL migration**. SQLite, PostgreSQL and SQL Server schema version 1,
project/run IDs, report JSON schema 1.0, batch manifest version 1, command-line
options, scanner settings and Go module pins remain unchanged. No scanners, CVE
databases, or credentials are downloaded by this update. Browser table-density and
navigation-collapse settings are local preferences, not new database columns.

Default `serve` still opens the all-project portfolio in the configured namespace.
An explicit `--project` still fixes that scope. Explicit report-directory serving
remains a standalone viewer. The source package is not a replacement executable.

## Build and deploy

On a connected machine, from the new source directory:

```sh
bash scripts/build.sh
./sekscan version
./sekscan serve --home /path/to/existing-workspace
```

Windows:

```powershell
go mod tidy
go mod verify
go test ./...
go vet ./...
$env:CGO_ENABLED = '0'
go build -trimpath -o sekscan.exe ./cmd/sekscan
.\sekscan.exe serve --home C:\path\to\workspace
```

Review and commit resolved module files as described in the source README. Reuse
the existing workspace; do not delete `data/`, `bin/`, `cache/`, or scanner configs.
Stop the old viewer before replacing the executable. A running viewer keeps the
assets compiled into that executable until restarted.

Stored-history report pages get the new presentation automatically. Old standalone
HTML remains static. Regenerate it without rescanning:

```sh
./sekscan report ./old-report/results.json --out ./refreshed-report
./sekscan serve ./refreshed-report
```

Use a new output directory and preserve old report/SBOM artifacts. JSON-to-HTML
rendering does not regenerate SBOMs or create a new security assessment.

After dependency resolution, the existing five-target ZIP builder includes these
instructions, the design-reference manifest and license:

```sh
bash scripts/build-release.sh --version 0.5.1-preview --targets all
```

## Acceptance and rollback

Run the normal tests, then `scripts/history-smoke.py --design-review` against a
production build, using a supported Chromium executable. Check the named flows in
`docs/UI.md`, native browser navigation, stored preferences, Firefox/WebKit and
manual screen-reader reading/focus order. The included automation is not a complete
accessibility review. `TESTING.md` records the checks actually run in this environment.

Rollback replaces the executable with the previous version and restarts the viewer.
No data rollback is necessary. Keep previously exported reports when preserving
historical presentation matters. Do not clear unrelated browser preferences or scan
history as part of a presentation rollback.
