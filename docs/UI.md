# UI design and navigation

sekscan **0.5.1-preview** adapts **SekuraDesignMCP 3.0.2** at commit
`687bcdcf67d56a3bdfe3bbc4ff1ae863239e8c8a`. Portfolio, project history, comparisons,
stored and portable reports, and history browser-error pages share one renderer
and presentation layer. No Node runtime, CDN, external font, or design server is
needed to use the executable or a self-contained HTML report.

## Reference and ownership

The reviewed upstream repository is https://github.com/mictsi/SekuraDesignMCP.
The pinned `package.json`, `CHANGELOG.md`, `MIGRATION.md`, form/navigation
specifications and semantic/primitive token definitions are recorded with Git
blob hashes in `third_party/SekuraDesignMCP.json`. The upstream MIT notice is
retained in `third_party/SekuraDesignMCP-LICENSE` (Copyright 2026 Michael Tsiortos).

This is a **Go-embedded adaptation**, not the complete upstream component runtime
or a claim of conformance certification. No upstream JavaScript executable bundle
or font files are copied into sekscan. Application-specific scan workflows, charts,
routes and permissions are not supplied by the design system.

The authoritative shell is `internal/ui/shell.go` / `assets/shell.html`. Both Go
renderers call it, escaping project names, URLs and other display context through
`html/template`. Shared CSS/JS live in `internal/ui/assets/`; consumer styles are
limited to report tables and history charts. Portable exports embed the same shared
asset bytes. Application JavaScript owns drawer/disclosure state; do not additionally
initialize upstream controllers on these elements.

## Information architecture

| Location | Tabs and navigation |
|---|---|
| `sekscan serve` | Portfolio Dashboard / Projects / All runs, across the configured namespace. |
| Project | Dashboard / Runs. The project appears beneath Projects with its own expandable branch. |
| Two-run comparison | Summary / Findings / Components and licenses. The comparison is listed separately under Open view. |
| Individual report | Dashboard / Findings / Application licenses / Inventory and SBOM / Changes / Scan health. |
| Browser error | Same shell, HTTP status, clear recovery links; API errors keep their existing response contract. |

Only the exact page gets `aria-current="page"` inside the workspace navigation.
The Projects ancestor is emphasized separately. Its disclosure button expands or
collapses the child list without following a route. The visible child guide is a
1px logical leading border; the current destination has an independent straight
4px accent. Project metadata, reports and comparisons do not masquerade as unrelated
menu destinations. Breadcrumbs retain current project identity.

Desktop navigation can collapse to an icon rail. Labels remain accessible;
focus/hover tooltips expose destination names. Below 64rem the rail becomes a modal
drawer with a scrim, background inertness, Tab/Shift+Tab confinement, Escape close,
and focus return. Resizing releases modal state. Expansion starts on the active
project branch; collapse never changes its selected route. Project-list filters,
run selection and pagination remain application-owned.

## Geometry, themes and controls

The reference dimensions at the normal root font size are a **48px header**, **272px
navigation**, **56px collapsed rail**, **32/40px page titles**, **36px controls**, and
14px control/table text. These are minimums or scalable rem dimensions, not rigid
heights that clip enlarged text. Wrapped header height is measured so content and
navigation do not overlap it. Dense data regions stay wide; tables scroll locally.

Appearance includes Dark, Light, High contrast dark, High contrast light, and
System. System follows color-scheme and increased-contrast changes. The existing
`sekscan.theme` preference is reused; optional persistence failure does not prevent
use. Navigation collapse uses `sekscan.nav.collapsed`. No preference grants access
or modifies stored scan evidence.

Filters use the Sekura four-track pattern: **label → optional hint → control →
feedback** in DOM and visual order. Peer fields share subgrid tracks, so wrapped
hints or errors do not misalign controls. Browsers without subgrid use a safe
single-column fallback. Apply/Reset buttons stay in the row's control track. Project
inputs retain native datalist wiring and a visible CSS indicator at rest, including
forced colors. Read-only fixed-project fields have no misleading dropdown indicator.

Every main table has a Table density control. Comfortable, Compact and Dense use
12/8/4px block padding only on that table region. Font size and surrounding filters
are unchanged. Best-effort density persistence is keyed per table. Paging, sorting,
selection and filtering remain independent of density.

## Report evidence and error states

Tabs retain existing filtering/paging behavior. Hidden component-inapplicable filters
hide their entire field, not just the control. Sortable report columns expose
`aria-sort`; data tables retain native header/cell semantics and keyboard-focusable
scroll regions. Status labels and marker shapes accompany colors.

The named native evidence dialog focuses its title on open and returns focus on
close. Invalid JSON imports show an inline alert without replacing the previous
report or clearing its active filter. HTTP error pages preserve error status and
safe recovery actions; internal server errors do not disclose raw database details.

Incomplete scans, coverage warnings, portfolio aggregation semantics and comparison
limits are unchanged. Latest-per-project totals do not turn failed coverage into
zero findings. A reduction in reported findings is not proof of remediation.

## Accessibility and validation boundary

The implementation includes a skip link targeting a focusable main landmark,
visible focus rings, named controls/dialogs, logical RTL positioning, manual tab
activation, reduced-motion handling and forced-color repair. Arrow keys/Home/End
move tab focus; Enter/Space activates. Ordinary navigation remains links plus
separate disclosure buttons, not an ARIA application menu.

Automated consumer tests check all primary surfaces at 320/390px, RTL and 200% root
text size, drawer keyboard behavior, four themes, selected actual text-contrast
pairs, density and filter alignment. This is **not** a complete WCAG audit,
screen-reader test, cross-browser certification or verification of every upstream
contrast pairing. Exact harness limits and untested conditions are in `TESTING.md`.

## Updating old reports

Stored history renders the current embedded UI at request time. Already-exported
HTML has its own frozen assets; it does not download updates. Re-render into a new
directory with `sekscan report old/results.json --out refreshed-report`. Keep the
original SBOMs; rendering does not recreate them or rescan dependencies.

See [migration and rollout](DESIGN-MIGRATION-3.0.2.md). Screenshots in `docs/screens/`
show synthetic fixture records, not real vulnerability assessments.
