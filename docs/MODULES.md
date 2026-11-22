# Production Go modules and update workflow

Updated on 2026-11-22 using the repository's module updater:

| Dependency | Selected version |
|---|---|
| Go toolchain | go1.27.4 |
| github.com/jackc/pgx/v5 | v5.13.0 |
| github.com/microsoft/go-mssqldb | v1.12.0 |
| modernc.org/sqlite | v1.63.0 |
| modernc.org/libc | v1.80.1 |

The minimum Go version remains 1.26.0. Direct, test, and transitive modules
are updated within their current major module paths. SQLite's libc dependency
is deliberately held at the exact version required by SQLite's own go.mod.
Production checksums are committed in `go.sum`.

## Update every resolvable module on a connected machine

Use a clean working copy with a supported Go installation:

```sh
bash scripts/update-modules.sh
# PowerShell equivalent:
# .\scripts\update-modules.ps1
```

Or run the cross-platform standard-library updater directly:

```sh
go run ./scripts/moduleupdate --yes
```

It updates direct, test and transitive dependencies using Go's latest resolution
within their current module/major paths, checks retained requirements for remaining updates, and follows new dependencies
until the graph converges. Graph-only modules removed by tidy are recorded in the
report but are not repeatedly re-added. It
reapplies SQLite's tested libc requirement, runs `go mod tidy`, `go mod verify`,
`go test ./...`, and `go vet ./...`, and records the resulting graph in
`module-updates.json`. Replacements or unresolved upgrades require manual review.

On ordinary errors or caught cancellation, original go.mod/go.sum are restored.
A retained `.module-update-backup-*` directory allows recovery after an uncatchable
termination. Process termination/power loss is not a transactional filesystem guarantee.
Review the diff, release notes and the report before committing go.mod and go.sum.
The automatic updater does not migrate imports to a new major module path, certify
API compatibility on untested platforms, or run real external SQL services.

The updater's parsing and rollback have local tests with a synthetic Go-command
fixture. Its network resolution, module verification, full application tests, and vet
passed on 2026-11-22 with Go 1.27.4.

Primary references:
- https://go.dev/dl/?mode=json
- https://github.com/jackc/pgx/releases/latest
- https://github.com/microsoft/go-mssqldb/releases/latest
- https://pkg.go.dev/modernc.org/sqlite
- https://gitlab.com/cznic/sqlite/-/raw/v1.60.1/go.mod
