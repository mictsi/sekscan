# Production Go modules and update workflow

Checked against primary upstream release/package metadata on 2026-10-02:

| Dependency | Selected version | Result |
|---|---|---|
| Go toolchain | go1.27.1 | Latest stable shown by go.dev; toolchain directive updated |
| github.com/jackc/pgx/v5 | v5.11.0 | Already matches the current release |
| github.com/microsoft/go-mssqldb | v1.11.2 | Already matches the current release |
| modernc.org/sqlite | v1.60.1 | Already matches the current module version retrieved |
| modernc.org/libc | v1.77.1 | Kept exactly aligned with SQLite's own go.mod |

Minimum module Go version remains 1.26.0. Upstream explicitly warns that SQLite must
use the same modernc.org/libc version as its own module file. A blind independent
libc upgrade is not a supported way to meet "latest".

**The complete production module graph was not downloaded or compiled here.** The
container's Go 1.23.2 cannot build the current SQLite module, and the attempt to
fetch the selected toolchain failed at DNS/network access. No go.sum or supposedly
validated transitive upgrade is fabricated. `docs/validation/v0.3.0/production-bootstrap-attempt.txt`
contains the failed command output. Existing direct pins were not newer releases
introduced by this patch; they were verified and retained.

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
within their current module/major paths, inspects the entire module build list for
remaining updates, and follows new dependencies until the graph converges. It
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
fixture. Its actual network resolution and successful production build remain unverified.

Primary references:
- https://go.dev/dl/?mode=json
- https://github.com/jackc/pgx/releases/latest
- https://github.com/microsoft/go-mssqldb/releases/latest
- https://pkg.go.dev/modernc.org/sqlite
- https://gitlab.com/cznic/sqlite/-/raw/v1.60.1/go.mod
