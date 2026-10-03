# Batch and GitHub scanning

sekscan 0.6 uses **one versioned batch manifest** for local directories and GitHub
repositories. `schema/batch.schema.json` is the canonical JSON Schema (2020-12).
`sekscan batch schema` emits those exact embedded bytes; it does not download a schema.
Single-repository `github` mode constructs and executes the same validated plan.

## Quick start

After building/installing sekscan and preparing a trusted workspace:

```sh
./sekscan prepare --home ./workspace --all --with-java --yes
./sekscan batch validate projects.json
./sekscan batch projects.json --dry-run
./sekscan batch projects.json --home ./workspace --out ./batch-reports
./sekscan serve --home ./workspace
```

On Windows use `.\sekscan.exe` with the same arguments. Build instructions are in
[README.md](../README.md). The source package does not contain scanner executables
or CVE databases. `prepare` installs configured tools into the managed `bin/` and
`cache/` directories even when copies exist on PATH. Batch execution does not install
or update executables implicitly.

## One manifest

Save `projects.json` alongside the folders it references:

```json
{
  "$schema": "./schema/batch.schema.json",
  "version": 1,
  "defaults": {
    "gitleaks": true,
    "actionlint": true
  },
  "continue_on_error": true,
  "projects": [
    {
      "project": "payments-api",
      "path": "../payments-api"
    },
    {
      "repo_url": "https://github.com/mictsi/SekuraDesignMCP"
    },
    {
      "project": "design-system-source",
      "repo_url": "https://github.com/mictsi/SekuraDesignMCP",
      "ref": "main",
      "subdir": "src",
      "settings": {
        "actionlint": false
      }
    }
  ]
}
```

Adjust `$schema` to the schema file's location in your editor. sekscan does not
fetch this URI. `examples/batch.json` and `examples/batch-local.json` use the same
schema, not separate local/GitHub configuration formats.

| Field | Meaning |
|---|---|
| `version` | Required integer `1`. This is the batch schema version, not the application configuration version. |
| `projects` | Required array with 1–1,000 entries. |
| `project` | Required for a local directory. Optional for GitHub; defaults to lowercase `owner/repository`. |
| `path` | Local directory; relative paths resolve against the **manifest's folder**, never the current working directory. Absolute paths work. |
| `repo_url` | GitHub repository URL or `owner/repository`; mutually exclusive with `path`. |
| `ref` | GitHub branch, tag, or full commit SHA; omitted means resolve the repository's default branch. |
| `subdir` | Optional relative GitHub subdirectory; it must exist and cannot escape the snapshot. |
| `defaults`, `settings` | Boolean scan settings shared across entries or overridden per entry. |
| `continue_on_error` | Defaults to `true`. `false` stops after the first nonzero result, including a policy failure. |

Allowed settings: `offline`, `inventory_only`, `gitleaks`, `actionlint`, `hadolint`,
`zizmor`, `govulncheck`, `gosec`, `trivy_vuln`, and `no_store`. Values must be booleans; `null` is not omission.

The seven source checks are enabled in the default application configuration and
run only on applicable inputs. Explicit `false` remains an opt-out. Batch schema
version 1 is retained; older manifests still validate. Example per-entry override:

```json
{"project":"api","path":"../api","settings":{"hadolint":true,"gosec":false}}
```

Prepare tools, the Go vulnerability snapshot and any needed Go module dependencies
before starting the batch. Batch and GitHub snapshot scans never execute dependency
installation as a hidden step. See [DEFAULT-SCANNERS.md](DEFAULT-SCANNERS.md).

Precedence is **trusted application config → manifest defaults → entry settings →
explicit CLI flags**. An explicit `false` overrides `true`. Offline and
inventory-only default to false. Main-config project identity is always replaced
by the validated entry's identity. Namespace and SQL storage come from the selected
trusted application configuration.

The loader rejects unknown fields, duplicate JSON keys, non-lowercase key spelling,
nulls, invalid source combinations, repeated project identities, excessive nesting,
and manifests larger than 4 MiB. Project names must follow the application's normal
identity rules. Duplicate identities are checked case-insensitively to avoid common
SQL Server collation collisions. Structural schema validation is supplemented by
runtime checks for project uniqueness, repository URLs, safe refs and local paths.

Use distinct explicit project names for different subdirectories/refs of one repo.
Use the **same** project key as earlier local scans when you intend GitHub scans to
join their history. Inferred names do not rename or merge existing projects.

## Commands and reporting

```sh
./sekscan batch schema > batch.schema.json
./sekscan batch validate projects.json
./sekscan batch projects.json --dry-run --json
./sekscan batch --file projects.json --config trusted-sekscan.json --out reports
./sekscan batch projects.json --gitleaks=false --fail-fast
```

`validate` and `--dry-run` validate the manifest and print a resolved plan without
network access, scanner execution, configuration loading, or database writes. They
are not a prerequisite or filesystem-existence check; use `doctor` and `db status`.

Execution is **sequential** in manifest order. This avoids competing writes to
scanner caches. Every invocation uses a new timestamp/random batch ID and output
subdirectory; it never merges reports from several projects into one SBOM.

```text
batch-reports/<batch-id>/
├── batch-results.json
├── 0001-payments-api-<hash>/
│   ├── results.json
│   ├── index.html
│   └── ... usual reports and available SBOMs
└── 0002-mictsi-sekuradesignmcp-<hash>/
    └── ...
```

The JSON summary is written atomically before execution and after each attempted
entry. It includes project, source, resolved revision, run ID, status, exit code,
relative report directory, timing, and safe errors. With `--json`, stdout contains
the final summary, while progress goes to stderr. Each normal result is persisted
under its project using existing SQLite/PostgreSQL/SQL Server storage. `no_store`
disables history for that entry but retains project identity in its report.

Missing local paths, inaccessible repositories, and failed acquisition produce
incomplete entry reports/history records where reporting and storage remain
available. Unattempted entries after fail-fast/cancellation appear as `skipped` in
the summary and do not fabricate scan history. A killed process may leave a
`running` summary; automatic resume is not implemented.

Exit codes: **0** all requested entries completed and passed; **1** completed
assessments with policy failures; **2** operational error, incomplete acquisition,
failed required coverage, or unattempted entries. The highest code wins. CI should
publish the complete batch output folder even when the scan step fails; do not hide
its exit status. Reuse the existing trusted-config and artifact-publishing pipeline
patterns with the `batch` command.

## GitHub mode

```sh
./sekscan github https://github.com/mictsi/SekuraDesignMCP --home ./workspace
./sekscan github mictsi/SekuraDesignMCP --ref main --project SekuraDesignMCP
./sekscan github mictsi/SekuraDesignMCP --ref main --subdir src --project design-source
./sekscan github:mictsi/SekuraDesignMCP --dry-run
```

The default project is `mictsi/sekuradesignmcp`, not just the repository basename.
The URL is canonicalized; an optional `.git` suffix is removed. GitHub SSH-style
`git@github.com:owner/repository.git` input is normalized to the same HTTPS API flow;
it **does not use SSH keys**. Non-GitHub hosts, enterprise instances, tree/blob URLs,
credential-bearing URLs, query strings, and fragments are not supported.

The client resolves the selected ref to a full commit and downloads an archive via
GitHub's repository/commit/archive REST endpoints. It **does not require Git** and
does not clone history. Authentication comes from `GITHUB_TOKEN`, or the environment
variable named by `--token-env`:

```sh
# Provision SEKSCAN_GITHUB_TOKEN through a secret manager or CI secret variable.
./sekscan github owner/private-repository --token-env SEKSCAN_GITHUB_TOKEN
./sekscan batch projects.json --token-env SEKSCAN_GITHUB_TOKEN --json
```

Do not put token values in the manifest, URLs, command arguments, or committed
configuration. Fine-grained tokens need repository Contents read access. Public
repository archives can be accessed without a token, subject to API rate limits.
HTTP errors distinguish access/rate-limit failures without storing raw response
bodies. No retry scheduling/backoff is implemented; retry explicitly after resolving
the cause. API documentation is linked below.

The token is sent only to `api.github.com`, stripped from redirects to the allowlisted
`codeload.github.com` host, and excluded from scanner and version-probe environments.
Unapproved redirect hosts/protocols are rejected. Paths, revisions, archive hashes,
and the requested/resolved ref are recorded as source provenance; token values and
signed archive redirect URLs are not recorded. The report's branch field carries
the resolved named ref (which may be a tag); detached full commits leave it empty.

### Source cache and portability

```text
workspace/cache/sources/github/<repository-hash>/
├── <commit>.tar.gz
└── <commit>.tar.gz.json
```

Downloads use temporary files and atomic moves. The metadata records a SHA-256
checksum, rechecked before every reuse. Extraction creates a fresh isolated
workspace, removed after the job. Source text is not retained in the shared history
database; the portable source archive remains in this workspace cache. Reports and
SBOMs are still sensitive and should be protected like source code. Scanner-native
SBOM evidence can include the temporary extraction path; normalized report identity
is the stable repository/subdirectory URL.

To scan offline, first scan the exact commit online, then copy the prepared
workspace (tools, databases, source cache) to the same OS/architecture:

```sh
# Replace COMMIT_SHA with the full 40-character revision from a previous report.
./sekscan github owner/repository --ref COMMIT_SHA --offline --home ./workspace
```

Offline mode requires an exact cached full SHA. It will not silently interpret a
cached mutable branch as its latest version. Scanner databases and target dependency
content must also be prepared. The `prepare` command prepares scanners/data, not
arbitrary future repository snapshots.

### Coverage and trust

A GitHub archive is a snapshot, not a built image, dependency installation or full
Git repository. No install scripts, hooks, repository configuration, or workflows
are executed. No config is discovered inside downloaded source or batch targets.
Scanner configuration comes only from the explicitly selected trusted application
workspace/config. The batch manifest itself controls coverage and must also be
protected from untrusted pull-request changes.

Archive extraction rejects traversal, absolute/ambiguous paths, duplicate or
case-colliding entries, multiple roots, and special device files. It removes execute
permission from extracted files. Symlinks/hardlinks are skipped; `.gitmodules`,
unresolved Git LFS pointers, or skipped links mark acquisition **incomplete**. The
available content can still be assessed, but the required acquisition check prevents
a clean result. Build outputs, submodules and LFS content must be supplied as a
complete local directory for that coverage. Directory secret scanning does not
inspect old commits.

Current limits: 512 MiB downloaded archive, 2 GiB expanded regular-file content,
200,000 archive entries, bounded metadata and trailers, request timeout 10 minutes.
Subdirectory scanning still downloads the whole archive. These limits are fixed in
this version. GitHub-specific live integration still needs validation in a connected
environment; current tests use controlled HTTPS transports and tar fixtures.

## References

- GitHub [repository archive API](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-tar).
- GitHub [commit resolution API](https://docs.github.com/en/rest/commits/commits#get-a-commit).
- [History, portfolio and comparison semantics](HISTORY.md).
- [Workspace portability](PORTABLE.md).

## Retired scanner setting

Legacy `defaults.semgrep` and per-project `settings.semgrep` booleans are accepted
as ignored compatibility input. The schema marks this property deprecated. New
plans omit it; no job installs or executes Semgrep. No other batch settings change.
