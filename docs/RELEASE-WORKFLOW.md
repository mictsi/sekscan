# GitHub release workflow

`.github/workflows/release.yml` builds only on `release: { types: [published] }`.
This includes stable releases and prereleases. It has no push/tag-push,
pull-request, draft-created, release-edited, or manual-dispatch trigger.
The separate `test.yml` may run tests on pushes; it does not publish release assets.

## Set up before the first release

1. Commit the workflow, `scripts/release_event.py`, `scripts/tests/`, the release
   builder, and all intended application changes. Put the workflow on the default
   branch as well as the tagged source; do not tag an older snapshot missing it.
2. On a connected machine, run `bash scripts/build.sh`. Review and commit the
   resolved `go.mod` and `go.sum`. This source preview has no resolved production
   go.sum, so the release gate will fail until it is created and committed.
3. Confirm GitHub Actions is enabled, the repository permits the pinned official
   actions, and the publishing job may use `contents: write` for its GITHUB_TOKEN.
   There is no separate personal access token requirement.
4. Confirm the intended release is mutable. Published immutable releases cannot
   accept new assets. This workflow intentionally fails instead of changing security
   settings or claiming uploads succeeded.
5. Tag the reviewed commit with a SemVer-style name such as `v0.6.5-preview` or
   `v1.0.0`. Create and publish a GitHub release for that exact tag.

Example from a trusted local checkout after all checks and module review:

```bash
git add .github/workflows/release.yml scripts/ README.md readme.med docs/ \
  internal/ go.mod go.sum SOURCE-PACKAGE.json CHANGELOG.md TESTING.md
git commit -m "Prepare sekscan release"
git tag -a v0.6.5-preview -m "sekscan 0.6.5-preview"
git push origin HEAD
git push origin v0.6.5-preview
# Now publish a GitHub release for v0.6.5-preview in the repository UI.
# Pushing the tag alone does not build or publish binaries.
```

These are maintainer commands, not actions performed by the assistant. No repository
or release was modified during creation of this source package.

## Build and publication flow

```text
release.published
  -> checkout event SHA
  -> verify tag points to that commit + committed module lock
  -> select tagged go.mod toolchain
  -> publication-control unit tests
  -> existing release builder: modules, tests, vet, all six builds, packaging
  -> seal full artifact set with release ID/tag/commit + checksums
  -> upload build artifact
  -> separate publishing job (contents: write)
  -> download this run's artifact and verify everything again
  -> verify current remote release ID and tag commit
  -> attach assets to that existing release ID
```

The source is **not** checked out using default-branch HEAD or `target_commitish`.
A moved tag, draft release, different release ID/commit, missing platform, failed
build, skipped tests, changed dependencies, or checksum mismatch stops publication.
The tag is passed as data, not inserted into shell code. `v` is stripped from the
binary version/filenames; the original tag remains in `release-source.json`.

The jobs use GitHub-hosted Ubuntu 24.04. The first job cross-compiles:

| Target | Archive suffix |
|---|---|
| Linux x86-64 | `linux-amd64.zip` |
| Linux ARM64 | `linux-arm64.zip` |
| Windows x86-64 | `windows-amd64.zip` |
| Windows ARM64 | `windows-arm64.zip` |
| macOS Intel | `darwin-amd64.zip` |
| macOS Apple Silicon | `darwin-arm64.zip` |

Every ZIP includes the executable, docs, examples, schema, and clean workspace.
The source ZIP, `release.json`, `release-source.json`, and `SHA256SUMS.txt` are also
attached. ZIP contents have their own checksums. Scanner executables, CVE databases,
credentials, active workspace history, and application logs are not bundled.

Only the publishing job has repository write permission. All `uses:` entries are
pinned to full upstream commits; provenance is recorded in
[RELEASE-ACTIONS.json](RELEASE-ACTIONS.json). Check and review pins when upgrading.
Native OS tests, signing/notarization, database-server integration, and live scanner
execution are not implied by cross-compilation. The workflow does not sign binaries.

## Retries and failure behavior

Build output is transferred only after every requested target succeeds. GitHub asset
uploads themselves are **not transactional**: a network failure can leave a subset
uploaded. Rerun the failed publishing job to reuse the same artifact set.
Already uploaded assets are skipped only when their server-provided SHA-256 matches.
A collision with different content or no verifiable digest fails; no `--clobber`,
asset deletion, tag movement, or automatic replacement is used.

Do not delete an asset merely to hide a mismatch. Inspect the run and artifacts.
Build artifacts are retained for seven days; expired artifacts require a reviewed
rebuild, and changed bytes may correctly prevent overwriting an existing release.
The concurrency group is scoped to the release ID and does not cancel an active run.

The dependency lock is required in the tagged commit. The release path never runs
`go get -u`, `go mod tidy`, or resolves "latest" module versions. Do dependency
updates separately, commit them, and tag afterward. It does not execute offline SQL
test drivers and explicitly rejects binaries missing the production DB modules.

## Immutable release limitation

GitHub prohibits adding assets after publishing an immutable release. A workflow
that starts *only after publication* therefore cannot attach newly built binaries
to that immutable release. The guard reports this clearly; it never disables
immutability. Organizations requiring immutable releases need an approved
**draft -> build -> upload -> publish** process, which is a different trigger/order
than the published-only workflow requested here.

## Local verification and references

```bash
python3 -m unittest discover -s scripts/tests -v
(cd scripts/release && go test ./...)
```

Control tests use synthetic artifact bytes and local Git/HTTP stubs, not real
release uploads. See [TESTING.md](../TESTING.md) for acceptance still outstanding.
The publication helper requires Python 3.11+ and Git; actual upload uses GitHub CLI
available on the selected hosted runner. They are release-time prerequisites only,
not sekscan runtime prerequisites.

- [GitHub release workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#release)
- [GitHub immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [Release asset upload API](https://docs.github.com/en/rest/releases/assets#upload-a-release-asset)

## 0.6.4 target and prerequisite boundary

`scripts/release/targets.json` is the canonical six-platform list. The Go release
builder embeds it, and the publication validator loads the same tagged file. A
release missing its Windows ARM64 archive fails validation. Include this file when
copying the workflow helpers; the full source ZIP contains the complete set.

To build Windows ARM64 alone after resolving/reviewing the production dependencies:

```bash
bash scripts/build-release.sh --version 0.6.5-preview --targets windows/arm64
```

An ARM64 application executable does not imply native availability of every external
scanner or runtime. Native assets must exist for each selected scanner; no emulation,
system-tool substitution or automatic required-check disablement is introduced.
Semgrep is removed from all scanner platforms. See [validation](../TESTING.md) for
the distinction between cross-compilation and native runtime acceptance.
