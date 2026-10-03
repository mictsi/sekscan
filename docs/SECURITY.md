# Security boundaries

This application orchestrates **trusted executable software** against potentially untrusted content. It is not an OS sandbox, authenticated web service or legal compliance authority.

Local configuration discovery is intentional. A `sekscan.json` in the working/executable directory can select programs, policies and database destinations. Do not run discovery in untrusted folders. CI requires explicit config selection; that file and the sekscan binary must come from a trusted source outside pull-request control. `--no-config` disables discovery.

Commands use argv arrays, not a shell. This avoids shell interpretation but not arbitrary behavior of the selected executable. Native configs and additional arguments may change scanner coverage or network behavior. Use least-privilege operating-system identities, isolated runners and filesystem/network controls for untrusted targets. Do not expose a container engine socket or administrator credentials unnecessarily.

Managed downloads use approved GitHub release hosts, SHA-256 manifests, optional independent pins and available asset digests. They do not verify publisher signatures. Protect `bin/` and its metadata against modification; a local adversary who controls both metadata and executable hashes defeats local integrity comparisons. Do not install tools from unreviewed configuration or update a production gate silently.

Built-in scanner stderr is not placed in reports or normal logs because it can contain secrets. Explicit `--diagnostic-stderr` writes bounded raw stderr to separate restricted `*.private.log` files; never publish these without reviewing and redacting them. File modes are not a substitute for Windows ACLs. Known built-in secret evidence is redacted; arbitrary SARIF messages are not automatically sanitized. Source paths, package metadata, findings and license text can still be sensitive. Protect reports, logs, SBOM artifacts and database backups. Application logs rotate by invocation/size but have no automatic retention.

The configured DB DSN variable, platform access tokens and scanner-behavior environment prefixes are stripped from child processes. This is not credential isolation from a malicious tool with the same OS account. For untrusted CI jobs, prefer `--no-store`; use a separate trusted artifact-import job with restricted database credentials.

Database statements use bound parameters. Remote DSNs are environment references with verified TLS by default. Error details that might leak DSNs/query values are withheld. Remote migrations are explicit and should use an administrator identity separate from routine writers/readers. Provision databases and grants separately. Namespaces are filters, not row-level authorization; use separate databases/accounts for isolation.

The dashboard binds only to loopback, validates Host/Origin and serves read-only routes. It does not implement authentication, RBAC, SSO or safe public/reverse-proxy hosting. Report content is escaped rather than inserted as executable markup. Portable reports use a restrictive content security policy and embedded assets.

Offline mode sets supported built-in scanner options and disables generic extensions; it is not a network sandbox. A remote history connection is still a network connection. Scanner database bundles are separate from history storage. Use a trusted offline cache source and OS-level egress controls when disconnected execution is mandatory.

Database payload hashes detect mismatches relative to stored hashes; they are not signatures or trusted build attestations. Shared writers can submit fabricated reports. Immutability is enforced by the application insert contract, not by denying administrators the ability to change SQL data.

Do not interpret missing packages, failed tools, absent license evidence or incomplete scans as a clean assessment. Application-only license policies do not establish legal license compatibility. Scanner findings require validation in their project/build context.

The preview's production database drivers and live upstream scanners have not been validated in the restricted authoring environment. Run the connected build, actual scanner smoke tests, server integration tests and your own security review before production adoption.

## Portable execution

Portable mode resolves only managed binaries under the workspace `bin/`, validates
recorded platform and executable checksums, and places scanner home, temporary and
cache directories under the workspace. This prevents accidental PATH/cache reuse;
it does not restrict what a malicious executable can read, write or send. Native
config file contents can still name external resources. Custom runtime-dependent
extensions require those runtimes/helpers and their configuration to be packaged
explicitly; legacy PATH templates opt out of portable mode.

Database snapshots and vulnerability caches must be copied consistently. Stop
writers before a whole-workspace copy; use `storage backup` for a SQLite snapshot
while source connections may remain open. Never overwrite an active destination
or mix restored history with stale WAL/SHM files. Remote SQL services are not copied
by filesystem portability.
