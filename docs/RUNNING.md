# Native application launcher

`run.sh` manages sekscan's read-only dashboard as a background process on Linux.
It requires Bash, `flock`, `curl`, and Go for builds. It can be invoked from any
directory. The existing application executable and direct CLI remain available.

```sh
cp .env.example .env  # first setup only; run.sh also creates it if absent
# Edit .env for your workspace, port, and application settings.
./run.sh build
./run.sh start
./run.sh status
./run.sh logs
./run.sh logs --follow
./run.sh restart
./run.sh stop
./run.sh clean
```

The default URL is `http://127.0.0.1:8080`. `start` builds automatically only if
`.run/sekscan` is missing; after source changes run `stop`, `build`, then `start`.
`build` verifies Go modules, runs tests/vet by default, and builds without changing
module declarations. Set `SEKSCAN_BUILD_TESTS=false` to skip tests/vet. `build`
refuses to replace a running dashboard binary. Go must satisfy `go.mod`.

`stop` sends SIGTERM and waits for graceful shutdown. The launcher records the
PID and Linux process start time and checks the executable before signaling it.
It refuses to force-kill a process that exceeds `SEKSCAN_STOP_TIMEOUT`.
Concurrent lifecycle commands are serialized with `flock`.

`clean` stops the dashboard and removes only `.run/sekscan`, temporary build
output, the PID file, and `.run/app.log`. It preserves `.env`, workspace settings,
databases, reports, scanner installations and caches. Logs append across starts;
`logs` shows the last `SEKSCAN_LOG_LINES` lines and `logs --follow` follows output.

## Configuration

`.env.example` lists launcher settings. `.env` is ignored by Git and created with
private permissions. An alternate file can be selected with:

```sh
SEKSCAN_ENV_FILE=/path/to/settings.env ./run.sh start
```

The file uses literal `KEY=value` lines, optionally enclosed in matching single
or double quotes. Blank lines and whole-line comments are allowed. Do not use
`export`, inline comments, shell substitutions, multiline values or variable
references: the launcher deliberately does not execute or interpolate them.
File values override inherited environment values. Relative paths start at the
repository directory, including paths from an alternate environment file.

All application settings supported by `sekscan.json` can be supplied as compact
JSON in `SEKSCAN_SETTINGS_JSON`, for example:

```dotenv
SEKSCAN_PORT=8090
SEKSCAN_WORKSPACE=./workspace
SEKSCAN_SETTINGS_JSON='{"version":2,"project":{"namespace":"engineering"},"checks":{"kics":true},"policy":{"fail_at":"high"}}'
```

On `start` and `cli`, the launcher initializes missing workspace files without
overwriting them, validates this JSON, and writes `workspace/.run-settings.json`.
This generated file is the explicit application configuration; an existing
workspace `sekscan.json` is preserved but is not merged into it. `{}` selects
application defaults. To use an existing reviewed configuration instead, set
`SEKSCAN_CONFIG_FILE`; then `SEKSCAN_SETTINGS_JSON` is ignored and the existing
file is never rewritten. Native config paths retain the application's normal
resolution rules. `.env` changes take effect after restart.

`SEKSCAN_PROJECT` optionally filters history. `SEKSCAN_REPORT_DIR` instead serves
an existing report directory; leave `SEKSCAN_PROJECT` empty for report mode.
The dashboard remains loopback-only, with its existing Host/Origin checks.

Database credentials belong in `SEKSCAN_DB_DSN`, with storage driver/settings in
the JSON. Do not put credentials directly in JSON. The loader also accepts
`GITHUB_TOKEN`, `GH_TOKEN`, `TRIVY_*`, `SYFT_*`, `GRYPE_*`, `AWS_*`, `AZURE_*`, Go
proxy/private-module settings, and HTTP proxy settings. Scanner subprocesses
still use sekscan's existing environment filtering.

## Scans and preparation

Starting the dashboard does not perform scans or download scanners. Use `cli`
to run application commands with the same environment, workspace, and config:

```sh
./run.sh cli prepare --all --yes
./run.sh cli scan dir:/path/to/project --project my-project
./run.sh cli history projects --json
```

Do not supply conflicting `--home`/`--config` flags to `cli`. CLI commands run in
the foreground and retain their exit codes (including policy failures). Only the
dashboard started by `start` is controlled by `stop`.

## Launcher validation

Run the lifecycle integration tests against a built application:

```sh
SEKSCAN_TEST_BINARY="$PWD/.run/sekscan" \
  python3 -m unittest discover -s scripts/tests -p test_run.py -v
```

Tests use temporary directories and loopback ports. They cover startup, restart,
shutdown, log access, settings propagation, invalid settings, occupied ports,
literal environment parsing, stale PID handling, and preserving data during clean.
