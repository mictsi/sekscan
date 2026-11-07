#!/usr/bin/env bash
# Native Linux lifecycle wrapper. Read .env literally; never source/eval it.
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$ROOT"
STATE="$ROOT/.run"
BINARY="$STATE/sekscan"
PIDFILE="$STATE/app.pid"
LOGFILE="$STATE/app.log"
ENV_FILE="${SEKSCAN_ENV_FILE:-$ROOT/.env}"
die() { printf 'run.sh: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: ./run.sh {start|stop|restart|status|build|clean|logs [--follow]|cli [arguments...]}
Settings: .env (created from .env.example if absent), or SEKSCAN_ENV_FILE.
start serves the dashboard; cli runs other sekscan commands with the same settings.
clean stops the app and removes launcher binaries, PID state, and logs only.
Workspace configuration, databases, reports, scanner binaries and caches are preserved.
EOF
}
action="${1:-help}"
if (($#)); then shift; fi
case "$action" in help|-h|--help) usage; exit 0 ;; start|stop|restart|status|build|clean|logs|cli) ;; *) usage >&2; exit 2 ;; esac
if [[ "$action" != cli && "$action" != logs && $# != 0 ]]; then die "unexpected arguments for $action"; fi
if [[ "$action" == cli && $# == 0 ]]; then die 'usage: ./run.sh cli <command> [arguments...]'; fi
[[ $(uname -s) == Linux ]] || die 'native lifecycle management currently requires Linux (/proc and flock)'
for command in flock curl; do command -v "$command" >/dev/null || die "required command missing: $command"; done
if [[ ! -f "$ENV_FILE" ]]; then
  [[ "$ENV_FILE" == "$ROOT/.env" ]] || die "environment file not found: $ENV_FILE"
  cp -- "$ROOT/.env.example" "$ENV_FILE"
  printf 'Created .env from .env.example\n'
fi
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || die 'invalid .env line; expected KEY=value'
  key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
  # Only app/build credentials and settings are accepted; never overwrite shell state.
  case "$key" in SEKSCAN_*|GITHUB_TOKEN|GH_TOKEN|TRIVY_*|SYFT_*|GRYPE_*|AWS_*|AZURE_*|GOPROXY|GOSUMDB|GOPRIVATE|GONOSUMDB|GONOPROXY|HTTP_PROXY|HTTPS_PROXY|NO_PROXY) ;; *) die "unsupported .env key: $key" ;; esac
  if [[ "$value" == \"* || "$value" == \'* ]]; then
    quote="${value:0:1}"
    [[ ${#value} -ge 2 && "${value: -1}" == "$quote" ]] || die "unclosed quote for $key"
    value="${value:1:${#value}-2}"
  fi
  export "$key=$value"
done < "$ENV_FILE"
SEKSCAN_WORKSPACE="${SEKSCAN_WORKSPACE:-$ROOT}"
SEKSCAN_PORT="${SEKSCAN_PORT:-8080}"
SEKSCAN_GO_BIN="${SEKSCAN_GO_BIN:-go}"
SEKSCAN_BUILD_TESTS="${SEKSCAN_BUILD_TESTS:-true}"
SEKSCAN_START_TIMEOUT="${SEKSCAN_START_TIMEOUT:-30}"
SEKSCAN_STOP_TIMEOUT="${SEKSCAN_STOP_TIMEOUT:-15}"
SEKSCAN_LOG_LINES="${SEKSCAN_LOG_LINES:-100}"
for key in SEKSCAN_PORT SEKSCAN_START_TIMEOUT SEKSCAN_STOP_TIMEOUT SEKSCAN_LOG_LINES; do
  value="${!key}"
  [[ "$value" =~ ^[1-9][0-9]{0,4}$ ]] || die "$key must be an integer from 1 to 99999"
done
((SEKSCAN_PORT <= 65535)) || die 'SEKSCAN_PORT exceeds 65535'
[[ "$SEKSCAN_BUILD_TESTS" == true || "$SEKSCAN_BUILD_TESTS" == false ]] || die 'SEKSCAN_BUILD_TESTS must be true or false'
mkdir -p -- "$STATE"
[[ ! -L "$STATE" ]] || die '.run must not be a symlink'
exec 9>"$STATE/control.lock"
flock -x 9

# Linux start ticks distinguish our process from a recycled PID. Also verify its
# executable before signaling it; a hand-edited/stale PID file cannot kill a shell.
identity() {
  local stat
  [[ "$1" =~ ^[1-9][0-9]*$ && -r /proc/$1/stat ]] || return 1
  stat=$(cat "/proc/$1/stat") || return 1
  stat="${stat##*) }"
  local fields
  read -ra fields <<< "$stat"
  [[ "${fields[0]}" != Z ]] || return 1
  printf '%s' "${fields[19]}"
}
running() {
  [[ -f "$PIDFILE" ]] || return 1
  read -r pid stamp < "$PIDFILE" || return 1
  [[ "$(identity "$pid" || true)" == "$stamp" && -n "$stamp" ]] || return 1
  [[ "$(readlink "/proc/$pid/exe" 2>/dev/null)" == "$BINARY" ]]
}
stop() {
  if ! running; then rm -f -- "$PIDFILE"; printf 'Not running\n'; return; fi
  kill -TERM "$pid"
  for ((i=0; i<SEKSCAN_STOP_TIMEOUT*10; i++)); do
    if ! running; then rm -f -- "$PIDFILE"; printf 'Stopped\n'; return; fi
    sleep 0.1
  done
  die 'graceful shutdown timed out; process retained (see logs)'
}
build() {
  if running; then die 'stop the app before rebuilding'; fi
  command -v "$SEKSCAN_GO_BIN" >/dev/null || die "Go executable not found: $SEKSCAN_GO_BIN"
  # Tests spawn Go themselves. Keep them on the same selected toolchain.
  local go_path
  go_path=$(command -v "$SEKSCAN_GO_BIN")
  export PATH="$(dirname "$go_path"):$PATH"
  "$SEKSCAN_GO_BIN" mod verify
  if [[ "$SEKSCAN_BUILD_TESTS" == true ]]; then
    "$SEKSCAN_GO_BIN" test ./...
    "$SEKSCAN_GO_BIN" vet ./...
  fi
  CGO_ENABLED=0 "$SEKSCAN_GO_BIN" build -mod=readonly -trimpath -o "$BINARY.new" ./cmd/sekscan
  mv -f -- "$BINARY.new" "$BINARY"
  printf 'Built %s\n' "$BINARY"
}
configure() {
  [[ -x "$BINARY" ]] || build >&2
  mkdir -p -- "$SEKSCAN_WORKSPACE"
  SEKSCAN_WORKSPACE=$(cd -- "$SEKSCAN_WORKSPACE" && pwd -P)
  "$BINARY" init --home "$SEKSCAN_WORKSPACE" >> "$LOGFILE" 2>&1
  config_file="${SEKSCAN_CONFIG_FILE:-}"
  if [[ -z "$config_file" ]]; then
    config_file="$SEKSCAN_WORKSPACE/.run-settings.json"
    [[ ! -L "$config_file" ]] || die 'generated settings file must not be a symlink'
    printf '%s\n' "${SEKSCAN_SETTINGS_JSON:-\{\}}" > "$config_file.tmp"
    "$BINARY" config validate --home "$SEKSCAN_WORKSPACE" --config "$config_file.tmp" >&2
    mv -f -- "$config_file.tmp" "$config_file"
  fi
  common=(--home "$SEKSCAN_WORKSPACE" --config "$config_file")
  "$BINARY" config validate "${common[@]}" >&2
}
start() {
  if running; then printf 'Already running (PID %s)\n' "$pid"; return; fi
  configure
  args=(serve "${common[@]}" --listen "127.0.0.1:$SEKSCAN_PORT")
  if [[ -n "${SEKSCAN_REPORT_DIR:-}" ]]; then args+=("$SEKSCAN_REPORT_DIR"); fi
  if [[ -n "${SEKSCAN_PROJECT:-}" ]]; then args+=(--project "$SEKSCAN_PROJECT"); fi
  printf '\n--- Starting %s ---\n' "$(date -Is)" >> "$LOGFILE"
  nohup "$BINARY" "${args[@]}" >> "$LOGFILE" 2>&1 < /dev/null 9>&- &
  pid=$!
  stamp=$(identity "$pid") || die "app exited during launch; see $LOGFILE"
  printf '%s %s\n' "$pid" "$stamp" > "$PIDFILE"
  for ((i=0; i<SEKSCAN_START_TIMEOUT; i++)); do
    if [[ -z "$(identity "$pid" || true)" ]]; then rm -f -- "$PIDFILE"; tail -n 20 "$LOGFILE" >&2; die 'app exited during startup'; fi
    if curl --noproxy '*' -fsS --max-time 1 "http://127.0.0.1:$SEKSCAN_PORT/" >/dev/null 2>&1; then
      sleep 0.2
      if running; then printf 'Started: http://127.0.0.1:%s (PID %s)\n' "$SEKSCAN_PORT" "$pid"; return; fi
    fi
    sleep 1
  done
  stop
  die "dashboard did not become ready; see $LOGFILE"
}
case "$action" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) if running; then printf 'Running (PID %s)\n' "$pid"; else printf 'Stopped\n'; exit 1; fi ;;
  build) build ;;
  clean) stop; rm -f -- "$BINARY" "$BINARY.new" "$LOGFILE" "$PIDFILE"; printf 'Cleaned launcher artifacts; workspace preserved\n' ;;
  logs)
    [[ -f "$LOGFILE" ]] || die 'no application log yet'
    flock -u 9
    if [[ "${1:-}" == --follow ]]; then exec tail -n "$SEKSCAN_LOG_LINES" -F "$LOGFILE"; fi
    [[ $# == 0 ]] || die 'usage: ./run.sh logs [--follow]'
    tail -n "$SEKSCAN_LOG_LINES" "$LOGFILE" ;;
  cli) configure; flock -u 9; exec "$BINARY" "$@" "${common[@]}" 9>&- ;;
esac
