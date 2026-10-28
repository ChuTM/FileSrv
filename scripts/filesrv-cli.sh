#!/usr/bin/env bash
#
# tenant-fs-server admin CLI — manage the server from a shell over SSH.
#
# Talks to the loopback-only admin API (default http://127.0.0.1:8081/admin/v1)
# using the bearer token from .env (or TENANT_FS_ADMIN_TOKEN). Covers the same
# operations as the web admin console: apps lifecycle, users, audit, backups.
#
# Usage:
#   ./scripts/admin-cli.sh [--token TOKEN] [--admin-bind HOST:PORT] <command> [args...]
#
# Requires: curl + (jq or python3) for pretty-printing.
#
# Examples:
#   ./scripts/admin-cli.sh apps
#   ./scripts/admin-cli.sh app create my-app --quota 1GiB --max-file 64MiB
#   ./scripts/admin-cli.sh app rotate-secret 1
#   ./scripts/admin-cli.sh user add 1 alice@example.com
#   ./scripts/admin-cli.sh audit --app-id 1 --since 86400
#   ./scripts/admin-cli.sh backup run
#   ./scripts/admin-cli.sh backup list
#   ./scripts/admin-cli.sh health

set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration (from environment, or .env, or flags)
# ---------------------------------------------------------------------------
ADMIN_TOKEN="${TENANT_FS_ADMIN_TOKEN:-}"
ADMIN_BIND="${TENANT_FS_ADMIN_BIND:-127.0.0.1:8081}"
PUBLIC_BIND="${TENANT_FS_PUBLIC_BIND:-127.0.0.1:8080}"

if [ -f ".env" ]; then
  _tok=$(grep -E '^TENANT_FS_ADMIN_TOKEN=' .env 2>/dev/null | tail -1 | cut -d= -f2-)
  [ -z "$ADMIN_TOKEN" ] && [ -n "$_tok" ] && ADMIN_TOKEN="$_tok"
  _b=$(grep -E '^TENANT_FS_ADMIN_BIND=' .env 2>/dev/null | tail -1 | cut -d= -f2-)
  [ -n "$_b" ] && ADMIN_BIND="$_b"
  _p=$(grep -E '^TENANT_FS_PUBLIC_BIND=' .env 2>/dev/null | tail -1 | cut -d= -f2-)
  [ -n "$_p" ] && PUBLIC_BIND="$_p"
fi

ADMIN_BASE="http://$ADMIN_BIND/admin/v1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

warn() { printf 'warn: %s\n' "$*" >&2; }

json_pretty() {
  if command -v jq >/dev/null 2>&1; then
    jq .
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool
  else
    cat
  fi
}

# bytes_of "1GiB" -> 1073741824  (accepts B, KiB, MiB, GiB, TiB, or raw bytes)
bytes_of() {
  python3 -c '
import sys
s = sys.argv[1].strip()
num = s
mult = 1
u = s.upper()
for suf, m in (("TIB", 1024**4), ("GIB", 1024**3), ("MIB", 1024**2), ("KIB", 1024), ("B", 1)):
    if u.endswith(suf):
        num = s[: -len(suf)].strip()
        mult = m
        break
try:
    print(int(float(num) * mult))
except ValueError:
    sys.exit(1)
' "$1" 2>/dev/null || die "cannot parse size '$1' (use e.g. 1GiB, 500MiB, or bytes)"
}

# req METHOD PATH [JSON_BODY]  -> fills global REQ_BODY + HTTP_CODE
# Runs in the CALLER's shell (not via $(...)), so both globals survive the call.
req() {
  local method="$1" path="$2" body="${3:-}"
  local hdrs=(-s -w $'\n%{http_code}' -X "$method" -H "Authorization: Bearer $ADMIN_TOKEN")
  if [ -n "$body" ]; then
    hdrs+=(-H "Content-Type: application/json" -d "$body")
  fi
  local out
  if ! out=$(curl "${hdrs[@]}" "$ADMIN_BASE$path" 2>/dev/null); then
    REQ_BODY=""
    HTTP_CODE="000"
    return 1
  fi
  HTTP_CODE="${out##*$'\n'}"
  REQ_BODY="${out%$'\n'$HTTP_CODE}"
}

# req_ok: run req, die on connection failure or non-2xx, print the body
req_ok() {
  if ! req "$@"; then
    printf 'error: cannot reach admin API at %s (is the server running?)\n' "$ADMIN_BIND" >&2
    exit 1
  fi
  if [ "${HTTP_CODE:0:1}" != "2" ]; then
    printf 'api error (HTTP %s): %s\n' "$HTTP_CODE" "$REQ_BODY" >&2
    exit 1
  fi
  printf '%s' "$REQ_BODY"
}

usage() {
  cat <<'EOF'
tenant-fs-server admin CLI

USAGE
  ./scripts/admin-cli.sh [--token TOKEN] [--admin-bind HOST:PORT] <command> [args...]

GLOBAL FLAGS
  --token TOKEN        admin bearer token (default: TENANT_FS_ADMIN_TOKEN or .env)
  --admin-bind A:B     admin endpoint (default 127.0.0.1:8081)

COMMANDS
  apps                          list apps
  app create NAME [--quota S] [--max-file S]   create app (S = size, e.g. 1GiB)
  app get ID                     show one app (detail JSON)
  app set ID [--enabled 0|1] [--quota S] [--max-file S]   update app
  app disable ID                 soft-disable an app
  app enable ID                  re-enable an app
  app rotate-secret ID           rotate app secret (old secret dies immediately)
  app delete ID                  soft-delete an app
  app usage ID                   show usage / quota / file count
  users ID                       list pre-provisioned users of an app
  user add ID USER_ID            pre-provision a user for an app
  audit [--app-id N] [--since S] query the audit log (--since in seconds)
  backup run                     run a backup now
  backup list                    list backups (with on-disk path)
  backup detail ID               backup detail + manifest
  backup config [--schedule S] [--target D] [--retention N]   show / set backup config
  health                         GET /healthz on the public endpoint

SIZE FORMAT
  --quota / --max-file accept raw bytes or K/M/G/T with B/iB suffix: 104857600, 64MiB, 1GiB.
EOF
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_apps() {
  local body
  body=$(req_ok GET /apps)
  if command -v jq >/dev/null 2>&1; then
    # prettier table
    jq -r '([["ID","NAME","APP_KEY","ENABLED","USAGE","QUOTA","MAX_FILE"]] + [.apps[] | [.id, .name, .app_key, (.enabled|tostring), (.usage_bytes|tostring), (.quota_bytes|tostring), (.max_payload_bytes|tostring)]]) | .[] | @tsv' <<<"$body" | column -t -s $'\t'
  else
    printf '%s\n' "$body" | json_pretty
  fi
}

cmd_app_create() {
  local name="$1" quota="$DEFAULT_QUOTA" maxfile="$DEFAULT_MAXFILE"
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --quota) quota=$(bytes_of "$2"); shift 2;;
      --max-file) maxfile=$(bytes_of "$2"); shift 2;;
      *) die "unknown option for create: $1";;
    esac
  done
  local body
  body=$(req_ok POST /apps "{\"name\":\"$name\",\"quota_bytes\":$quota,\"max_payload_bytes\":$maxfile}")
  printf '%s\n' "$body" | json_pretty
  warn "app_secret is shown ONCE above — store it server-side now; it cannot be recovered later."
}

cmd_app_get() { req_ok GET "/apps/$1" | json_pretty; }

cmd_app_set() {
  local id="$1"; shift
  local fields=() enabled quota maxfile
  while [ $# -gt 0 ]; do
    case "$1" in
      --enabled) fields+=("\"enabled\":$2"); shift 2;;
      --quota) quota=$(bytes_of "$2"); fields+=("\"quota_bytes\":$quota"); shift 2;;
      --max-file) maxfile=$(bytes_of "$2"); fields+=("\"max_payload_bytes\":$maxfile"); shift 2;;
      *) die "unknown option for set: $1";;
    esac
  done
  [ ${#fields[@]} -eq 0 ] && die "app set requires at least one of --enabled / --quota / --max-file"
  local joined
  joined=$(printf '%s' "${fields[*]}")
  req_ok PATCH "/apps/$id" "{$joined}" >/dev/null
  echo "ok: app $id updated"
}

cmd_app_disable() { req_ok PATCH "/apps/$1" '{"enabled":0}' >/dev/null && echo "ok: app $1 disabled"; }
cmd_app_enable()  { req_ok PATCH "/apps/$1" '{"enabled":1}' >/dev/null && echo "ok: app $1 enabled"; }

cmd_app_rotate() {
  local body
  body=$(req_ok POST "/apps/$1/secret/rotate")
  printf '%s\n' "$body" | json_pretty
  warn "app_secret is shown ONCE above; the previous secret was invalidated immediately."
}

cmd_app_delete() { req_ok DELETE "/apps/$1" >/dev/null && echo "ok: app $1 deleted (soft-delete; disabled immediately)"; }

cmd_app_usage() {
  req_ok GET "/apps/$1/usage" | json_pretty
}

cmd_users() {
  local body
  body=$(req_ok GET "/apps/$1/users")
  if command -v jq >/dev/null 2>&1; then
    jq -r '([["USER_ID","CREATED_AT"]] + [.users[] | [.user_id, (.created_at|tostring)]]) | .[] | @tsv' <<<"$body" | column -t -s $'\t'
  else
    printf '%s\n' "$body" | json_pretty
  fi
}

cmd_user_add() {
  req_ok POST "/apps/$1/users" "{\"user_id\":\"$2\"}" | json_pretty
}

cmd_audit() {
  local q="app_id=&since="
  while [ $# -gt 0 ]; do
    case "$1" in
      --app-id) q="app_id=$2"; shift 2;;
      --since) q="${q%%&*}since=$2"; shift 2;;
      *) die "unknown audit option: $1";;
    esac
  done
  local body
  body=$(req_ok GET "/audit?$q")
  if command -v jq >/dev/null 2>&1; then
    jq -r '([["TIME","ACTOR","ACTION","APP","TARGET","IP","DECISION"]] + [.entries[] | [.at, .actor, .action, (.app_id|tostring), .target, .ip, .decision]]) | .[] | @tsv' <<<"$body" | column -t -s $'\t'
  else
    printf '%s\n' "$body" | json_pretty
  fi
}

cmd_backup_run() {
  req_ok POST /backups/run | json_pretty
}

cmd_backup_list() {
  local body
  body=$(req_ok GET /backups)
  if command -v jq >/dev/null 2>&1; then
    jq -r '([["ID","STATUS","SIZE","FINISHED_AT","PATH"]] + [.backups[] | [.id, .status, (.size|tostring), (.finished_at|tostring), (.path // "-")]]) | .[] | @tsv' <<<"$body" | column -t -s $'\t'
  else
    printf '%s\n' "$body" | json_pretty
  fi
}

cmd_backup_detail() { req_ok GET "/backups/$1" | json_pretty; }

cmd_backup_config() {
  # The API only exposes PATCH for backup config (no GET); require an option.
  [ $# -gt 0 ] || die "backup config requires --schedule / --target / --retention"
  local fields=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --schedule) fields+=("\"schedule\":$2"); shift 2;;
      --target) fields+=("\"target\":\"$2\""); shift 2;;
      --retention) fields+=("\"retention\":$2"); shift 2;;
      *) die "unknown backup config option: $1";;
    esac
  done
  local body
  body=$(printf '{%s}' "$(printf '%s' "${fields[*]}")")
  req_ok PATCH /backups/config "$body" | json_pretty
}

cmd_health() {
  curl -s -w '\nHTTP %{http_code}\n' "http://$PUBLIC_BIND/healthz" 2>/dev/null \
    || die "cannot reach public endpoint at $PUBLIC_BIND"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DEFAULT_QUOTA=10737418240
DEFAULT_MAXFILE=104857600

while [ $# -gt 0 ]; do
  case "$1" in
    --token) [ $# -ge 2 ] || die "--token needs a value"; ADMIN_TOKEN="$2"; shift 2;;
    --admin-bind) [ $# -ge 2 ] || die "--admin-bind needs a value"; ADMIN_BIND="$2"; shift 2;;
    -h|--help|help) usage; exit 0;;
    --) shift; break;;
    -*) die "unknown flag: $1";;
    *) break;;
  esac
done

[ $# -lt 1 ] && { usage >&2; exit 1; }
[ -z "$ADMIN_TOKEN" ] && die "no admin token: set TENANT_FS_ADMIN_TOKEN, provide --token, or run from the project dir with .env present"

cmd="$1"; shift

case "$cmd" in
  apps)                 cmd_apps "$@";;
  app)
    [ $# -ge 1 ] || die "app requires a subcommand (create|get|set|disable|enable|rotate-secret|delete|usage)"
    sub="$1"; shift
    case "$sub" in
      create)          [ $# -ge 1 ] || die "app create requires a name"; cmd_app_create "$@";;
      get)             [ $# -ge 1 ] || die "app get requires an id"; cmd_app_get "$1";;
      set)             [ $# -ge 2 ] || die "app set requires an id and options"; cmd_app_set "$@";;
      disable)         [ $# -ge 1 ] || die "app disable requires an id"; cmd_app_disable "$1";;
      enable)          [ $# -ge 1 ] || die "app enable requires an id"; cmd_app_enable "$1";;
      rotate-secret)   [ $# -ge 1 ] || die "app rotate-secret requires an id"; cmd_app_rotate "$1";;
      delete)          [ $# -ge 1 ] || die "app delete requires an id"; cmd_app_delete "$1";;
      usage)           [ $# -ge 1 ] || die "app usage requires an id"; cmd_app_usage "$1";;
      *) die "unknown app subcommand: $sub";;
    esac
    ;;
  users)    [ $# -ge 1 ] || die "users requires an app id"; cmd_users "$1";;
  user)
    [ $# -ge 2 ] || die "user add requires an app id and a user_id"
    [ "$1" = "add" ] || die "only 'user add' is supported"
    cmd_user_add "$2" "$3"
    ;;
  audit)    cmd_audit "$@";;
  backup)
    [ $# -ge 1 ] || die "backup requires a subcommand (run|list|detail|config)"
    sub="$1"; shift
    case "$sub" in
      run)    cmd_backup_run;;
      list)   cmd_backup_list;;
      detail) [ $# -ge 1 ] || die "backup detail requires an id"; cmd_backup_detail "$1";;
      config) cmd_backup_config "$@";;
      *) die "unknown backup subcommand: $sub";;
    esac
    ;;
  health)   cmd_health;;
  *) die "unknown command: $cmd (try --help)";;
esac
