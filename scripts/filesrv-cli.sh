#!/usr/bin/env bash
#
# filesrv-cli — shell front-end for the filesrv.
#
# Two command families:
#   filesrv admin <cmd>   operator actions against the loopback admin API
#                         (apps lifecycle, users, audit, backups) — needs the
#                         admin bearer token from .env / TENANT_FS_ADMIN_TOKEN.
#   filesrv health        non-sensitive: GET /healthz on the public endpoint.
#   filesrv version       non-sensitive: print server package version.
#
# Usage:
#   sh scripts/filesrv-cli.sh [--token TOKEN] [--admin-bind HOST:PORT] <command> [args...]
#
# Requires: curl + (jq or python3) for pretty-printing.
#
# Examples:
#   sh scripts/filesrv-cli.sh admin apps
#   sh scripts/filesrv-cli.sh admin app create my-app --quota 1GiB --max-file 64MiB
#   sh scripts/filesrv-cli.sh admin app rotate-secret 1
#   sh scripts/filesrv-cli.sh admin user add 1 alice@example.com
#   sh scripts/filesrv-cli.sh admin audit --app-id 1 --since 86400
#   sh scripts/filesrv-cli.sh admin backup run
#   sh scripts/filesrv-cli.sh admin backup list
#   sh scripts/filesrv-cli.sh health
#   sh scripts/filesrv-cli.sh version

# This script uses bash features, so reject non-bash `sh` (e.g. dash on Linux).
if [ -z "${BASH_VERSION:-}" ]; then
  printf 'error: filesrv-cli must run under bash. Use: bash %s\n' "$0" >&2
  exit 1
fi

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
filesrv-cli — shell front-end for filesrv

USAGE
  sh scripts/filesrv-cli.sh [--token TOKEN] [--admin-bind HOST:PORT] <command> [args...]

GLOBAL FLAGS
  --token TOKEN        admin bearer token (default: TENANT_FS_ADMIN_TOKEN or .env)
  --admin-bind A:B     admin endpoint (default 127.0.0.1:8081)

COMMANDS — admin namespace (operator; requires the admin token)
  admin apps                            list apps
  admin app create NAME [--quota S] [--max-file S]   create app (S = size, e.g. 1GiB)
  admin app get ID                       show one app (detail JSON)
  admin app set ID [--enabled 0|1] [--quota S] [--max-file S]   update app
  admin app disable ID                   soft-disable an app
  admin app enable ID                    re-enable an app
  admin app rotate-secret ID             rotate app secret (old secret dies immediately)
  admin app delete ID                    soft-delete an app (compat; prefer archive)
  admin app archive ID                   archive an app (disable + move to Archive)
  admin app unarchive ID                 unarchive an app (re-enable + move to Apps)
  admin app wipe ID                      wipe out an app PERMANENTLY (record + all
                                         files/tokens/users/groups + on-disk blobs)
  admin app usage ID                     show usage / quota / file count
  admin users ID                         list pre-provisioned users of an app
  admin user add ID USER_ID              pre-provision a user for an app
  admin group list ID                    list user groups of an app
  admin group create ID NAME             create a group (empty membership)
  admin group delete ID NAME             delete a group
  admin group members ID NAME            show a group and its members
  admin group member add ID NAME USER    add a user to a group
  admin group member remove ID NAME USER remove a user from a group
  admin storage info                     storage/backup dashboard (settings)
  admin storage recompute                recompute every app's usage_bytes from live files
  admin storage audit                    integrity-audit blobs on disk (exists/size/SHA)
  admin audit [--app-id N] [--since S]   query the audit log (--since in seconds)
  admin backup run                       run a backup now
  admin backup list                      list backups (with on-disk path)
  admin backup detail ID                 backup detail + manifest
  admin backup config [--schedule S] [--target D] [--retention N]   set backup config
  admin rotate [--new SECRET] [--stop] [--dry-run] [--yes]
                                     rotate SERVER_SECRET in place (LOCAL,
                                     high-risk: double-confirm, auto-backup,
                                     re-key blobs, update .env, print new secret)

COMMANDS — non-sensitive (no admin token required)
  health                                 GET /healthz on the public endpoint
  version                                print the server package version
  help                                   show this help

SIZE FORMAT
  --quota / --max-file accept raw bytes or K/M/G/T with B/iB suffix: 104857600, 64MiB, 1GiB.
EOF
}

# ---------------------------------------------------------------------------
# Commands — admin namespace
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

cmd_app_archive()   { req_ok POST "/apps/$1/archive" >/dev/null && echo "ok: app $1 archived (disabled; moved to Archive)"; }
cmd_app_unarchive() { req_ok POST "/apps/$1/unarchive" >/dev/null && echo "ok: app $1 unarchived (re-enabled; moved to Apps)"; }
cmd_app_wipe()      { req_ok POST "/apps/$1/wipe" >/dev/null && echo "ok: app $1 wiped (PERMANENT — app record, files, tokens, users, groups and on-disk blobs removed)"; }

cmd_storage_info()      { req_ok GET "/storage/info" | json_pretty; }
cmd_storage_recompute() { req_ok POST "/storage/recompute" | json_pretty; }
cmd_storage_audit()     { req_ok POST "/storage/audit" | json_pretty; }

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

# URL-encode a path segment (group names / user_ids live in URLs).
urlenc() {
  python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1" 2>/dev/null \
    || die "cannot encode '$1'"
}

cmd_group_list() {
  local body
  body=$(req_ok GET "/apps/$1/groups")
  if command -v jq >/dev/null 2>&1; then
    jq -r '([["GROUP","MEMBERS"]] + [.groups[] | [.name, (.members|join(","))]]) | .[] | @tsv' <<<"$body" | column -t -s $'\t'
  else
    printf '%s\n' "$body" | json_pretty
  fi
}

cmd_group_create() {
  req_ok POST "/apps/$1/groups" "{\"name\":\"$2\"}" | json_pretty
}

cmd_group_delete() {
  local name
  name=$(urlenc "$2")
  req_ok DELETE "/apps/$1/groups/$name" >/dev/null && echo "ok: group $2 deleted"
}

cmd_group_members() {
  local name
  name=$(urlenc "$2")
  req_ok GET "/apps/$1/groups/$name" | json_pretty
}

cmd_group_member_add() {
  local name
  name=$(urlenc "$2")
  req_ok POST "/apps/$1/groups/$name/members" "{\"user_id\":\"$3\"}" | json_pretty
}

cmd_group_member_remove() {
  local name
  name=$(urlenc "$2")
  req_ok DELETE "/apps/$1/groups/$name/members/$3" | json_pretty
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

# ---------------------------------------------------------------------------
# Commands — non-sensitive (no admin token required)
# ---------------------------------------------------------------------------

# Offer to add a `filesrv` shell alias so operators can run `filesrv admin …`
# instead of `./scripts/filesrv-cli.sh …`. Checked on EVERY run: as long as no
# `filesrv` alias is configured, an interactive terminal is prompted (Y/n).
maybe_setup_alias() {
  # Already available (installed command, function, or alias in this shell)?
  if command -v filesrv >/dev/null 2>&1; then
    return
  fi

  # Pick the rc file for the current login shell.
  local rc
  case "${SHELL##*/}" in
    zsh)   rc="${ZDOTDIR:-$HOME}/.zshrc";;
    bash)  rc="$HOME/.bashrc";;
    *)     rc="$HOME/.bashrc";;
  esac

  # Already set up in the rc file? Then never prompt again.
  if [ -f "$rc" ] && grep -qE '^[[:space:]]*alias filesrv=' "$rc" 2>/dev/null; then
    return
  fi

  # Only prompt on a real terminal (skip pipes, CI, scripts).
  [ -t 0 ] || return

  printf 'The "filesrv" alias is not configured.\n'
  printf 'Set it up so you can run "filesrv admin …" / "filesrv health"? [Y/n] '
  local ans
  read -r ans || return
  case "$ans" in
    ""|y|Y|yes|YES)
      mkdir -p "$(dirname "$rc")"
      {
        printf '\n# added by filesrv-cli (filesrv)\n'
        printf "alias filesrv='sh %s'\n" "$SCRIPT_DIR/filesrv-cli.sh"
      } >> "$rc"
      printf 'You now can use \033[33mfilesrv\033[0m command to use Filesrv CLI.\n'
      printf 'Restart your shell, or run: source %s\n' "$rc"
      ;;
    *)
      printf 'Skipped; you can add it later with: alias filesrv="sh %s"\n' "$SCRIPT_DIR/filesrv-cli.sh" >&2
      ;;
  esac
}

cmd_health() {
  curl -s -w '\nHTTP %{http_code}\n' "http://$PUBLIC_BIND/healthz" 2>/dev/null \
    || die "cannot reach public endpoint at $PUBLIC_BIND"
}

cmd_version() {
  local ver
  # Cargo.toml lives one level above the scripts/ dir, regardless of cwd.
  ver=$(grep -m1 '^version' "$SCRIPT_DIR/../Cargo.toml" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')
  echo "filesrv · filesrv-cli"
  echo "server package version: ${ver:-unknown}"
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

if [ $# -lt 1 ]; then
  # No command given: still offer the filesrv alias, then show usage.
  maybe_setup_alias
  usage >&2
  exit 1
fi

cmd="$1"; shift

case "$cmd" in
  admin)
    # Admin namespace: requires the admin token.
    [ -z "$ADMIN_TOKEN" ] && die "no admin token: set TENANT_FS_ADMIN_TOKEN, provide --token, or run from the project dir with .env present"
    [ $# -ge 1 ] || die "admin requires a subcommand (apps|app|users|user|audit|backup)"
    sub="$1"; shift
    case "$sub" in
      apps)                 cmd_apps "$@";;
      app)
        [ $# -ge 1 ] || die "app requires a subcommand (create|get|set|disable|enable|rotate-secret|delete|usage)"
        s2="$1"; shift
        case "$s2" in
          create)          [ $# -ge 1 ] || die "app create requires a name"; cmd_app_create "$@";;
          get)             [ $# -ge 1 ] || die "app get requires an id"; cmd_app_get "$1";;
          set)             [ $# -ge 2 ] || die "app set requires an id and options"; cmd_app_set "$@";;
          disable)         [ $# -ge 1 ] || die "app disable requires an id"; cmd_app_disable "$1";;
          enable)          [ $# -ge 1 ] || die "app enable requires an id"; cmd_app_enable "$1";;
          rotate-secret)   [ $# -ge 1 ] || die "app rotate-secret requires an id"; cmd_app_rotate "$1";;
          delete)          [ $# -ge 1 ] || die "app delete requires an id"; cmd_app_delete "$1";;
          archive)         [ $# -ge 1 ] || die "app archive requires an id"; cmd_app_archive "$1";;
          unarchive)       [ $# -ge 1 ] || die "app unarchive requires an id"; cmd_app_unarchive "$1";;
          wipe)            [ $# -ge 1 ] || die "app wipe requires an id"; cmd_app_wipe "$1";;
          usage)           [ $# -ge 1 ] || die "app usage requires an id"; cmd_app_usage "$1";;
          *) die "unknown app subcommand: $s2";;
        esac
        ;;
      users)    [ $# -ge 1 ] || die "users requires an app id"; cmd_users "$1";;
      user)
        [ $# -ge 2 ] || die "user add requires an app id and a user_id"
        [ "$1" = "add" ] || die "only 'user add' is supported"
        cmd_user_add "$2" "$3"
        ;;
      group)
        [ $# -ge 1 ] || die "group requires a subcommand (list|create|delete|members|member)"
        gsub="$1"; shift
        case "$gsub" in
          list)    [ $# -ge 1 ] || die "group list requires an app id"; cmd_group_list "$1";;
          create)  [ $# -ge 2 ] || die "group create requires an app id and a name"; cmd_group_create "$1" "$2";;
          delete)  [ $# -ge 2 ] || die "group delete requires an app id and a name"; cmd_group_delete "$1" "$2";;
          members) [ $# -ge 2 ] || die "group members requires an app id and a name"; cmd_group_members "$1" "$2";;
          member)
            [ $# -ge 4 ] || die "group member requires add|remove <app_id> <name> <user_id>"
            gop="$1"; gid="$2"; gname="$3"; guid="$4"
            case "$gop" in
              add)    cmd_group_member_add "$gid" "$gname" "$guid";;
              remove) cmd_group_member_remove "$gid" "$gname" "$guid";;
              *) die "unknown group member op: $gop";;
            esac
            ;;
          *) die "unknown group subcommand: $gsub";;
        esac
        ;;
      audit)    cmd_audit "$@";;
      backup)
        [ $# -ge 1 ] || die "backup requires a subcommand (run|list|detail|config)"
        s2="$1"; shift
        case "$s2" in
          run)    cmd_backup_run;;
          list)   cmd_backup_list;;
          detail) [ $# -ge 1 ] || die "backup detail requires an id"; cmd_backup_detail "$1";;
          config) cmd_backup_config "$@";;
          *) die "unknown backup subcommand: $s2";;
        esac
        ;;
      rotate)
        # Local, high-risk op: delegate to rotate-secret.sh (double-confirm,
        # auto-backup, re-key blobs in place, update .env, print new secret).
        [ -x "$SCRIPT_DIR/rotate-secret.sh" ] || die "rotate-secret.sh not found (expected at $SCRIPT_DIR/rotate-secret.sh)"
        exec "$SCRIPT_DIR/rotate-secret.sh" "$@"
        ;;
      storage)
        [ $# -ge 1 ] || die "storage requires a subcommand (info|recompute|audit)"
        case "$1" in
          info)      shift; cmd_storage_info "$@";;
          recompute) shift; cmd_storage_recompute "$@";;
          audit)     shift; cmd_storage_audit "$@";;
          *) die "unknown storage subcommand: $1";;
        esac
        ;;
      *) die "unknown admin command: $sub (try --help)";;
    esac
    ;;
  health)  cmd_health;;
  version) cmd_version;;
  *) die "unknown command: $cmd (try --help)";;
esac

# Command finished — offer the `filesrv` alias on the way out.
maybe_setup_alias
