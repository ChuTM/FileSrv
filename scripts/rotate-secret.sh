#!/usr/bin/env bash
#
# filesrv — rotate SERVER_SECRET in place.
#
# SERVER_SECRET is the KEK (SHA-256(secret)) that seals each blob's per-file
# DEK. Envelope encryption lets us rotate it cheaply: the `rekey` tool re-seals
# every DEK from the OLD secret to the NEW one while leaving the file payloads
# untouched — no re-upload, no re-encryption of the bodies.
#
# Safety contract:
#   * The server MUST be stopped while blobs are re-keyed (it writes new blobs
#     and holds the DB). Pass --stop to stop it here, or stop it yourself.
#   * A safety snapshot (fs.db + .env) is taken before anything is changed.
#   * .env is only updated AFTER re-keying finishes, so a mid-run failure leaves
#     the old secret in place and is retryable.
#
# Usage:
#   ./rotate-secret.sh [options]
#
# Options:
#   --old <secret>     current SERVER_SECRET (default: read from .env)
#   --new <secret>     new secret (default: auto-generated with openssl)
#   --blobs <dir>      blob root (default: from .env TENANT_FS_BLOBS, else ./data/blobs)
#   --data <dir>       data dir for the safety snapshot (default: ./data)
#   --env <file>       .env file to update (default: the one next to this script)
#   --stop             stop the running server before re-keying
#   --no-backup        skip the safety snapshot
#   --dry-run          only preview; change nothing
#   -h, --help         show this help
#
# Examples:
#   ./rotate-secret.sh --stop                 # rotate to a new random secret
#   ./rotate-secret.sh --old <s> --new <s> --stop --dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE=""
OLD=""
NEW=""
BLOBS=""
DATA_DIR=""
STOP=0
BACKUP=1
DRY=0
YES=0

usage() {
  cat <<'EOF'
Usage:
  ./rotate-secret.sh [options]

Options:
  --old <secret>     current SERVER_SECRET (default: read from .env)
  --new <secret>     new secret (default: auto-generated with openssl)
  --blobs <dir>      blob root (default: from .env TENANT_FS_BLOBS, else ./data/blobs)
  --data <dir>       data dir for the safety snapshot (default: ./data)
  --env <file>       .env file to update (default: the one next to this script)
  --stop             stop the running server before re-keying
  --no-backup        skip the safety snapshot (default: snapshot is taken)
  --yes              skip the interactive double confirmation
  --dry-run          only preview; change nothing
  -h, --help         show this help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --old)      [[ $# -ge 2 ]] || { echo "error: --old requires a value" >&2; usage; }; OLD="$2"; shift 2 ;;
    --new)      [[ $# -ge 2 ]] || { echo "error: --new requires a value" >&2; usage; }; NEW="$2"; shift 2 ;;
    --blobs)    [[ $# -ge 2 ]] || { echo "error: --blobs requires a value" >&2; usage; }; BLOBS="$2"; shift 2 ;;
    --data)     [[ $# -ge 2 ]] || { echo "error: --data requires a value" >&2; usage; }; DATA_DIR="$2"; shift 2 ;;
    --env)      [[ $# -ge 2 ]] || { echo "error: --env requires a value" >&2; usage; }; ENV_FILE="$2"; shift 2 ;;
    --stop)     STOP=1; shift ;;
    --no-backup) BACKUP=0; shift ;;
    --yes)      YES=1; shift ;;
    --dry-run)  DRY=1; shift ;;
    -h|--help)  usage ;;
    -*)         echo "error: unknown option: $1" >&2; usage ;;
    *)          echo "error: unexpected argument: $1" >&2; usage ;;
  esac
done

ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/.env}"
[[ -f "$ENV_FILE" ]] || { echo "error: .env not found at $ENV_FILE" >&2; exit 1; }

# ---- old secret ----
if [[ -z "$OLD" ]]; then
  OLD="$(sed -n 's/^TENANT_FS_SERVER_SECRET=//p' "$ENV_FILE" | head -1)"
  [[ -n "$OLD" ]] || { echo "error: TENANT_FS_SERVER_SECRET not in .env (pass --old)" >&2; exit 1; }
fi

# ---- new secret ----
if [[ -z "$NEW" ]]; then
  NEW="$(openssl rand -base64 32 | tr -d '\n')"
  echo "==> generated new SERVER_SECRET (base64, 32 bytes)"
fi
[[ -n "$NEW" ]] || { echo "error: could not generate a new secret" >&2; exit 1; }

# ---- resolve data/blobs ----
DATA_DIR="${DATA_DIR:-$PROJECT_ROOT/data}"
if [[ -z "$BLOBS" ]]; then
  BLOBS="$(sed -n 's/^TENANT_FS_BLOBS=//p' "$ENV_FILE" | head -1)"
  [[ -n "$BLOBS" ]] || BLOBS="data/blobs"
  [[ "$BLOBS" = /* ]] || BLOBS="$PROJECT_ROOT/$BLOBS"
fi
[[ -d "$BLOBS" ]] || { echo "error: blobs dir does not exist: $BLOBS" >&2; exit 1; }

echo "==> old secret length: ${#OLD}"
echo "==> new secret length: ${#NEW}"
echo "==> blobs: $BLOBS"
echo "==> data (safety snapshot): $DATA_DIR"
echo "==> .env to update: $ENV_FILE"
if [[ "$DRY" == "1" ]]; then echo "==> DRY RUN — nothing will be written"; fi

# ---- risk disclosure + double confirmation ----
if [[ "$DRY" != "1" && "$YES" != "1" ]]; then
  echo ""
  echo "!! RISK — rotating SERVER_SECRET:"
  echo "   * Every blob's DEK is re-sealed from the OLD secret to the NEW one,"
  echo "     in place. The .env is only updated AFTER re-keying succeeds, so a"
  echo "     mid-run failure leaves the old secret active and is retryable."
  echo "   * Blobs you cannot unwrap with the OLD secret (older/mismatched key)"
  echo "     are skipped (reported as 'unwrappable') and stay unreadable."
  echo "   * A safety snapshot of fs.db + .env is taken before any change."
  echo ""
  echo "NEW SERVER_SECRET that will be written to .env:"
  echo "    $NEW"
  read -r -p "Type 'yes' to confirm you understand the risk: " ans1
  [[ "$ans1" == "yes" ]] || { echo "aborted."; exit 1; }
  read -r -p "Confirm again (irreversible once the server starts): type 'yes': " ans2
  [[ "$ans2" == "yes" ]] || { echo "aborted."; exit 1; }
fi

# ---- ensure the server is stopped ----
if pgrep -f 'target/release/filesrv' >/dev/null 2>&1; then
  if [[ "$STOP" == "1" ]]; then
    if [[ "$DRY" != "1" ]]; then
      echo "==> stopping server..."
      pkill -9 -f 'target/release/filesrv' 2>/dev/null || true
      sleep 3
      pgrep -f 'target/release/filesrv' >/dev/null 2>&1 && { echo "!! server still running; aborting." >&2; exit 1; }
      echo "==> server stopped"
    else
      echo "==> (dry) would stop the running server"
    fi
  else
    echo "!! the server is running. Stop it first (or pass --stop):" >&2
    echo "    pkill -9 -f 'target/release/filesrv'; sleep 3" >&2
    exit 1
  fi
fi

# ---- safety snapshot ----
if [[ "$BACKUP" == "1" && "$DRY" != "1" ]]; then
  TS="$(date +%Y%m%d-%H%M%S)"
  if [[ -f "$DATA_DIR/fs.db" ]]; then
    cp "$DATA_DIR/fs.db" "$DATA_DIR/.pre-rotate-$TS.fs.db"
    echo "==> safety snapshot: $DATA_DIR/.pre-rotate-$TS.fs.db"
  fi
  cp "$ENV_FILE" "$ENV_FILE.pre-rotate-$TS"
  echo "==> safety snapshot: $ENV_FILE.pre-rotate-$TS"
fi

# ---- locate the rekey binary ----
REKEY="$PROJECT_ROOT/target/release/rekey"
[[ -x "$REKEY" ]] || { echo "error: rekey binary not found at $REKEY (run: cargo build --release)" >&2; exit 1; }

# ---- run the re-key ----
if [[ "$DRY" == "1" ]]; then
  "$REKEY" --blobs "$BLOBS" --old "$OLD" --new "$NEW" --dry-run
else
  "$REKEY" --blobs "$BLOBS" --old "$OLD" --new "$NEW"
fi

if [[ "$DRY" == "1" ]]; then
  echo "==> dry-run complete. Run without --dry-run to apply."
  exit 0
fi

# ---- update .env (only after re-key succeeded) ----
echo "==> updating $ENV_FILE with the new SERVER_SECRET"
sed -i.bak "s|^TENANT_FS_SERVER_SECRET=.*|TENANT_FS_SERVER_SECRET=$NEW|" "$ENV_FILE"
rm -f "$ENV_FILE.bak"
chmod 600 "$ENV_FILE"

echo ""
echo "==> SERVER_SECRET rotated. Summary:"
echo "    old: ${#OLD} bytes, new: ${#NEW} bytes"
echo "    blobs re-keyed under: $BLOBS"
echo "    .env updated: $ENV_FILE"
echo "    NEW SERVER_SECRET: $NEW"
if pgrep -f 'target/release/filesrv' >/dev/null 2>&1; then
  echo "    note: server is running — re-keyed blobs are now served with the NEW secret"
else
  echo "    NEXT STEP — server is stopped. Start it now:"
  echo "      nohup $SCRIPT_DIR/start.sh > /tmp/filesrv.log 2>&1 &"
  echo "      sleep 3; curl -s http://127.0.0.1:8080/healthz   # -> OK"
  echo "    then smoke-test one real download (decrypt path)."
fi
echo ""
echo "    IMPORTANT: keep the OLD secret safe (it is in any --pre-rotate snapshot)."
echo "    To roll back: restore .env.pre-rotate-<ts>, then re-run rotate with"
echo "    --old <new> --new <old>."
