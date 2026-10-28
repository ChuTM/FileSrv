#!/usr/bin/env bash
#
# filesrv — restore from a `backup.sh` snapshot.
#
# Restores the whole data tree (fs.db + blobs/) and, by default, the .env file
# (because .env carries SERVER_SECRET, which MUST match the backup, and all the
# binds/settings). Restore = stop server -> copy back -> start with the SAME
# secret. This script automates the copy + verification and protects the current
# state with a safety snapshot before touching anything.
#
# Usage:
#   ./restore.sh <backup-dir> [options]
#
# Options:
#   --data <dir>        data directory to restore INTO (default: ./data)
#   --env <file>        .env file to restore (default: <backup>/.env if present,
#                       else the project .env is left untouched)
#   --env-file <file>   restore .env from this explicit file (overrides <backup>/.env)
#   --no-env            do NOT restore any .env (use it when you already have the
#                       right credentials; then you MUST start with the same secret)
#   --stop              stop the running server before restoring
#   --no-backup         skip the safety snapshot of the current state
#   --dry-run           preview only; change nothing
#   -y, --yes           skip the interactive confirmation
#   -h, --help          show this help
#
# Examples:
#   ./restore.sh /backup/filesrv --stop
#   ./restore.sh /backup/filesrv --data /srv/fs/data --env-file ~/secrets/fs.env --stop

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$PROJECT_ROOT/data"
BACKUP=""
ENV_MODE="auto"   # auto | file | skip
ENV_FILE_ARG=""
STOP=0
BACKUP_SAFE=1
DRY=0
YES=0

usage() {
  cat <<'EOF'
Usage:
  ./restore.sh <backup-dir> [options]

Options:
  --data <dir>        data directory to restore INTO (default: ./data)
  --env <file>        restore .env from this explicit file
  --no-env            do NOT restore any .env
  --stop              stop the running server before restoring
  --no-backup         skip the safety snapshot of the current state
  --dry-run           preview only; change nothing
  -y, --yes           skip the interactive confirmation
  -h, --help          show this help

Examples:
  ./restore.sh /backup/filesrv --stop
  ./restore.sh /backup/filesrv --data /srv/fs/data --env ~/secrets/fs.env --stop
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data)       [[ $# -ge 2 ]] || { echo "error: --data requires a value" >&2; usage; }; DATA_DIR="$2"; shift 2 ;;
    --env)        [[ $# -ge 2 ]] || { echo "error: --env requires a value" >&2; usage; }; ENV_FILE_ARG="$2"; ENV_MODE="file"; shift 2 ;;
    --no-env)     ENV_MODE="skip"; shift ;;
    --stop)       STOP=1; shift ;;
    --no-backup)  BACKUP_SAFE=0; shift ;;
    --dry-run)    DRY=1; shift ;;
    -y|--yes)     YES=1; shift ;;
    -h|--help)    usage ;;
    -*)           echo "error: unknown option: $1" >&2; usage ;;
    *)
      if [[ -z "$BACKUP" ]]; then BACKUP="$1"; else echo "error: unexpected extra argument: $1" >&2; usage; fi
      shift ;;
  esac
done

[[ -n "$BACKUP" ]] || { echo "error: missing backup directory" >&2; usage; }
BACKUP="$(cd "$BACKUP" 2>/dev/null && pwd)" || { echo "error: backup dir does not exist: $BACKUP" >&2; exit 1; }

# ---- validate the snapshot ----
[[ -f "$BACKUP/fs.db" ]] || { echo "error: not a backup.sh snapshot (missing fs.db) in $BACKUP" >&2; exit 1; }

mkdir -p "$DATA_DIR"
DATA_DIR="$(cd "$DATA_DIR" && pwd)"
PROJECT_ENV="$PROJECT_ROOT/.env"

echo "==> restore source: $BACKUP"
echo "==> restore target: $DATA_DIR"
echo "==> env mode: $ENV_MODE"

# ---- determine the .env source ----
ENV_SRC=""
if [[ "$ENV_MODE" == "file" ]]; then
  ENV_SRC="$(cd "$(dirname "$ENV_FILE_ARG")" 2>/dev/null && pwd)/$(basename "$ENV_FILE_ARG")"
  [[ -f "$ENV_SRC" ]] || { echo "error: --env file not found: $ENV_SRC" >&2; exit 1; }
elif [[ "$ENV_MODE" == "auto" && -f "$BACKUP/.env" ]]; then
  ENV_SRC="$BACKUP/.env"
fi

# ---- confirm unless -y ----
if [[ "$DRY" != "1" && "$YES" != "1" ]]; then
  echo ""
  echo "This will OVERWRITE $DATA_DIR (and .env). Current state is snapshotted"
  echo "unless --no-backup. Proceed? [y/N]"
  read -r ans || { echo "aborted" >&2; exit 1; }
  [[ "$ans" =~ ^[yY] ]] || { echo "aborted." >&2; exit 1; }
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

# ---- safety snapshot of the current state ----
if [[ "$BACKUP_SAFE" == "1" && "$DRY" != "1" ]]; then
  TS="$(date +%Y%m%d-%H%M%S)"
  if [[ -f "$DATA_DIR/fs.db" ]]; then
    cp "$DATA_DIR/fs.db" "$DATA_DIR/.pre-restore-$TS.fs.db"
    echo "==> safety snapshot: $DATA_DIR/.pre-restore-$TS.fs.db"
  fi
  if [[ -f "$PROJECT_ENV" ]]; then
    cp "$PROJECT_ENV" "$PROJECT_ENV.pre-restore-$TS"
    echo "==> safety snapshot: $PROJECT_ENV.pre-restore-$TS"
  fi
fi

# ---- restore the data tree (fs.db + blobs), excluding manifest/.env ----
if [[ "$DRY" != "1" ]]; then
  echo "==> restoring data tree from $BACKUP ..."
  rsync -a --exclude 'backup-manifest.txt' --exclude '.env' "$BACKUP/" "$DATA_DIR/"
else
  echo "==> (dry) would rsync $BACKUP/ -> $DATA_DIR/ (excluding manifest/.env)"
fi

# ---- restore .env ----
if [[ "$DRY" != "1" ]]; then
  if [[ -n "$ENV_SRC" ]]; then
    cp "$ENV_SRC" "$PROJECT_ENV"
    chmod 600 "$PROJECT_ENV"
    echo "==> .env restored from $ENV_SRC -> $PROJECT_ENV (mode 600)"
  else
    if [[ "$ENV_MODE" == "skip" ]]; then
      echo "==> .env not restored (--no-env). You MUST start with the matching SERVER_SECRET."
    else
      echo "==> no .env in the backup and no --env given; leaving current .env."
      echo "    IMPORTANT: this only works if the current .env has the SAME SERVER_SECRET"
      echo "    that produced the backup, otherwise blobs will not decrypt."
    fi
  fi
else
  if [[ -n "$ENV_SRC" ]]; then
    echo "==> (dry) would restore .env from $ENV_SRC -> $PROJECT_ENV"
  else
    echo "==> (dry) .env mode: $ENV_MODE (nothing restored)"
  fi
fi

# ---- verify the restored DB ----
if [[ "$DRY" != "1" ]] && command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DATA_DIR/fs.db" ]]; then
  if sqlite3 "$DATA_DIR/fs.db" "PRAGMA integrity_check;" 2>/dev/null | grep -q '^ok$'; then
    echo "==> restored DB integrity check passed (ok)"
  else
    echo "!! restored DB failed integrity check — restore is NOT usable." >&2
    echo "   Your previous state is in the pre-restore snapshot." >&2
    exit 1
  fi
fi

# ---- done ----
if [[ "$DRY" != "1" ]]; then
  echo ""
  echo "==> restore complete. Start the server:"
  echo "    nohup $SCRIPT_DIR/start.sh > /tmp/tenant-fs.log 2>&1 &"
  echo "    sleep 3; curl -s http://127.0.0.1:8080/healthz   # -> OK"
else
  echo "==> dry-run complete. Run without --dry-run to apply."
fi
