#!/usr/bin/env bash
#
# filesrv — whole-data-directory snapshot backup (the simplest option)
#
# Synchronizes the entire data/ tree (SQLite DB + all sharded blob files) to a
# given destination. Restore = stop the server -> put the backup back into
# data/ -> start with the SAME SERVER_SECRET. See Documents/Ops-and-Backup.md
# section 5.5.
#
# Usage:
#   ./backup.sh <destination> [--data <data-dir>] [--secret-out <key-file>] [--no-verify]
#
# Examples:
#   ./backup.sh /Volumes/Backup/tenant-fs --data ./data --secret-out ~/.secrets/tenant-fs.server_secret
#   ./backup.sh /backup/tenant-fs            # data dir defaults to ./data
#
# Notes:
#   - SERVER_SECRET is NEVER written into the backup media: it is the root key
#     for blob encryption and must stay in the deployment environment.
#   - Stop the server first if you can; otherwise the script attempts a WAL
#     checkpoint so the DB copy is consistent, and warns if that fails.
#   - Excluded (all re-creatable): backups/, blobs/dec_cache/, blobs/exports/,
#     blobs/tmp_*.
#   - By default the backup copy is verified with sqlite3 integrity_check
#     (skip with --no-verify).

set -euo pipefail

DATA_DIR="$(pwd)/data"
SECRET_OUT=""
VERIFY=1
DEST=""
ENV_SRC=""
ENV_OUT=""
INCLUDE_ENV=1

usage() {
  cat <<'EOF'
Usage:
  ./backup.sh <destination> [options]

Options:
  --data <dir>            data directory path (default: ./data under cwd)
  --secret-out <file>     also save SERVER_SECRET to <file> (chmod 600, kept
                          OUTSIDE the backup media)
  --env <file>            .env file to back up (default: <data-parent>/.env,
                          or the one at the project root next to this script)
  --env-out <file>        copy the .env file to <file> (chmod 600, kept OUTSIDE
                          the backup media) — the recommended way to back up
                          .env so credentials never leave the deployment
  --include-env           copy the .env file INTO the backup destination
                          (<dest>/.env) — ON by default, for the simplest
                          one-dir restore. Only safe when the backup media is
                          trusted/encrypted, because .env holds SERVER_SECRET
                          and ADMIN_TOKEN
  --no-env                do NOT copy .env into the backup destination
                          (use --env-out / --secret-out for the credentials)
  --no-verify             skip SQLite integrity_check of the backup copy
  -h, --help              show this help

Examples:
  ./backup.sh /Volumes/Backup/tenant-fs --data ./data
  ./backup.sh /backup/tenant-fs --env-out ~/.secrets/tenant-fs.env     # .env separate
  ./backup.sh /backup/tenant-fs --no-env                               # .env not in media
  ./backup.sh /backup/tenant-fs --secret-out ~/.secrets/tenant-fs.server_secret
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data)
      [[ $# -ge 2 ]] || { echo "error: --data requires a value" >&2; usage; }
      DATA_DIR="$2"; shift 2 ;;
    --secret-out)
      [[ $# -ge 2 ]] || { echo "error: --secret-out requires a value" >&2; usage; }
      SECRET_OUT="$2"; shift 2 ;;
    --env)
      [[ $# -ge 2 ]] || { echo "error: --env requires a value" >&2; usage; }
      ENV_SRC="$2"; shift 2 ;;
    --env-out)
      [[ $# -ge 2 ]] || { echo "error: --env-out requires a value" >&2; usage; }
      ENV_OUT="$2"; shift 2 ;;
    --include-env)
      INCLUDE_ENV=1; shift ;;
    --no-env)
      INCLUDE_ENV=0; shift ;;
    --no-verify)
      VERIFY=0; shift ;;
    -h|--help)
      usage ;;
    -*)
      echo "error: unknown option: $1" >&2; usage ;;
    *)
      if [[ -z "$DEST" ]]; then
        DEST="$1"
      else
        echo "error: unexpected extra argument: $1" >&2; usage
      fi
      shift ;;
  esac
done

[[ -n "$DEST" ]] || { echo "error: missing destination path" >&2; usage; }

# ---- normalize paths ----
DATA_DIR="$(cd "$DATA_DIR" 2>/dev/null && pwd)" || {
  echo "error: data directory does not exist or is not accessible: $DATA_DIR" >&2; exit 1
}
mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)"

# ---- safety: destination must not be inside (or equal to) the data dir ----
if [[ "$DEST" == "$DATA_DIR" || "$DEST" == "$DATA_DIR"/* ]]; then
  echo "error: destination must not be inside the data directory: $DEST" >&2
  exit 1
fi

echo "==> backup source: $DATA_DIR"
echo "==> backup destination: $DEST"
echo ""

# ---- 1) consistency: checkpoint WAL when the service is idle ----
DB_FILE="$DATA_DIR/fs.db"
if [[ -f "$DB_FILE" ]] && command -v sqlite3 >/dev/null 2>&1; then
  if sqlite3 "$DB_FILE" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1; then
    echo "==> SQLite WAL checkpoint done"
  else
    echo "!! WAL checkpoint failed — the service may be writing. Stop the server" >&2
    echo "   before backing up, otherwise the snapshot may be inconsistent." >&2
  fi
fi

# ---- 2) sync data/ -> DEST/ (exclude re-creatable / nested dirs) ----
rsync -a --delete \
  --exclude 'backups/' \
  --exclude 'blobs/dec_cache/' \
  --exclude 'blobs/exports/' \
  --exclude 'blobs/tmp_*' \
  "$DATA_DIR/" "$DEST/"

# ---- 3) verify the backup copy (optional) ----
if [[ "$VERIFY" == "1" ]] && command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DEST/fs.db" ]]; then
  if sqlite3 "$DEST/fs.db" "PRAGMA integrity_check;" 2>/dev/null | grep -q '^ok$'; then
    echo "==> backup copy integrity check passed (integrity_check: ok)"
  else
    echo "!! backup copy failed SQLite integrity check — backup is not usable." >&2
    exit 1
  fi
fi

# ---- 4) optional: save SERVER_SECRET to a separate secure location ----
if [[ -n "$SECRET_OUT" ]]; then
  if [[ -n "${TENANT_FS_SERVER_SECRET:-}" ]]; then
    mkdir -p "$(dirname "$SECRET_OUT")"
    ( umask 077; printf '%s\n' "$TENANT_FS_SERVER_SECRET" > "$SECRET_OUT" )
    chmod 600 "$SECRET_OUT"
    echo "==> SERVER_SECRET saved to ${SECRET_OUT} (mode 600, outside the backup media)"
  else
    echo "!! TENANT_FS_SERVER_SECRET is not set; skipping the secret save." >&2
    echo "   You must provide the SAME SERVER_SECRET when restoring, otherwise" >&2
    echo "   the data cannot be decrypted." >&2
  fi
fi

# ---- 4.5) back up the .env file (credentials + settings) ----
# The .env file holds SERVER_SECRET, ADMIN_TOKEN and other settings. Backing it
# up is REQUIRED for a byte-perfect restore, but it must never leak. Two modes:
#   --env-out  -> copy to a separate, trusted location (recommended)
#   --include-env -> copy INSIDE the backup media (simplest restore, but only if
#                    the media itself is trusted/encrypted)
if [[ -z "$ENV_SRC" ]]; then
  ENV_SRC="$(dirname "$DATA_DIR")/.env"
fi
ENV_SRC_ABS="$(cd "$(dirname "$ENV_SRC")" 2>/dev/null && pwd)/$(basename "$ENV_SRC")"
ENV_EXISTS=0
[[ -f "$ENV_SRC_ABS" ]] && ENV_EXISTS=1
if [[ "$ENV_EXISTS" != "1" ]]; then
  echo "!! no .env file found at $ENV_SRC_ABS; .env will not be backed up." >&2
fi
if [[ "$INCLUDE_ENV" == "1" ]]; then
  if [[ "$ENV_EXISTS" == "1" ]]; then
    cp "$ENV_SRC_ABS" "$DEST/.env"
    chmod 600 "$DEST/.env"
    echo "==> .env copied INTO the backup media: $DEST/.env (mode 600)"
    echo "    WARNING: .env holds SERVER_SECRET and ADMIN_TOKEN. Keep the media trusted/encrypted."
  else
    echo "!! --include-env given but no .env exists; skipping." >&2
  fi
fi
if [[ -n "$ENV_OUT" ]]; then
  if [[ "$ENV_EXISTS" == "1" ]]; then
    mkdir -p "$(dirname "$ENV_OUT")"
    cp "$ENV_SRC_ABS" "$ENV_OUT"
    chmod 600 "$ENV_OUT"
    echo "==> .env saved separately to ${ENV_OUT} (mode 600, outside the backup media)"
  else
    echo "!! --env-out given but no .env exists; skipping." >&2
  fi
fi

# ---- 5) write the manifest ----
MANIFEST="$DEST/backup-manifest.txt"
{
  echo "filesrv whole-directory snapshot backup"
  echo "time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "source: $DATA_DIR"
  echo "destination: $DEST"
  echo "excluded: backups/ blobs/dec_cache/ blobs/exports/ blobs/tmp_*"
  echo "env: $ENV_SRC_ABS"
  if [[ "$INCLUDE_ENV" == "1" ]]; then
    echo "env-in-backup: yes (.env stored inside this backup media)"
  else
    echo "env-in-backup: no"
  fi
  if [[ -n "$ENV_OUT" ]]; then
    echo "env-out: $ENV_OUT (separate trusted location)"
  fi
  echo "note: SERVER_SECRET is not stored in the backup media; restoring requires"
  echo "      the SAME SERVER_SECRET that produced this backup."
} > "$MANIFEST"

echo ""
echo "==> backup complete: $DEST"
echo "    manifest: $MANIFEST"
if [[ -z "$SECRET_OUT" ]]; then
  echo "    reminder: save SERVER_SECRET separately (not included in this backup)"
fi
