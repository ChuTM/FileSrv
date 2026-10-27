#!/usr/bin/env bash
#
# tenant-fs-server — whole-data-directory snapshot backup (the simplest option)
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

usage() {
  cat <<'EOF'
Usage:
  ./backup.sh <destination> [options]

Options:
  --data <dir>            data directory path (default: ./data under cwd)
  --secret-out <file>     also save SERVER_SECRET to <file> (chmod 600, kept
                          OUTSIDE the backup media)
  --no-verify             skip SQLite integrity_check of the backup copy
  -h, --help              show this help

Examples:
  ./backup.sh /Volumes/Backup/tenant-fs --data ./data
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

# ---- 5) write the manifest ----
MANIFEST="$DEST/backup-manifest.txt"
{
  echo "tenant-fs-server whole-directory snapshot backup"
  echo "time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "source: $DATA_DIR"
  echo "destination: $DEST"
  echo "excluded: backups/ blobs/dec_cache/ blobs/exports/ blobs/tmp_*"
  echo "note: SERVER_SECRET is not stored in the backup media; restoring requires"
  echo "      the SAME SERVER_SECRET that produced this backup."
} > "$MANIFEST"

echo ""
echo "==> backup complete: $DEST"
echo "    manifest: $MANIFEST"
if [[ -z "$SECRET_OUT" ]]; then
  echo "    reminder: save SERVER_SECRET separately (not included in this backup)"
fi
