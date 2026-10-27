#!/usr/bin/env bash
# start.sh — load .env into the environment and start tenant-fs-server.
#
# Reads every KEY=VALUE line from .env (including the required secrets),
# sanity-checks them, then execs the release binary.
#
# Usage:  ./scripts/start.sh [extra args...]
#   e.g.  ./scripts/start.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f ".env" ]; then
  echo "ERROR: no .env file. Run ./scripts/setup-env.sh first" \
       "(or cp .env.example .env and edit it)." >&2
  exit 1
fi

# Export every variable from .env for the child process.
set -a
# shellcheck disable=SC1091
. ./.env
set +a

# Required secrets must be non-empty.
: "${TENANT_FS_SERVER_SECRET:?TENANT_FS_SERVER_SECRET is not set in .env}"
: "${TENANT_FS_ADMIN_TOKEN:?TENANT_FS_ADMIN_TOKEN is not set in .env}"

if [ ! -x "target/release/tenant-fs-server" ]; then
  echo "ERROR: target/release/tenant-fs-server not found." \
       "Run 'cargo build --release' first." >&2
  exit 1
fi

echo "Starting tenant-fs-server (public=${TENANT_FS_PUBLIC_BIND:-0.0.0.0:8080}, admin=${TENANT_FS_ADMIN_BIND:-127.0.0.1:8081})"
exec ./target/release/tenant-fs-server "$@"
