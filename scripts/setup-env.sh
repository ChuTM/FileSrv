#!/usr/bin/env bash
# setup-env.sh — generate a .env file from .env.example, auto-filling
# blank required secrets (SERVER_SECRET / ADMIN_TOKEN).
#
# Usage:  ./scripts/setup-env.sh
# Effect: creates .env (mode 600) in the project root if it does not exist;
#         never overwrites an existing .env.
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE=".env"
EXAMPLE=".env.example"

if [ ! -f "$EXAMPLE" ]; then
  echo "ERROR: ${EXAMPLE} not found in project root." >&2
  exit 1
fi

if [ -f "$ENV_FILE" ]; then
  echo "WARN: ${ENV_FILE} already exists; not overwriting." >&2
  exit 0
fi

# Generate fresh secrets (SERVER_SECRET must be 32 random bytes hex;
# ADMIN_TOKEN any high-entropy string).
SERVER_SECRET="$(openssl rand -hex 32)"
ADMIN_TOKEN="$(openssl rand -base64 24 | tr -d '\n')"

awk -v secret="$SERVER_SECRET" -v token="$ADMIN_TOKEN" '
  /^TENANT_FS_SERVER_SECRET=.*$/ && !done_secret {
    print "TENANT_FS_SERVER_SECRET=" secret; done_secret=1; next
  }
  /^TENANT_FS_ADMIN_TOKEN=.*$/ && !done_token {
    print "TENANT_FS_ADMIN_TOKEN=" token; done_token=1; next
  }
  { print }
' "$EXAMPLE" > "$ENV_FILE"

chmod 600 "$ENV_FILE"
echo "Created ${ENV_FILE} (mode 600) with auto-generated SERVER_SECRET and ADMIN_TOKEN."
echo "Review the other settings, then run:  ./scripts/start.sh"
