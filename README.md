# Tenant FS Server

A multi-tenant, multi-app file storage service written in Rust (Axum).
Strict data and access isolation between apps and users — built for SaaS / PaaS
backends that store arbitrary, potentially sensitive files (finance invoices,
documents, images, …).

## What it does

- **Tenant model**: Account → App → User. An App owns its own `app_key` /
  `app_secret`, quota, blob space and folder tree. `user_id` is an opaque
  identifier chosen by the App and unique *within* the App.
- **Upload / Download / Link APIs**: signed app requests, capability download
  tokens, Range support, ETag/304.
- **Isolation, everywhere**:
  - Physical blobs: `/blobs/app_{id}/yyyy/mm/{uuid}` — no extensions, outside
    web root, path-escape proof (canonicalize + `starts_with(app_root)`).
  - Tokens: capability tokens bound to app + file + optional IP, with TTL,
    immediate revoke, and idempotent embed window (same token returned within
    the TTL unless revoked).
  - ACLs: per-file and per-folder, per-action (read/write/delete/list/export),
    folder inheritance, deny-wins-everything, owner default access, `"*"`
    wildcard and `public_read`.
  - Requests: `X-App-Key` + HMAC-SHA256 signature over
    `method\npath\nquery\nbody_hash\nts\nnonce`, ±300s timestamp window,
    single-use nonce (replay protection), constant-time comparisons.
  - User identity comes only from a user-context JWT signed with the App
    secret (`iss = app:{id}`); a `user_id` in the request body is never
    trusted.
  - Admin API binds to localhost only, authenticated with a bearer token.
- **Persistence**: SQLite (WAL) as the authoritative store + real blob files
  on disk. Everything survives restarts. No Redis/PostgreSQL required.
- **Operations**: app lifecycle (create/disable/rotate secret/delete), usage
  metrics, audit log, full app export as a tarball or zip, payload/quota limits.
- **Encryption at rest**: blobs are envelope-encrypted (per-blob random DEK,
  sealed under a KEK derived from `TENANT_FS_SERVER_SECRET`; self-contained
  `TSFS` header). Legacy plaintext blobs are read transparently. The secret is
  never copied into backups.
- **Soft-delete grace**: `DELETE` marks a tombstone, rolls quota back and
  invalidates tokens immediately; the blob is physically purged after a grace
  window (default 7 days) by a background loop.
- **Built-in backups**: `POST /admin/v1/backups/run` snapshots the DB
  (`VACUUM INTO`) + archives the encrypted blob tree with a sha256 manifest;
  configurable retention, schedule, and a target whitelist under
  `data/backups`. Restore is an operator-side procedure.
- **Chunked / resumable upload**: `init` → `PUT` with `X-Chunk-Offset` →
  `finalize`, contiguous-offset enforcement (409 + resume offset), TTL sweep.
- **Per-app rate limiting**: shared 60s fixed window across
  generate/upload/export (incl. chunked calls); `429` + `Retry-After`.
- **Idempotent uploads**: optional `Idempotency-Key` returns the cached result
  within a configurable window.
- **Admin console**: a small loopback-only HTML/JS dashboard on the admin bind,
  pure client-side bearer auth, hardened CSP / frame-deny / no-store headers.

## Quick start

```bash
cd tenant-fs-server
# Environment (defaults shown):
export TENANT_FS_DB=data/fs.db            # SQLite file
export TENANT_FS_BLOBS=data/blobs         # blob root
export TENANT_FS_ADMIN_TOKEN=dev-admin-token
export TENANT_FS_SERVER_SECRET=dev-server-secret-change-me  # for token/secret encryption
export TENANT_FS_PUBLIC_BIND=0.0.0.0:8080 # public API
export TENANT_FS_ADMIN_BIND=127.0.0.1:8081# admin API (localhost only)
cargo run --release
```

Then create an App:

```bash
curl -X POST http://127.0.0.1:8081/admin/v1/apps \
  -H "Authorization: Bearer $TENANT_FS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-app","quota_bytes":10737418240,"max_payload_bytes":104857600}'
```

The response contains `app_key` and `app_secret` — keep the secret server-side.
Full API reference: [`多租戶檔案儲存服務_API規範.md`](../多租戶檔案儲存服務_API規範.md).

## Verify

```bash
cargo test          # 60 tests: 32 unit + 28 integration
cargo clippy --all-targets   # 0 warnings
```

Integration tests cover cross-tenant isolation, quota enforcement, ACL
inheritance + deny priority (including inherited deny vs file-level explicit
ACL), token idempotency/revoke/IP binding, X-Forwarded-For spoof rejection,
replay and forgery rejection, path traversal, Range/ETag, persistence across
process restarts, secret rotation, app export (tar + zip), batch ACL, payload
limits, audit, unsigned-upload early rejection, envelope blob encryption
(read-old/write-new), soft-delete grace → purge, chunked upload, backup run /
list / detail / config (incl. target escape), per-app rate limit 429 +
Retry-After, HEAD download headers/404, idempotency-key reuse, and export TTL
sweep.

A live end-to-end smoke test (real sockets) was also run: 121/121 checks passed
(admin auth, upload, embed token reuse, range download, revoke→404→new token,
cross-tenant 404, forged HMAC 401, nonce replay 401, usage + audit, IP-bound
share tokens against real peer IP, XFF spoof blocked, inherited-deny
regression, envelope encryption read-old/write-new, soft-delete lifecycle,
backup API, chunked upload, rate limit, HEAD, zip export, idempotency, export
TTL, and the loopback admin console).

Note: the server ignores `X-Forwarded-For` by default and uses the TCP peer IP
for IP-bound tokens and audit; set `TENANT_FS_TRUST_XFF=true` only when running
behind a trusted reverse proxy that overwrites that header. Leftover `tmp_*`
blobs are swept at startup; a background maintenance loop (every
`TENANT_FS_PURGE_INTERVAL_SECS`, default 600s) prunes expired nonces, old
audit rows (`TENANT_FS_AUDIT_RETENTION_DAYS`), expired `tokens`, soft-delete
tombstones past the grace window, finished exports past their TTL, and
interrupted chunked-upload sessions.

## Layout

```
src/
  main.rs         two listeners: public + admin (localhost), maintenance loop
  lib.rs          build_app(cfg) -> routers
  config.rs       env configuration (Config + Ops knobs)
  crypto.rs       HMAC, JWT (HS256), AES-256-GCM, sha256, constant-time cmp,
                  blob envelope encryption (KEK/DEK)
  db.rs           SQLite schema + queries (WAL, FK, nonce, audit, export jobs,
                  backups, upload jobs, settings, pruning)
  storage.rs      blob dir layout + path-escape-proof resolver + plaintext migration
  authz.rs        Identity, actions, ACL engine, folder inheritance
  tokens.rs       embed/share/revoke/verify capability tokens
  auth.rs         app HMAC + user JWT + admin verification
  ratelimit.rs   per-app fixed-window limiter (429 + Retry-After)
  idem.rs         Idempotency-Key cache (LRU)
  upload.rs       chunked-upload session state
  backup.rs       backup run (VACUUM INTO + blobs.tar + sha256 manifest), retention,
                  target whitelist
  admin_ui.rs     embedded loopback admin console assets (CSP / frame-deny / no-store)
  routes/         app.rs (files/folders/acl/batch/export/upload), admin.rs (apps/audit/
                  backups), download.rs
tests/
  integration.rs  full API tests
```

## Security model (summary)

L1: App key scope binds every request to one tenant; L2: server-minted
capability tokens for downloads (no IdP/OIDC — by design). Blob access is
gated by file metadata ACLs, never by path string parsing. Deny rules are
collected across the whole folder chain and always win. Tokens expire; an
expired/revoked token is 404 and a revoked embed slot mints a fresh token on
the next generate.

For backup / compliance topics (blob envelope encryption, key policy, the
built-in backup API, retention/schedule, restore procedure, audit retention)
see [`Documents/Ops-and-Backup.md`](Documents/Ops-and-Backup.md) and the full
[`Documents/API-Spec-en.md`](Documents/API-Spec-en.md) /
[`Documents/API-Spec-zh.md`](Documents/API-Spec-zh.md).
