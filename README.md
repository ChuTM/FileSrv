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
  metrics, audit log, full app export as a tarball, payload/quota limits.

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
cargo test          # 36 tests: 17 unit + 19 integration
```

Integration tests cover cross-tenant isolation, quota enforcement, ACL
inheritance + deny priority (including inherited deny vs file-level explicit
ACL), token idempotency/revoke/IP binding, X-Forwarded-For spoof rejection,
replay and forgery rejection, path traversal, Range/ETag, persistence across
process restarts, secret rotation, app export, batch ACL, payload limits,
audit, unsigned-upload early rejection.

A live end-to-end smoke test (real sockets) was also run: 69/69 checks passed
(admin auth, upload, embed token reuse, range download, revoke→404→new token,
cross-tenant 404, forged HMAC 401, nonce replay 401, usage + audit, IP-bound
share tokens against real peer IP, XFF spoof blocked, inherited-deny
regression).

Note: the server ignores `X-Forwarded-For` by default and uses the TCP peer IP
for IP-bound tokens and audit; set `TENANT_FS_TRUST_XFF=true` only when running
behind a trusted reverse proxy that overwrites that header. Leftover `tmp_*`
blobs are swept at startup, and expired nonces / old audit rows are pruned
periodically (see `TENANT_FS_AUDIT_RETENTION_DAYS`).

## Layout

```
src/
  main.rs         two listeners: public + admin (localhost)
  lib.rs          build_app(cfg) -> routers
  config.rs       env configuration
  crypto.rs       HMAC, JWT (HS256), AES-256-GCM, sha256, constant-time cmp
  db.rs           SQLite schema + queries (WAL, FK, nonce, audit, export jobs)
  storage.rs      blob dir layout + path-escape-proof resolver
  authz.rs        Identity, actions, ACL engine, folder inheritance
  tokens.rs       embed/share/revoke/verify capability tokens
  auth.rs         app HMAC + user JWT + admin verification
  routes/         app.rs (files/folders/acl/batch/export), admin.rs, download.rs
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

For backup / compliance topics (encryption at rest, audit retention, app
export, restic-style backups) see [`多租戶檔案儲存服務_完整規劃.md`](../多租戶檔案儲存服務_完整規劃.md).
