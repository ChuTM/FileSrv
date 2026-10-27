# Tenant File Server — API Specification (English)

> Version: v1.0 · Type: API usage specification (as implemented)
> Base path (App API): `https://<host>/v1`
> Admin path (Admin API): `http://127.0.0.1:<admin-port>/admin/v1` (loopback only)
> Transport: HTTP/HTTPS · Versioned: `/v1` · Content-Type: `application/json`

---

## 1. Overview

- Four identity kinds, each mapped to specific endpoints (see §2).
- Every data operation (upload / list / meta / delete / export / download) goes
  through a unified auth + rules gateway, **deny-by-default**.
- Every request's final decision is written to the audit log (traceable).
- Errors always use the unified JSON error model (§1.1); HTTP status codes are
  semantic.
- **Language**: all API output (response payloads, field values, error
  `message`) is English (en-US). This document is in English as documentation.

### 1.1 Error model

```json
{
  "error": {
    "code": "app_not_found",
    "message": "App not found or disabled.",
    "request_id": "req_01J..."
  }
}
```

---

## 2. Authentication

| Identity | Mechanism | Endpoints |
|---|---|---|
| App-level | `X-App-Key` + `X-App-Signature` (HMAC) | upload, export, generate (as app) |
| User-level | `Authorization: Bearer <user-jwt>` (signed by the app's secret) | upload, list, meta, delete, generate (as user) |
| Capability token | `GET /v1/download/<token>` — no app key required | download |
| Admin | `Authorization: Bearer <admin-token>` (loopback only) | admin endpoints |

### 2.1 App-level HMAC signature

- `X-App-Key`: the app's public identifier.
- `X-App-Signature`: HMAC-SHA256 of the canonical request + timestamp + nonce,
  signed with the app's secret.
- `X-Timestamp` and `X-Nonce` are required (replay protection: ±300s window,
  nonce must never repeat).

```
signature = HMAC_SHA256(app_secret, "<method>\n<path>\n<query>\n<body-hash>\n<timestamp>\n<nonce>")
```

### 2.2 User-context JWT (delegated identity)

The app backend signs a short-lived JWT for its end user (`user_id`); the
server verifies the signature and trusts the JWT. Any `user_id` carried in the
request body/header is ignored and overridden.

```json
{ "iss": "app:{app_id}", "sub": "u_8f3a…", "exp": 1800000000, "scope": "files:rw" }
```

---

## 3. Rules and ACL (per action)

`user_id` is an opaque identifier assigned by the app (not a display name),
unique within the app.

```json
{
  "owner": "u_8f3a",
  "read":   ["u_2c9d", "group:team_ops"],
  "write":  ["u_2c9d"],
  "delete": [],
  "list":   ["u_2c9d", "group:team_ops"],
  "export": ["group:admins"],
  "deny":   ["u_mallory"],
  "public_read": false
}
```

- `"*"` = everyone; `group:{name}` = a group; **`deny` wins over every allow.**
- **Inheritance**: a file with no explicit ACL inherits from its folder →
  ancestors → app default; **`deny` is collected across the whole chain and a
  file's explicit ACL cannot override an inherited deny**; the owner keeps
  default access unless denied.
- **Who may change ACLs**: ① User level — only the **owner** may change the ACL
  of a file it owns; ② **App level (tenant admin)** may change the ACL of any
  file/folder in the app, including batch and folder-recursive (see §8.4, §8.5).

---

## 4. Upload API

### `POST /v1/upload`

Call with a **user-context JWT** or **app identity**.

| Header | Value |
|---|---|
| `Authorization: Bearer <user-jwt>` or `X-App-Key`+`X-App-Signature` | identity |
| `X-User-Id` | **required for app-level uploads** — the user the app vouches for |
| `Content-Type` | MIME of the file (stored as-is; the server never infers from the filename) |

Body: file content (streamed to a temp file, then verified).

| Header | Value |
|---|---|
| `Idempotency-Key` | **optional** — retry guard (see §4.2) |

Response `200`:

```json
{
  "file_id": 3,
  "app_id": "app_1",
  "owner": "u1",
  "storage_uuid": "a5cd67dc-...",
  "size": 1048576,
  "sha256": "9b1deb4d...",
  "classification": "internal",
  "content_type": "application/octet-stream"
}
```

- The original filename is stripped; content is stored as an opaque UUID in the
  app's dedicated directory. `logical_path` and the download filename are the
  storage UUID.
- Payload is capped while streaming: over `max_payload_bytes` → `413`;
  quota full → `429`.
- Optional `?folder_id=` query targets a folder (must belong to the app).

### 4.2 Idempotent upload retries

Send a client-generated `Idempotency-Key` header on `POST /v1/upload`. Within
the configured window (`TENANT_FS_IDEMPOTENCY_WINDOW_SECS`, default 3600s,
floor 60s) a retry carrying the **same key from the same identity** gets back
the **original** upload result — no second blob is written, no quota is
double-charged. After the window expires the key is forgotten and behaves as a
brand-new upload. The cache is in-memory (best-effort retry guard, not a
durable queue), hard-capped at `TENANT_FS_IDEMPOTENCY_MAX_ENTRIES` (default
10000, LRU eviction).

### 4.3 Chunked / resumable upload

For large files or flaky networks, use the three-step session:

| Step | Method & path | Behavior |
|---|---|---|
| 1. init | `POST /v1/upload/init` | Body `{ "total_size"?: <bytes>, "folder_id"?: <id> }`. Returns `{ "upload_id": "up_…", "status": "open", "total_size", "received_size": 0, "chunk_ttl_secs", "max_payload_bytes" }`. `total_size > 0` is rejected if it exceeds the app's `max_payload_bytes`. |
| 2. chunk | `PUT /v1/upload/{upload_id}` | Raw chunk body, header `X-Chunk-Offset: <byte offset>`. Chunks must arrive **contiguously**: the offset must equal the server's current `received_size`. A gap → `409` with `{ "error": { "code": "conflict", "message": "Unexpected chunk offset; resume at N." } }` so the client can re-aim. App-level HMAC is verified per chunk. Returns `{ "upload_id", "received_size", "status": "open" }`. |
| 3. finalize | `POST /v1/upload/{upload_id}/finalize` | Verifies the received byte count against `total_size`, re-checks quota atomically, SHA-256s the staged file, encrypt-writes the blob through the storage layer (see §13), and returns the same metadata shape as `POST /v1/upload`. |

- Identity rules mirror `POST /v1/upload` (user JWT, or app HMAC with
  `X-User-Id`); an unknown / expired / cross-tenant session → `404`.
- Interrupted sessions expire after `TENANT_FS_UPLOAD_TTL_SECS` (default
  86400s, floor 60s); staged partial files are unlinked by the background loop.
- All three calls are metered by the per-app rate limiter (§11).

---

## 5. Generate download links

### `POST /v1/links/generate`

Call with **app identity** or **user-context JWT** (only a request; the server
mints the token).

```json
{
  "file_id": 3,
  "ttl_seconds": 1800,
  "scope": "embed",
  "allowed_ip": "203.0.113.45"
}
```

- `scope: "embed"`: **idempotent** — the same (file, user, scope) returns the
  **same** token, TTL fixed from first mint, refreshing does not extend it.
  Keyed on the requesting user for user JWTs (falls back to the file owner for
  app identity).
- `scope: "share"`: one-time share — a new token each time, optionally bound to
  `allowed_ip`.
- The server re-reads the file, re-runs the ACL, deny-by-default; a `file_id`
  outside the current app → `404`.

Response `200`:

```json
{
  "token": "tk_....",
  "url": "/v1/download/tk_....",
  "scope": "embed",
  "expires_at": 1800000000,
  "reused": false
}
```

(`reused: true` means an existing token was returned.)

---

## 6. Download API

### `GET /v1/download/:token`

For end users, **no app key required**. The capability token binds
`(app_id, file_id, TTL)`; share tokens may additionally bind a client IP.

- Expired / revoked token → `404` (hides existence).
- Supports **Range** (`206`), `ETag`, `If-None-Match` (→ `304`); `416` for an
  unsatisfiable range.
- Security headers: `Content-Disposition: attachment` + `X-Content-Type-Options:
  nosniff`.
- **Client IP for IP-bound tokens**: the TCP peer IP by default; the
  `X-Forwarded-For` header is honored **only** when the server runs in
  trusted-proxy mode (`TENANT_FS_TRUST_XFF=true`). Otherwise a spoofed header
  has no effect.

### `HEAD /v1/download/:token`

Identical authentication, token rules and 404 semantics as `GET`, but
response headers only — no body. Returns `Content-Length`, `ETag`
(`"sha256-<hex>"`), `Content-Type`, `Content-Disposition`,
`X-Content-Type-Options: nosniff`; `If-None-Match` → `304`; unknown / expired
token → `404`. Use it for pre-flight size/etag checks before streaming.

---

## 7. Revoke a token

### `POST /v1/tokens/revoke`

Call with **app identity**. A revoked token fails immediately; the next
generate mints a **new** token.

```json
{ "token": "tk_...." }
```

Response `200`: `{ "revoked": true }`; unknown token → `404`.

---

## 8. Files and folders CRUD

### 8.1 Files

`GET /v1/files/:id` — file metadata. Requires `read` on the file.

`GET /v1/files?folder_id=&cursor=` — list, paginated by cursor, `WHERE app_id =
identity.app_id`. For user JWTs the list is filtered by access
(`list`/`read`).

`DELETE /v1/files/:id` — requires `delete`; **ownership check** (app + user
ACL). Soft-delete: sets a tombstone (`deleted_at`), immediately frees the
app's storage usage and drops every download token of the file (tokens fail
`404` at once). The on-disk blob and DB row survive a grace window
(`TENANT_FS_SOFT_DELETE_DAYS`, default 7) and are physically removed by the
background purge loop every `TENANT_FS_PURGE_INTERVAL_SECS` (default 600s).
Success → `204`.

### 8.2 Folders

| Method | Path | Description |
|---|---|---|
| POST | `/v1/folders` | Create: `{ parent_id?, name }` |
| GET | `/v1/folders/:id` | Folder detail + ACL |
| GET | `/v1/folders/:id/files` | Files under the folder |
| PATCH | `/v1/folders/:id` | Rename / move under another parent |
| DELETE | `/v1/folders/:id` | Delete (requires `delete`; cascade to files) |

### 8.3 ACL management (file)

`PATCH /v1/files/:id/acl` — change one file's ACL (owner or app level). Body:

```json
{ "action": "read", "add": ["u_2c9d", "group:ops"], "remove": ["u_mallory"], "deny": ["u_mallory"] }
```

### 8.4 Folder ACL (recursive)

`PATCH /v1/folders/:id/acl`

```json
{ "action": "read", "add": ["group:team_ops"], "recursive": true }
```

`recursive: true` applies to child folders; `deny` stays chain-priority.

### 8.5 Batch ACL

`POST /v1/files/batch/acl` — change many files at once (app level). Body:

```json
{ "file_ids": [1, 2, 3], "action": "read", "add": ["u_2c9d"], "remove": [] }
```

- Batch cap (`TENANT_FS_MAX_BATCH_ACL`, default 1000), idempotent, single
  audit entry. Only files of the authenticated app; cross-app targets rejected.

---

## 9. App self-export

### `POST /v1/apps/export`

Call with **app identity** (hard-bound to the verified `app_id`; no target
app_id parameter is accepted).

```json
{ "format": "tar", "scope": "all" }
```

`format` accepts `"tar"` (default) or `"zip"`. `zip` is produced by the `zip`
crate (no external process), and organises entries the same way as tar:
`files/<user_id>/<storage_uuid>`.

Response `202`:

```json
{ "job_id": 1, "status": "pending" }
```

### `GET /v1/apps/exports/:id` / `GET /v1/apps/exports/:id/download`

`200`: `{ "status": "ready", "size": 12345, ... }`; still running → `202` (the
status endpoint). The archive is a **tar** or **zip** containing every
non-deleted file, organised as `files/<user_id>/<storage_uuid>`.

Finished export artifacts and their rows are swept after
`TENANT_FS_EXPORT_TTL_SECS` (default 86400s, floor 1s) by the background
maintenance loop.

---

## 10. Internal admin API (loopback only)

Header: `Authorization: Bearer <ADMIN_TOKEN>`. **Never accepts
`X-App-Key`/HMAC.**

### Apps

| Method | Path | Description |
|---|---|---|
| POST | `/admin/v1/apps` | Create app → `{app_id, app_key, app_secret}` (**secret returned once**) |
| GET | `/admin/v1/apps` | List with usage/quota |
| GET | `/admin/v1/apps/{id}` | Detail |
| PATCH | `/admin/v1/apps/{id}` | `{enabled?, quota_bytes?, max_payload_bytes?}` |
| POST | `/admin/v1/apps/{id}/secret/rotate` | Rotate secret (old one invalidated immediately) |
| DELETE | `/admin/v1/apps/{id}` | Soft-delete (immediately disabled) |
| GET | `/admin/v1/apps/{id}/usage` | `usage_bytes / quota_bytes / file_count / active_token_count` |

### Audit

| Method | Path | Description |
|---|---|---|
| GET | `/admin/v1/audit?app_id=&since=` | Query audit log (append-only), newest first, LIMIT 200 |

### Backups (§14)

| Method | Path | Description |
|---|---|---|
| POST | `/admin/v1/backups/run` | Run a backup synchronously: DB snapshot (`VACUUM INTO`) + `blobs.tar` (envelope-encrypted blob tree, `dec_cache/` / finished exports / `tmp_*` partials excluded) + `manifest.json` with per-file sha256. Returns `{ "backup_id": "bk_…", "id", "status": "ready", "size", "files": [{name, size, sha256}] }`. |
| GET | `/admin/v1/backups` | List known backups, newest first (`id, backup_id, status, created_at, finished_at, size, path`). |
| GET | `/admin/v1/backups/{id}` | Detail incl. `target_path` and the parsed manifest; unknown id → `404`. |
| PATCH | `/admin/v1/backups/config` | Body `{ "schedule"?: <secs>, "target"?: "<relative dir>", "retention"?: <1..1000> }`. Persisted in the DB and applied to the next run. `target` must be a relative directory name inside `TENANT_FS_BACKUP_ROOT` (canonicalize + `starts_with(root)`; absolute paths, `..`, `:` and `\` rejected). Returns the effective `{schedule_secs, target, retention}`. |

Backup configuration knobs: `TENANT_FS_BACKUP_ROOT` (default `data/backups`),
`TENANT_FS_BACKUP_RETENTION` (default 7, newest wins),
`TENANT_FS_BACKUP_SCHEDULE_SECS` (default 0 = off; when > 0 the maintenance
loop fires a run when the interval has elapsed since the last backup).

### Admin console (static assets)

A small HTML/JS console is embedded at compile time and served **only on the
loopback admin bind** — the public router 404s all of it:

| Method | Path | Description |
|---|---|---|
| GET | `/admin`, `/admin/`, `/admin/index.html` | The HTML shell |
| GET | `/admin/app.js`, `/admin/style.css` | Client-side assets |

The page is pure client-side: it stores the admin bearer token in
`sessionStorage` and calls `/admin/v1/*` itself. Every console response carries
hardening headers: `Content-Security-Policy`, `X-Frame-Options: DENY`,
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`.

---

## 11. Limits and quotas

- **Storage quota** `quota_bytes` (app level) and `max_payload_bytes`
  (per file) — enforced atomically; over quota → `429 quota_exceeded`.
- Payload over limit → `413 payload_too_large`.
- **Per-app rate limiting**: `generate`, `upload` (plain and chunked
  init/chunk/finalize) and `export` share one fixed 60s window per `app_id`.
  When the window is exhausted the call fails with `429`, response header
  `Retry-After: <seconds until the window resets>` and body
  `{ "error": { "code": "rate_limited", ... } }`.
  Knobs: `TENANT_FS_RATE_LIMIT_PER_MIN` (default 120; 0 = disabled),
  `TENANT_FS_RATE_LIMIT_MAX_ENTRIES` (default 10000; hard map capacity, stale
  windows swept before it can grow).

---

## 12. Error codes

| Status | code | Situation |
|---|---|---|
| 400 | `invalid_request` | malformed parameter |
| 401 | `unauthorized` | missing/wrong identity, bad signature, replay |
| 403 | `forbidden` | rule denial (deny / no permission) |
| 404 | `not_found` | file/app/token missing or expired (404 rather than 403 hides existence) |
| 409 | `conflict` | state conflict (e.g. export not ready; chunk offset mismatch) |
| 413 | `payload_too_large` | over the per-file limit |
| 429 | `quota_exceeded` | app storage quota full |
| 429 | `rate_limited` | per-app request window exhausted; `Retry-After` header set |
| 500 | `internal` | server error |

> Security note: non-existent resources always return **404**, never 403.

---

## 13. Static encryption and key policy

Blobs are encrypted at rest by default (`TENANT_FS_ENCRYPT_BLOBS=true`). Each
blob is a self-contained envelope:

```
[0..4]    magic "TSFS"
[4]       format version = 1
[5..17]   dek_nonce   (12 bytes, nonce sealing the DEK under the KEK)
[17..65]  sealed_dek  (48 bytes = AES-256-GCM(KEK, dek_nonce, DEK[32]))
[65..77]  body_nonce  (12 bytes)
[77..]    ciphertext  = AES-256-GCM(DEK, body_nonce, plaintext)
```

- Every blob gets its own random 256-bit DEK; two encryptions of the same
  plaintext produce different bytes.
- **KEK policy**: the KEK is derived as `SHA-256(SERVER_SECRET)` — the same
  derivation used for sealing app secrets. `SERVER_SECRET` lives **only** in
  the deployment environment and is **never** copied into a backup (DB dump,
  blob archive, manifest, volume snapshot, CI fixture). Because the sealed DEK
  travels inside the blob header, a stolen backup without `SERVER_SECRET` holds
  ciphertext that cannot be opened. Key material is never logged.
- **Legacy plaintext**: blobs written before encryption (no `TSFS` magic) are
  served through the legacy plaintext path transparently. `migrate_plaintext_blobs()`
  is an idempotent one-shot migration that rewrites legacy blobs in place to the
  envelope format.
- **Decrypted read cache**: when serving an encrypted blob the server
  materializes a per-uuid plaintext cache under `blob_root/dec_cache/` (atomic
  swap). That cache is deliberately excluded from backups and from the export
  trees; deletion and purge operate on the real encrypted file.

## 14. Backup and disaster recovery

- **`POST /admin/v1/backups/run`** produces one backup directory under
  `TENANT_FS_BACKUP_ROOT` (default `data/backups`) containing `db.sqlite`
  (consistent snapshot via `VACUUM INTO`), `blobs.tar` (the envelope-encrypted
  app blob trees; `dec_cache/`, finished exports and `tmp_*` partials skipped),
  and `manifest.json` listing each file with its size and sha256.
- **No key material** ever lands in a backup: `SERVER_SECRET`, the admin token
  and app secrets stay in the deployment environment. The DB snapshot contains
  `apps.secret_sealed` (app secrets sealed under the KEK), which is useless
  without `SERVER_SECRET`.
- **Retention** keeps the newest N copies (`TENANT_FS_BACKUP_RETENTION`,
  default 7; overridable 1–1000 via `PATCH /backups/config`). Obsolete
  directories and rows are removed.
- **Schedule** is off by default (`TENANT_FS_BACKUP_SCHEDULE_SECS=0`). When set
  > 0 (or overridden in the DB via `PATCH /backups/config`), the maintenance
  loop fires a run when the interval has elapsed since the last backup.
- **Target whitelist**: `target` must be a relative directory name; it is
  canonicalized and must stay inside the backup root — absolute paths, `..`,
  `:` and `\` are rejected, blocking path/symlink escape.
- **Restore** is an operator-side procedure (no restore endpoint yet): stop
  the server, place the snapshot `fs.db` and untar `blobs.tar` back into the
  blob root, then start the server with the same `SERVER_SECRET`. Missing blob
  files surface as "File content missing." on download.

---

## 15. Specified but NOT yet implemented (roadmap)

| Feature | Notes |
|---|---|
| Backup **restore** endpoint | Backups are produced; restore is a manual operator procedure (§14). |
| TLS / HSTS termination | Server speaks plain HTTP; terminate TLS at a reverse proxy. |
| Malware / antivirus scanning of uploads | Not present. |
| Operator / auditor role separation | Single shared `ADMIN_TOKEN` today; no role split. |
| Webhook / push notification on export completion | Poll the status endpoint instead. |

> Note: `TENANT_FS_ADMIN_TOKEN` still has a development default; the server
> prints a loud startup WARNING (same treatment as `SERVER_SECRET`). Set both
> explicitly in production.

---

## 16. Appendix: upload example (curl)

App-level upload:

```bash
ts=$(date +%s); nonce=$(openssl rand -hex 16)
body_hash=$(sha256sum file.bin | cut -d' ' -f1)
sig=$(printf "POST\n/v1/upload\n\n%s\n%s\n%s" "$body_hash" "$ts" "$nonce" \
  | openssl dgst -sha256 -hmac "$APP_SECRET" -hex | cut -d' ' -f2)

curl -X POST http://<host>:8080/v1/upload \
  -H "X-App-Key: $APP_KEY" -H "X-App-Signature: $sig" \
  -H "X-Timestamp: $ts" -H "X-Nonce: $nonce" \
  -H "X-User-Id: u_8f3a" \
  --data-binary @file.bin
```

Generate an embed link and download:

```bash
# 1) generate (app identity; repeated calls return the same token)
curl -X POST http://<host>:8080/v1/links/generate \
  -H "X-App-Key: $APP_KEY" -H "X-App-Signature: $sig2" ... \
  -d '{"file_id":3,"ttl_seconds":1800,"scope":"embed"}'

# 2) download (no app key)
curl http://<host>:8080/v1/download/tk_.... -o out.bin
```

Revoke the token (app identity):

```bash
curl -X POST http://<host>:8080/v1/tokens/revoke \
  -H "X-App-Key: $APP_KEY" ... -d '{"token":"tk_...."}'
# → the old link fails immediately; the next generate mints a new token
```
