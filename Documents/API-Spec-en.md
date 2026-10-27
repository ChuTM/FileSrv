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
ACL); soft-delete (tombstone), blob removed immediately, tokens dropped,
usage freed. Success → `204`.

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

Response `202`:

```json
{ "job_id": 1, "status": "pending" }
```

### `GET /v1/apps/exports/:id` / `GET /v1/apps/exports/:id/download`

`200`: `{ "status": "ready", "size": 12345, ... }`; still running → `202` (the
status endpoint). The archive is a **tar** containing every non-deleted file,
organised as `files/<user_id>/<storage_uuid>`.

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

---

## 11. Limits and quotas

- **Storage quota** `quota_bytes` (app level) and `max_payload_bytes`
  (per file) — enforced atomically; over quota → `429 quota_exceeded`.
- Payload over limit → `413 payload_too_large`.

> Note: per-app rate limiting (generate / upload / export) is specified in the
> roadmap but **not yet implemented** (see §13).

---

## 12. Error codes

| Status | code | Situation |
|---|---|---|
| 400 | `invalid_request` | malformed parameter |
| 401 | `unauthorized` | missing/wrong identity, bad signature, replay |
| 403 | `forbidden` | rule denial (deny / no permission) |
| 404 | `not_found` | file/app/token missing or expired (404 rather than 403 hides existence) |
| 409 | `conflict` | state conflict (e.g. export not ready) |
| 413 | `payload_too_large` | over the per-file limit |
| 429 | `quota_exceeded` | app storage quota full |
| 500 | `internal` | server error |

> Security note: non-existent resources always return **404**, never 403.

---

## 13. Specified but NOT yet implemented (roadmap)

| Feature | Spec reference | Status |
|---|---|---|
| Backup API (`/admin/v1/backups/run`, `/backups`, `PATCH /backups/config {schedule?, target?, retention?}`) | spec §10 Backup | **Not implemented** — see `Ops-and-Backup.md` |
| Chunked / resumable upload (`/v1/upload/init` → `PUT /v1/upload/{id}` → `finalize`) | spec §4 | Not implemented |
| Per-app rate limiting + `Retry-After` | spec §11 | Not implemented |
| Admin web page / HTML dashboard | roadmap | Not implemented (API only) |
| `Idempotency-Key` on upload | spec §4 (recommended) | Not implemented |
| `HEAD` on download, `zip` export format | spec §6/§9 | Not implemented (GET only; tar only) |
| Export archive TTL + expiry cleanup | spec §9 | Not implemented |
| Blob encryption at rest (envelope KEK/DEK) | roadmap §12 | Not implemented (plaintext blobs on disk) |
| Grace-period purge after soft-delete | spec §8.1 | Not implemented (immediate blob removal) |

---

## 14. Appendix: upload example (curl)

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
