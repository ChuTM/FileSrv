# Tenant File Server — Admin API (loopback only)

> Scope: operator / admin endpoints, **bound to the loopback admin interface
> only** — never exposed on the public router.
> Base path: `http://127.0.0.1:<admin-port>/admin/v1`
> Auth: `Authorization: Bearer <ADMIN_TOKEN>` — this surface **never** accepts
> `X-App-Key` / HMAC.
> Transport: plain HTTP over loopback by default; terminate at the reverse
> proxy / firewall if the admin bind is ever reachable off-host.
> The **app-facing API** is documented separately in `Documents/en/api.md`
> (and `Documents/zh/api.md`); this file is the admin counterpart.

---

## 1. Overview

- Everything here mutates server/tenant state, so it requires the admin bearer
  token and only listens on `TENANT_FS_ADMIN_BIND` (default `127.0.0.1:8081`).
- The web console and the local CLI (`scripts/admin-cli.sh`) are thin clients
  over these endpoints.
- Hardening headers are applied to console responses: `Content-Security-Policy`,
  `X-Frame-Options: DENY`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.

---

## 2. Admin console (static assets)

A small HTML/JS console is embedded at compile time and served **only** on the
loopback admin bind; the public router 404s all of it.

| Method | Path | Description |
|---|---|---|
| GET | `/admin` | 308 → `/admin/` |
| GET | `/admin/`, `/admin/index.html` | The HTML shell |
| GET | `/admin/app.js`, `/admin/style.css` | Client-side assets |

The page is pure client-side: it stores the admin bearer token in
`sessionStorage` and calls `/admin/v1/*` itself. No data ships in the static
assets.

---

## 3. Apps

| Method | Path | Description |
|---|---|---|
| POST | `/admin/v1/apps` | Create app → `{app_id, app_key, app_secret}` (**secret returned once**) |
| GET | `/admin/v1/apps` | List with usage/quota (soft-deleted apps included, `enabled=false`) |
| GET | `/admin/v1/apps/{id}` | Detail; soft-deleted app → `404` |
| PATCH | `/admin/v1/apps/{id}` | `{enabled?, quota_bytes?, max_payload_bytes?}` |
| POST | `/admin/v1/apps/{id}/secret/rotate` | Rotate secret (old one invalidated immediately) |
| DELETE | `/admin/v1/apps/{id}` | Soft-delete (immediately disabled) |
| GET | `/admin/v1/apps/{id}/usage` | `usage_bytes / quota_bytes / file_count / active_token_count` |
| POST | `/admin/v1/apps/{id}/users` | Pre-provision a user: `{"user_id": "..."}` (`INSERT OR IGNORE`) |
| GET | `/admin/v1/apps/{id}/users` | List pre-provisioned users of the app |
| POST | `/admin/v1/apps/{id}/groups` | Create a group: `{"name": "..."}` (empty membership) |
| GET | `/admin/v1/apps/{id}/groups` | List groups (each with its members) |
| GET | `/admin/v1/apps/{id}/groups/{name}` | Group detail + members |
| DELETE | `/admin/v1/apps/{id}/groups/{name}` | Delete a group |
| POST | `/admin/v1/apps/{id}/groups/{name}/members` | Add member: `{"user_id": "..."}` |
| DELETE | `/admin/v1/apps/{id}/groups/{name}/members/{user_id}` | Remove member |

### User groups

Groups let the operator grant access by membership instead of listing every
`user_id` in each file ACL. A file ACL rule may reference a group as
`g:<group>` (e.g. `{"action":"read","add":["g:eng"]}`) — any registered user who
is a member of that group is then allowed for that action. Group members are
managed through the admin API above; a group is scoped to one app.

Rules:
- Group name: `1..=64` chars, no `/`, `\` or spaces; unique per app.
- Adding an existing member is idempotent; removing a missing member is a no-op.
- Deleting a group does **not** rewrite existing file ACLs — a `g:<name>`
  reference to a deleted group simply matches nothing (users lose that access).
- Membership does **not** grant the user JWT validity on its own; a user must
  still be registered in `app_users` (see `/apps/{id}/users`) before their
  user-context JWT is accepted.

```json
// create group
POST /admin/v1/apps/{id}/groups   {"name": "eng"}
// add member
POST /admin/v1/apps/{id}/groups/eng/members   {"user_id": "alice"}
```

### Create request

```json
{
  "name": "my-app",
  "quota_bytes": 1073741824,
  "max_payload_bytes": 67108864
}
```

Create response (`app_secret` is shown once and cannot be recovered later —
store it server-side):

```json
{
  "app_id": 3,
  "app_key": "app_YRhbtjMbi9g88KJh",
  "app_secret": "vuk0a5dZPtRO6Uy/dEllSdjJxoCOJPLr7EPfTANzF7U=",
  "enabled": true,
  "name": "my-app",
  "quota_bytes": 1073741824,
  "max_payload_bytes": 67108864
}
```

`user_id` follows the same validation rules as the upload path so exported
archive entry names can never contain traversal sequences.

---

## 4. Audit

| Method | Path | Description |
|---|---|---|
| GET | `/admin/v1/audit?app_id=&since=` | Query audit log (append-only), newest first, LIMIT 200 |

Filters: `app_id` (integer) and `since` (Unix seconds). Each entry carries
`at, actor, action, app_id, target, ip, decision`.

---

## 5. Backups

| Method | Path | Description |
|---|---|---|
| POST | `/admin/v1/backups/run` | Run a backup synchronously — see §6 |
| GET | `/admin/v1/backups` | List known backups, newest first (`id, backup_id, status, created_at, finished_at, size, path`) |
| GET | `/admin/v1/backups/{id}` | Detail incl. `target_path` and the parsed manifest; unknown id → `404` |
| PATCH | `/admin/v1/backups/config` | Set config — see below (no GET on this endpoint) |

`PATCH /admin/v1/backups/config` body:

```json
{ "schedule"?: 86400, "target"?: "nightly", "retention"?: 7 }
```

- `schedule`: seconds between runs (0 = off). `target`: a **relative** directory
  name inside `TENANT_FS_BACKUP_ROOT` (canonicalized + `starts_with(root)`;
  absolute paths, `..`, `:` and `\` rejected). `retention`: 1..1000.
- Returns the effective `{schedule_secs, target, retention}`. Persisted in the
  DB and applied to the next run.

---

## 6. Backup & disaster recovery

`POST /admin/v1/backups/run` produces one backup directory under
`TENANT_FS_BACKUP_ROOT` (default `data/backups`) containing:

- `db.sqlite` — consistent DB snapshot via `VACUUM INTO`;
- `blobs.tar` — the envelope-encrypted app blob trees (`dec_cache/`, finished
  exports and `tmp_*` partials skipped);
- `manifest.json` — each file with its name, size and sha256.

Response:

```json
{
  "backup_id": "bk_…",
  "id": 2,
  "status": "ready",
  "size": 152172544,
  "files": [ { "name": "...", "size": 123, "sha256": "..." } ]
}
```

- **No key material** ever lands in a backup: `SERVER_SECRET`, the admin token
  and app secrets stay in the deployment environment. The DB snapshot contains
  `apps.secret_sealed` (app secrets sealed under the KEK), which is useless
  without `SERVER_SECRET`. A stolen backup therefore holds unopenable
  ciphertext.
- **Retention** keeps the newest N copies (`TENANT_FS_BACKUP_RETENTION`,
  default 7; overridable 1–1000 via `PATCH /backups/config`). Obsolete
  directories and rows are removed.
- **Schedule** is off by default (`TENANT_FS_BACKUP_SCHEDULE_SECS=0`). When set
  > 0 (or overridden in the DB), the maintenance loop fires a run when the
  interval has elapsed since the last backup.
- **Target whitelist**: `target` must be a relative directory name; it is
  canonicalized and must stay inside the backup root — absolute paths, `..`,
  `:` and `\` are rejected, blocking path/symlink escape.

**Restore** (operator-side procedure; no restore endpoint yet): stop the
server, place the snapshot `fs.db` and untar `blobs.tar` back into the blob
root, then start the server with the same `SERVER_SECRET`. Missing blob files
surface as "File content missing." on download.

---

## 7. Key policy (operator view)

- `SERVER_SECRET` lives only in the deployment environment and is **never**
  copied into a backup, volume snapshot, or CI fixture.
- The KEK is `SHA-256(SERVER_SECRET)`, used both for sealing app secrets
  (`apps.secret_sealed`) and for wrapping each blob's per-file DEK (AES-256-GCM
  envelope). Two encryptions of the same plaintext always differ.
- Key material is never logged.

---

## 8. Roadmap (admin-scoped, not yet implemented)

| Feature | Notes |
|---|---|
| Backup **restore** endpoint | Backups are produced; restore is a manual operator procedure (§6). |
| Operator / auditor role separation | Single shared `ADMIN_TOKEN` today; no role split. |
| Webhook / push notification on export completion | Poll the status endpoint instead. |

> Note: `TENANT_FS_ADMIN_TOKEN` still has a development default; the server
> prints a loud startup WARNING (same treatment as `SERVER_SECRET`). Set both
> explicitly in production.
