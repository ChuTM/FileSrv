# Tenant File Server — Operations & Backup Notes

> Applies to the **current implementation** (SQLite + local blob directories,
> envelope-encrypted blobs, built-in backup API). Where the finalized roadmap
> differs, the difference is called out.

---

## 1. What the server actually persists

Two things, and nothing else:

| Data | Where | Format |
|---|---|---|
| Authority DB (apps, files metadata, ACLs, folders, tokens, nonces, audit log, backup records, upload jobs, settings) | `TENANT_FS_DB` (default `data/fs.db`) | SQLite 3, WAL mode, foreign keys on |
| Blob content | `TENANT_FS_BLOBS` (default `data/blobs`) | Envelope-encrypted files under `blobs/app_<id>/yyyy/mm/<uuid>` (self-contained `TSFS` header); legacy plaintext blobs are read transparently |

Blobs are **immutable** (written once as UUID, never modified). Tokens are
regenerable (TTL-bounded). This matters for backup consistency: the blob tree
and the DB are snapshotted by the built-in backup as a single consistent unit.

---

## 2. Backup: how it works today

**There is a built-in backup surface.** It is exposed on the loopback admin API:

| Method | Path | Behavior |
|---|---|---|
| POST | `/admin/v1/backups/run` | Synchronous run: DB snapshot (`VACUUM INTO`) + `blobs.tar` + `manifest.json` (per-file sha256). Returns immediately when done. |
| GET | `/admin/v1/backups` | List records, newest first. |
| GET | `/admin/v1/backups/{id}` | Detail incl. `target_path` and the parsed manifest. |
| PATCH | `/admin/v1/backups/config` | `{ schedule?, target?, retention? }`, persisted in the DB. |

A run produces one directory under `TENANT_FS_BACKUP_ROOT` (default
`data/backups`) containing:

- `db.sqlite` — a consistent online snapshot via `VACUUM INTO` (not a raw file
  copy while the server runs).
- `blobs.tar` — the envelope-encrypted app blob trees. Plaintext caches
  (`dec_cache/`), finished export artifacts (`exports/`) and interrupted
  `tmp_*` partials are deliberately excluded; only `app_*` trees are archived.
- `manifest.json` — `backup_id`, `created_at`, per-file `{name, size, sha256}`,
  and a note stating that no key material is included.

Configuration knobs:

- `TENANT_FS_BACKUP_ROOT` (default `data/backups`) — root all targets hang off.
- `TENANT_FS_BACKUP_RETENTION` (default 7, clamp 1–1000) — keep the newest N
  copies; older directories and DB rows are removed.
- `TENANT_FS_BACKUP_SCHEDULE_SECS` (default 0 = off) — when > 0 the background
  maintenance loop fires a run when the interval has elapsed since the last
  backup. An operator can override schedule / target / retention at runtime via
  `PATCH /admin/v1/backups/config` (the DB value wins over the env default).

---

## 3. Where the backup goes (target whitelist)

`target` in `PATCH /admin/v1/backups/config` is a **relative directory name**
under `TENANT_FS_BACKUP_ROOT`. It is validated:

- absolute paths, `..`, `:` and `\` are rejected outright;
- the candidate is canonicalized and must still `starts_with(canonical_root)`
  — this blocks both path traversal and symlink escape (canonicalize resolves
  links).

So backups are scoped to the configured root by construction. If you want
off-site copies, mount/sync the backup root (e.g. `restic` / `rsync` the root
after a run) — the server itself does not yet speak S3 / restic remotes.

---

## 4. Encryption at rest and key policy

Blobs are envelope-encrypted by default (`TENANT_FS_ENCRYPT_BLOBS=true`):

```
[0..4]   "TSFS"  [4] version=1
[5..17]  dek_nonce (12)      [17..65] sealed_dek (48, AES-256-GCM(KEK, dek_nonce, DEK[32]))
[65..77] body_nonce (12)     [77..]  ciphertext = AES-256-GCM(DEK, body_nonce, plaintext)
```

- Every blob gets its own random 256-bit DEK; two encryptions of the same
  plaintext differ byte-for-byte.
- The **KEK = SHA-256(SERVER_SECRET)**, the same derivation used to seal app
  secrets. `SERVER_SECRET` lives only in the deployment environment and is
  **never** written into a backup (DB snapshot, `blobs.tar`, manifest, volume
  snapshot, CI fixture). The manifest explicitly states this.
- Because the sealed DEK travels inside the blob header, a stolen backup
  without `SERVER_SECRET` holds ciphertext that cannot be opened.
- Legacy plaintext blobs (no `TSFS` magic) are served through the plaintext path
  transparently; `migrate_plaintext_blobs()` rewrites them in place to the
  envelope format (idempotent).
- On read, an encrypted blob is materialized to a per-uuid plaintext cache
  under `blob_root/dec_cache/` (atomic swap). That cache is excluded from
  backups and exports; deletion/purge removes the real encrypted file.

**Operator duty: store `SERVER_SECRET` separately and securely.** It is the
single root of trust for both app-secret sealing and blob encryption. Losing
it makes all backups and all sealed app secrets unrecoverable; leaking it (with
a backup) defeats the encryption.

---

## 5. Restore (operator-side procedure)

There is **no restore endpoint** yet. Restore is a manual runbook:

1. Stop the server (or accept that the next step is a fresh boot on a copy).
2. Place the snapshot `db.sqlite` as the new `TENANT_FS_DB`.
3. Unpack `blobs.tar` back into the blob root so the `app_<id>/yyyy/mm/<uuid>`
   layout is restored.
4. Start the server with the **same `SERVER_SECRET`** that produced the backup.
   Without it, sealed app secrets and every envelope blob stay undecryptable.
5. Verify: `GET /admin/v1/apps/{id}/usage` and a test download of a known
   file. If a blob is missing for some row, downloads/export skip it with
   "File content missing." — the DB is the authority, blobs are the content.

Because blobs are immutable and the DB is a single SQLite file, you may also
layer `restic` / `borg` / `rsync` over the backup root after a `run` for
off-site copies — but always pair an off-site backup with a securely stored
copy of `SERVER_SECRET` (kept out of the backup media itself).

---

## 6. Operational notes on the current build

- **Data safety**: SQLite WAL + foreign keys; single-writer mutex serializes
  writes (correct, but the write bottleneck — expect ~1k+ small writes/s).
- **Secret hygiene**: `TENANT_FS_SERVER_SECRET` and `TENANT_FS_ADMIN_TOKEN`
  both have dev defaults; the server now prints a loud startup WARNING for
  **both**. Set both explicitly in production, and store `SERVER_SECRET`
  independently from your backup media.
- **Expiry housekeeping**: the background maintenance loop
  (`TENANT_FS_PURGE_INTERVAL_SECS`, default 600s) prunes nonces, old audit
  rows (`TENANT_FS_AUDIT_RETENTION_DAYS`, default 30), expired `tokens` rows,
  soft-delete tombstones past the grace window (`TENANT_FS_SOFT_DELETE_DAYS`,
  default 7 — physically removing their blobs), finished exports past
  `TENANT_FS_EXPORT_TTL_SECS` (default 86400), and interrupted chunked-upload
  sessions past their TTL.
- **Soft-delete semantics**: `DELETE` immediately rolls quota back and drops
  the file's tokens, but the blob survives the grace window; purge is
  physical. Set `TENANT_FS_SOFT_DELETE_DAYS=0` to purge on the next tick
  (used by tests/E2E).
- **Network posture**: public bind defaults to `0.0.0.0:8080`; admin binds to
  `127.0.0.1` only (and the console static assets are 404 on the public
  router). Put the public port behind TLS (reverse proxy). If you use a proxy
  that rewrites `X-Forwarded-For`, set `TENANT_FS_TRUST_XFF=true`; otherwise
  leave it off so clients cannot spoof IP-bound share tokens.
- **Blobs are encrypted on disk** (envelope KEK/DEK, §4). You still need
  volume-level encryption or an encrypted off-site copy for defense-in-depth.

---

## 7. Feature gaps worth knowing

- No backup **restore** endpoint — restore is the manual runbook in §5.
- No TLS / HSTS termination in-process — terminate at a reverse proxy.
- No malware / antivirus scanning of uploads.
- Single shared `ADMIN_TOKEN` — no operator / auditor role split.
- No webhook / push notification when an export job finishes (poll the status
  endpoint).
- Backup target is local-disk relative; S3 / restic-style remote destinations
  are not yet implemented.
