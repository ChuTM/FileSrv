# Tenant File Server — Operations & Backup Notes

> Applies to the **current implementation** (SQLite + local blob directories,
> envelope-encrypted blobs, built-in backup API). Where the finalized roadmap
> differs, the difference is called out.

---

## 1. What the server actually persists

Everything lives under the working directory by default (the whole tree is the
"data" directory you copy for a snapshot backup, §5.5):

```
data/                          <- the one tree to back up
├── fs.db                      <- TENANT_FS_DB     (SQLite, WAL mode)
├── blobs/                     <- TENANT_FS_BLOBS  (all user file content)
│   ├── app_<id>/yyyy/mm/<uuid>   envelope-encrypted blob files ("拆散" layout)
│   ├── dec_cache/               re-creatable plaintext cache (TTL-swept, §4)
│   ├── exports/                 finished tar/zip artifacts (TTL-swept)
│   └── tmp_*                    interrupted-upload partials (swept at boot)
└── backups/                   <- TENANT_FS_BACKUP_ROOT (built-in backup output)
```

| Data | Where | Format |
|---|---|---|
| Authority DB (apps, files metadata, ACLs, folders, tokens, nonces, audit log, backup records, upload jobs, settings) | `TENANT_FS_DB` (default `data/fs.db`) | SQLite 3, WAL mode, foreign keys on |
| Blob content | `TENANT_FS_BLOBS` (default `data/blobs`) | Envelope-encrypted files under `blobs/app_<id>/yyyy/mm/<uuid>` (self-contained `TSFS` header); legacy plaintext blobs are read transparently |
| Built-in backup output | `TENANT_FS_BACKUP_ROOT` (default `data/backups`) | Per-run directories with `db.sqlite` + `blobs.tar` + `manifest.json` |

So yes: **both the database and every user file already live under `data/`**,
and user files are already split into the `app_<id>/yyyy/mm/<uuid>` layout on
disk. Nothing else is needed for a file-level restore.

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

**Locking note (F3 fix):** a run only holds the global DB mutex for the short
`VACUUM INTO` snapshot and the bookkeeping updates. The slow blob-tree tar is
archived **without** the DB lock, so a big backup no longer stalls every API
request for its whole duration.

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
  The cache is now **TTL-swept** (`TENANT_FS_DEC_CACHE_TTL_SECS`, default
  86400): entries older than the TTL are removed by the maintenance loop, so
  plaintext does not persist on disk indefinitely (F2 fix).

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

## 5.5 The simplest option: snapshot the whole `data/` directory

> A ready-to-use script ships with the repo: `scripts/backup.sh <目标路径>
> [--data <data目录>] [--secret-out <密钥文件>] [--no-verify]`. It performs
> the WAL checkpoint, the rsync below, an optional `integrity_check`, and an
> optional separate save of `SERVER_SECRET`. The manual steps are equivalent.

Since the DB and every blob already live under one directory (§1), the
lowest-friction backup is **a whole-directory copy of `data/`** — no built-in
API involved. Restore is then literally "copy it back and start the server".

**Backup (`data/` → backup media):**

1. Stop the server, or run `sqlite3 data/fs.db 'PRAGMA wal_checkpoint(TRUNCATE);'`
   right before copying if you must stay online (a live file copy of a WAL-mode
   DB is not guaranteed consistent).
2. Copy the tree, excluding the re-creatable / nested parts:
   ```bash
   rsync -a --delete \
     --exclude 'backups/'       # nested built-in backup output
     --exclude 'blobs/dec_cache/'   # plaintext cache, re-created on demand
     --exclude 'blobs/exports/'     # finished export artifacts, re-creatable
     --exclude 'blobs/tmp_*'        # interrupted-upload partials
     data/  /backup/media/data-$(date +%F)/
   ```
3. Store `SERVER_SECRET` **separately** from the backup media (it is the only
   key needed to decrypt everything; it must NOT ride inside the copy).

**Restore (backup media → `data/`):**

1. Stop the server.
2. Replace the whole `data/` directory with the copy (or unpack it to the same
   path). Excluded sub-directories (`dec_cache/`, `exports/`, `tmp_*`,
   `backups/`) are simply absent or re-created by the server on demand.
3. Start the server with the **same `SERVER_SECRET`** and the same
   `TENANT_FS_DB` / `TENANT_FS_BLOBS` paths that the backup was taken from.
   The service starts directly on the restored files — no re-import, no
   migration step.
4. Verify: `GET /admin/v1/apps/{id}/usage` and a test download.

Why this is safe: blobs are immutable and keyed by UUID, the DB is a single
SQLite file, and both live under `data/`. Excluding `dec_cache/` / `exports/`
keeps plaintext out of the backup media (preserving the at-rest-encryption
story) without losing anything — both are re-created on demand.

---

## 6. Operational notes on the current build

- **Data safety**: SQLite WAL + foreign keys; single-writer mutex serializes
  writes (correct, but the write bottleneck — expect ~1k+ small writes/s).
- **Secret hygiene**: `TENANT_FS_SERVER_SECRET` and `TENANT_FS_ADMIN_TOKEN`
  both have dev defaults; the server prints a loud startup WARNING for **both**
  and now **refuses to start** while either is the dev default, unless
  `TENANT_FS_DEV_ALLOW_DEFAULT_SECRETS=true` is set (dev-only escape hatch —
  never in production). Set both explicitly in production, and store
  `SERVER_SECRET` independently from your backup media.
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
  router). The server now **refuses to start** on a non-loopback admin bind
  (F6 fix) unless `TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN=true` is set explicitly —
  that override is NOT recommended. Put the public port behind TLS (reverse
  proxy). If you use a proxy that rewrites `X-Forwarded-For`, set
  `TENANT_FS_TRUST_XFF=true`; otherwise leave it off so clients cannot spoof
  IP-bound share tokens.
- **Rate limiting**: downloads (GET/HEAD `/v1/download/{token}`) now count
  against the same per-app budget as upload/generate/export
  (`TENANT_FS_RATE_LIMIT_PER_MIN`, default 120/min) — a hot link cannot exhaust
  server I/O with unbounded token traffic (F7 fix).
- **Download audit (opt-in)**: by default a successful download is not audited
  (keeps the log small on high-read workloads). Set
  `TENANT_FS_AUDIT_DOWNLOADS=true` to record a `download` audit row per GET —
  useful when a per-download trail is required for sensitive files. Old rows are
  still pruned per `TENANT_FS_AUDIT_RETENTION_DAYS`.
- **User directory**: users are provisioned by the operator via
  `POST /admin/v1/apps/{id}/users` (admin console: "用戶" button on each app);
  an app can also still vouch for a user at upload time via `X-User-Id`.
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
- **Large-file memory**: an encrypted blob is decrypted by reading the whole
  file into memory (same for a chunked-upload finalize). Under heavy concurrency
  with large files this raises RAM usage. Mitigations today: keep
  `max_payload_bytes`/quota caps sensible and size host RAM accordingly;
  streaming decryption is future work.
