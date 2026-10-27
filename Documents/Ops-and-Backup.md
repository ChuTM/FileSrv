# Tenant File Server — Operations & Backup Notes

> Applies to the **current implementation** (SQLite + local blob directories).
> Where the finalized roadmap differs, the difference is called out.

---

## 1. What the server actually persists

Two things, and nothing else:

| Data | Where | Format |
|---|---|---|
| Authority DB (apps, files metadata, ACLs, folders, tokens, nonces, audit log) | `TENANT_FS_DB` (default `data/fs.db`) | SQLite 3, WAL mode, foreign keys on |
| Blob content | `TENANT_FS_BLOBS` (default `data/blobs`) | Plain files under `blobs/app_<id>/yyyy/mm/<uuid>` |

Blobs are **immutable** (written once as UUID, never modified). Tokens are
regenerable (TTL-bounded). This matters for backup consistency: the blob tree
and the DB can be snapshotted independently without tearing.

---

## 2. Backup: how is it done today?

**Short answer: there is no built-in backup.**

- The finalized API spec defines a backup surface:
  - `POST /admin/v1/backups/run` — run a backup now
  - `GET /admin/v1/backups` · `/admin/v1/backups/{id}` — list / status
  - `PATCH /admin/v1/backups/config` — `{schedule?, target?, retention?}`
- The finalized roadmap plans restic/borg-style backups (content-addressed,
  encrypted, immutable snapshots, off-site copy, schedule 6h increments + DB
  dump, retention `daily×7 / weekly×4 / monthly×6`).
- **None of that is implemented in `src/`.** There are no backup routes, no
  backup tables, no scheduler. `grep -r backup src/` finds nothing.

So the current backup strategy is what *you* do at the filesystem layer:

```bash
# Consistent-enough manual snapshot (server stopped, or accept WAL replay):
sqlite3 data/fs.db ".backup 'backups/fs-$(date +%F).db'"
rsync -a data/blobs/ backups/blobs/
# Or use restic/borg pointed at data/ (DB + blobs together):
restic -r s3:my-bucket/fs backup data/fs.db data/blobs
```

Because blobs are immutable and the DB is a single SQLite file, `restic` /
`borg` / `rsync` all work fine; the DB should be snapshotted with the SQLite
online backup API (`sqlite3 .backup`) or `VACUUM INTO` rather than a plain
file copy while the server is running.

---

## 3. Can you choose where the backup goes?

**Not through the API.** There is no endpoint that accepts a target.

- The spec's `PATCH /admin/v1/backups/config` includes `target?` — i.e. the
  *designed* answer is "yes, configurable", but it is **not implemented**.
- Today the only knobs are OS-level: you decide the backup destination when
  you run rsync/restic yourself (local disk, NAS, S3, another region…).
- The one built-in data-export feature is **App self-export**
  (`POST /v1/apps/export` → tar of the app's files). It exports *file content
  only* — no ACLs, no metadata beyond path, no audit — and it is per-app, not
  a system backup. It also cannot be given a custom destination; the archive
  is served back to the requester.

**Recommendation if you want API-driven, selectable-destination backups:** the
missing piece is exactly the roadmap's backup module. A minimal implementation
would add:
1. `admin/v1/backups/run` — snapshot DB (`VACUUM INTO` / `.backup`) + tar the
   blob tree (blobs are immutable so this is cheap);
2. `backups/config` — `target` as a filesystem path or `s3://`/`rest:` repo
   URL, `retention`, `schedule`;
3. a lightweight scheduler (the server already has tokio; a 6h interval task
   is trivial);
4. `GET /admin/v1/backups/{id}` status + integrity check (sha256 manifest).
That would make "choose where the backup goes" a `PATCH /backups/config`
away.

---

## 4. Restore

No restore endpoint exists either. Manual restore is:

1. Stop the server.
2. Restore `fs.db` (the snapshot) and the `blobs/` tree (restic restore /
   rsync back).
3. Start the server. `blob_path` columns, tokens, ACLs are all inside the DB,
   so the state returns as a whole.

(If blobs are missing for some rows, downloads/export skip them and return
"File content missing." — the DB is the authority, blobs are the content.)

---

## 5. Operational notes on the current build

- **Data safety**: SQLite WAL + foreign keys; single-writer mutex keeps writes
  serialized (correct, but the write bottleneck — expect ~1k+ small writes/s).
- **Secret hygiene**: `TENANT_FS_SERVER_SECRET` and `TENANT_FS_ADMIN_TOKEN`
  both have dev defaults; the server prints a WARNING for the former but not
  for the admin token — set both explicitly in production.
- **Expiry housekeeping**: nonces and audit rows are pruned by a background
  task every 10 minutes (audit retention: `TENANT_FS_AUDIT_RETENTION_DAYS`,
  default 30). Note: **expired `tokens` rows are not pruned** — tokens are
  soft-checked by `expires_at`, so expired rows accumulate in the DB.
- **Network posture**: public bind defaults to `0.0.0.0:8080`; admin binds to
  `127.0.0.1` only. Put the public port behind TLS (reverse proxy). If you use
  a proxy that rewrites `X-Forwarded-For`, set `TENANT_FS_TRUST_XFF=true`;
  otherwise leave it off so clients cannot spoof IP-bound share tokens.
- **Blobs are plaintext on disk**: the roadmap's at-rest encryption (envelope
  KEK/DEK) is not implemented; encrypt the volume or the backup set if that
  matters for compliance.

---

## 6. Feature gaps worth knowing (API-only today)

- No HTML admin page / dashboard — the whole surface is REST.
- No per-app rate limiting (only quota + payload caps).
- No chunked/resumable upload; no `HEAD`; export is tar-only.
- No webhook/notification on export completion.
