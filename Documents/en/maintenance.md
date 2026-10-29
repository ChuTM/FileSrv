# Maintenance

This document is the operations companion to the file server: what the backup
numbers mean, what to do when something breaks, and the routine checks to keep
it healthy. Code and commands are in English; the structure mirrors
`deploy.md`.

---

## 1. Backup & retention

### 1.1 How backups work

There are two backup mechanisms — don't confuse them:

- **Built-in backup API** (`POST /admin/v1/backups/run`) writes a point-in-time
  copy under `$BACKUP_ROOT` (default `data/backups/`), one directory per backup
  named `bk_<id>`, containing `db.sqlite` + `blobs.tar` + `manifest.json`. The
  Settings page (Backup card) reads this from the API and shows the root, how
  many copies are kept, the retention cap, the total backup bytes, and the
  latest backup id / status / time. Retention is `TENANT_FS_BACKUP_RETENTION`.
- **`scripts/backup.sh`** is an operator-side whole-directory snapshot: it
  copies the database + blob store (and, **by default**, the `.env` file) to a
  destination you choose, so a full restore brings back the data *and* the
  secrets (server secret, admin token, bind settings) together. It is separate
  from the built-in API and is not governed by the retention cap.

### 1.2 What "Retention: 7 copies" means

`.env` sets `RETENTION=7`. This is the **cap on how many backup generations are
kept on disk**. The behaviour is simple:

- At any moment the server keeps **at most `RETENTION` backups** (default 7).
- When a new backup is created and `RETENTION` copies already exist, the
  **oldest** copy is deleted automatically. So you always have the most recent
  7 generations, never an unbounded pile.
- In Settings, "Copies kept" = how many backups exist right now, and
  "Retention" = the configured cap. They read independently: if a backup
  hasn't run yet this period, copies kept can be below the cap.
- **To keep more history**, raise `RETENTION` in `.env` (uses more disk).
  **To save space**, lower it. The value is read at startup, so change it and
  restart the service.
- **External snapshots are outside this cap.** `scripts/backup.sh` writes to an
  arbitrary destination you choose (e.g. an external drive). That directory is
  NOT under `$BACKUP_ROOT`, so `RETENTION` does not apply to it — the server
  never counts or prunes it; you manage those snapshots yourself.

### 1.3 Restoring

- `scripts/restore.sh` unpacks a backup back into the live `data/` (or a
  target you choose). See `deploy.md` → "Backup / restore" for the exact
  invocation and safety notes. Always test a restore into a scratch directory
  before you rely on it in anger.

---

## 2. Routine check plan

### Daily
- Confirm the service is up:
  `curl http://127.0.0.1:8080/healthz` should return `OK`.
- Check the latest backup timestamp is recent (not silently stale).
- Glance at disk usage; the blob store grows with every upload.

### Weekly
- Open Settings → **Storage Maintenance** and run **Audit files (integrity)**
  to verify every blob on disk is present with the right size and SHA-256.
- Confirm "Copies kept" is within retention and backups are still being made.
- Check free disk space vs the sum of `data/fs.db` + `data/blobs` +
  `data/backups`.

### Monthly
- Test a full restore into a scratch location end-to-end.
- Review the admin audit log for failed or suspicious requests.
- Rotate the server secret (section 3.4) if it has been exposed or shared.

---

## 3. Troubleshooting

### 3.1 The service won't start

- Read the startup log: `./scripts/start.sh` prints the resolved bindings.
- Common causes:
  - Port already in use → stop the old process first (`pkill -9 -f
    filesrv`), then start.
  - `.env` missing or malformed → run `./scripts/setup-env.sh` (it will not
    overwrite an existing `.env`), then check `TENANT_FS_DB` and
    `TENANT_FS_BLOBS` point at writable paths.
  - DB locked / corrupt → see 3.5.

### 3.2 Backup failed

- Check there is room under `$BACKUP_ROOT` and on the volume holding it.
- Check the `.env` was readable (a backup includes `.env`; if it can't be read
  the backup may still proceed without it — restore then has no secrets).
- Confirm the previous backup directory isn't locked by another process.
- If a backup is half-written, `retention` will clean the oldest full copy,
  not the in-flight one; remove a partial `bk_*` directory manually only after
  confirming no process is writing to it.

### 3.3 Audit reports "missing" files (orphan blobs)

`Audit files` walks every file record and checks its blob exists on disk with
the expected size and SHA-256. The result fields mean:

| Field | Meaning |
|---|---|
| `checked` | file records scanned |
| `ok` | blobs present and correct |
| `missing` | DB has a record but the blob file is **gone from disk** |
| `size_mismatch` | blob exists but its byte size differs from the record |
| `sha_mismatch` | blob exists but its hash differs from the record |
| `bytes_ok` | total verified bytes |

**`missing` is the important one.** It means the database still references a
blob file that no longer exists on disk — typically the result of a manual
cleanup of `data/blobs`, an interrupted wipe, or a partially restored backup.
The file content is **permanently lost** and cannot be recovered from disk. To
clean up:

1. Find which app owns the missing blob:
   `sqlite3 data/fs.db "SELECT app_id, blob_path FROM files WHERE blob_path LIKE '<sample>';"`
2. Confirm the app and that you accept the loss.
3. Remove the orphan file record(s) so the database no longer references files
   that don't exist (a deliberate, manual step — there is intentionally no
   automatic deletion of user data).
4. Re-run Audit files; `missing` should now be `0`.

> `size_mismatch` / `sha_mismatch` usually mean corruption or a partial write;
> restore the blob from a backup if one exists, otherwise treat as lost.

### 3.4 Rotating secrets — two different things

There are **two separate keys** that can be rotated. Do not confuse them.

**Site-wide: the server secret (`TENANT_FS_SERVER_SECRET`)**

- Use `scripts/rotate-secret.sh`. It backs up `.env`, generates a new
  `TENANT_FS_SERVER_SECRET`, and rewrites `.env`.
- The server secret derives the KEK that seals **all** blobs and **every**
  app's stored secret, so rotating it is a **site-wide** operation:
  - every previously issued HMAC signature / user JWT becomes invalid
    immediately — update the backends before you continue.

**What happens during a server-secret rotation** (`rotate-secret.sh`):

1. Reads the current secret from `.env` (or `--old`), then generates a new
   random 32-byte secret with `openssl rand -base64 32`.
2. Shows a risk disclosure and requires you to type **yes twice** (double
   confirmation).
3. Ensures the server is stopped (`--stop`, or stop it yourself).
4. Takes a **safety snapshot**: `data/.pre-rotate-<ts>.fs.db` and
   `.env.pre-rotate-<ts>`, so you can roll back.
5. Runs the `rekey` tool. Thanks to envelope encryption this only
   **re-seals each blob's per-file DEK** from the OLD secret to the NEW one —
   the file payloads are never re-encrypted (no re-upload, cheap). Blobs that
   can't be unwrapped with the OLD secret are skipped (reported as
   "unwrappable") and stay unreadable.
6. Updates `.env` **only after re-keying fully succeeds** (sed replaces the
   `TENANT_FS_SERVER_SECRET` line, then `chmod 600`). A mid-run failure leaves
   the OLD secret active, so it is retryable.
7. To roll back, restore a `.pre-rotate-<ts>` snapshot, or re-run with
   `--old <new> --new <old>` to reverse it.

**Per-app: an app's own secret (`app_secret`)**

- The **Rotate Secret** action (admin UI row menu, or
  `filesrv admin app rotate-secret <id>`) regenerates **only that one app's**
  access credential.
- It is lightweight and isolated: it writes a new random secret sealed with
  the (unchanged) server secret, and touches only that app. **No `blob_rekey`,
  no JWT impact, no effect on other apps.**
- Use it when a single app's key is leaked, or that app's client should be
  re-keyed.

**What happens during an app-secret rotation:**

1. An authenticated admin targets the app by id.
2. `crypto::random_secret()` generates a new random 32-byte secret (base64).
3. It is **sealed** with the (unchanged) server secret's KEK and written into
   the app's `secret_sealed` row, overwriting the old value.
4. The old secret is gone from the DB, so **every HMAC signature made with the
   old secret now fails** — that app's client must switch to the new secret
   (the admin receives the plaintext to hand over). App requests are signed
   with the secret via `app_key` + timestamp + nonce (HMAC), not JWT.
5. Nothing else changes: server secret untouched, no blob re-key, other apps
   and user JWTs unaffected. It is a single-row, single-secret swap.

**Admin token (`TENANT_FS_ADMIN_TOKEN`) — what it is**

- It is the **single management credential** for the admin console, stored in
  `.env`. The admin API binds only to `127.0.0.1:8081` (loopback), so the token
  is used on the machine / over SSH and never travels on the public network.
- It authenticates the admin web UI login (the token lives in the page's
  `sessionStorage`) and every `filesrv admin …` CLI command. It is checked
  with a constant-time compare to resist timing attacks.
- It grants **full admin power**: create / disable / archive / wipe apps, add
  users, manage groups, run backups, read the audit log, rotate keys.
- Rotate it separately with `filesrv admin rotate-token` — the CLI backs up,
  rotates, prints the new token and rewrites `.env`. Confirm the risk prompt,
  then update anything that held the old token.

### 3.5 Database corrupt or locked

- Stop the service first.
- If SQLite reports corruption, restore the database from the newest backup
  (`restore.sh`) — this is why backups include the DB.
- Never delete `data/fs.db` while the service is running (SQLite locking).
- After a restore, run Audit files to confirm blobs still line up with the
  restored records.

### 3.6 Disk full

- The server refuses writes when there is no space; uploads fail cleanly.
- Free space by: lowering `RETENTION`, wiping archived apps (Wipe out removes
  their blobs), or moving `data/blobs` to a larger volume via `TENANT_FS_BLOBS`.
- After freeing space, run Audit files to confirm the blob store is intact.

### 3.7 Admin token lost

- The token lives only in `.env` and the admin session; it is never stored on
  disk elsewhere. If lost, rotate it from the machine (see 3.4) rather than
  guessing.
- The admin API is bound to localhost only (`127.0.0.1:8081`); treat it as a
  loopback control surface.

### 3.8 Updating the web UI / the binary

The admin console static assets (`login.html`, `dashboard/*.html`, `app.js`,
`dashboard.css`, `style.css`, `gsap.min.js`) are embedded into the binary **at
compile time** via `include_str!` in `src/admin_ui.rs`. They are not read from
disk at runtime, so editing a file alone changes nothing — `start.sh` only
launches the already-built binary, it never recompiles.

Update steps:

1. Edit the files under `src/admin_ui/static/…`.
2. For any static asset you changed, bump its cache-busting version query string
   (otherwise the browser keeps the old copy). Example:
   ```bash
   sed -i '' 's/app.js?v=16/app.js?v=17/g' \
     src/admin_ui/static/login.html src/admin_ui/static/dashboard/*.html
   # repeat with dashboard.css?v=N when the CSS changed
   ```
3. Rebuild — this is the step that bakes the files into the binary:
   ```bash
   cargo build --release
   ```
4. Restart:
   ```bash
   pkill -9 -f 'target/release/filesrv'; sleep 2
   nohup ./scripts/start.sh > /tmp/filesrv.log 2>&1 &
   ```

Rust-only changes (routing/logic) need the same build + restart; the version
bump applies only to static assets.

---

## 4. Quick reference

| Concern | Where it lives |
|---|---|
| Database | `data/fs.db` (`$TENANT_FS_DB`) |
| Blob store | `data/blobs` (`$TENANT_FS_BLOBS`) |
| Backups | `data/backups` (`$BACKUP_ROOT`) |
| Secrets / config | `.env` |
| Backup script | `scripts/backup.sh` |
| Restore script | `scripts/restore.sh` |
| Secret rotation | `scripts/rotate-secret.sh` |
| Admin CLI | `filesrv admin …` |
| Integrity audit | Settings → Storage Maintenance → Audit files |
