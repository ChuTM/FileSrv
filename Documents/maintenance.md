# Maintenance & Operations Runbook — filesrv

> Operational reference for the multi-tenant file server. Covers what to do when
> things break, plus a routine-check schedule. Companion docs:
> [`Documents/Ops-and-Backup.md`](Ops-and-Backup.md) (data & key policy),
> [`Documents/en/deploy.md`](en/deploy.md) / [`Documents/zh/deploy.md`](zh/deploy.md)
> (Linux deployment), `Documents/en|zh/api.md` (app-facing API),
> `development/admin-api.md` (admin API).

All commands assume a **Linux** target (the deployment environment). On the
dev Mac they work identically, but paths/init style may differ.

---

## 1. Quick reference cards

### 1.1 Health check & restart

```bash
# health (no credentials needed)
curl -s http://127.0.0.1:8080/healthz            # -> OK
# or via CLI
sh scripts/filesrv-cli.sh health

# restart
pkill -9 -f filesrv ; sleep 3
pgrep -f 'target/release/filesrv' || echo "stopped"   # must print "stopped"
nohup ./scripts/start.sh > /tmp/tenant-fs.log 2>&1 &
sleep 3; curl -s http://127.0.0.1:8080/healthz                  # -> OK
```

### 1.2 Backup & restore (fast path)

```bash
# BACKUP — .env is backed up by DEFAULT (into the media). Recommend keeping
# credentials OUTSIDE the media as well:
./scripts/backup.sh /backup/tenant-fs \
    --env-out ~/.secrets/tenant-fs.env \
    --secret-out ~/.secrets/tenant-fs.server_secret
#     .env goes into the media by default; add --no-env to keep it out.

# SIMPLEST one-dir restore (backup with .env inside):
./scripts/backup.sh /backup/tenant-fs --include-env   # (already the default)

# RESTORE — use the helper script (stops server, snapshots current state,
# copies data + .env back, verifies integrity):
./scripts/restore.sh /backup/tenant-fs --stop

# ROTATE SERVER_SECRET in place (re-seals every DEK, payloads untouched):
./scripts/rotate-secret.sh --stop
```

### 1.3 Symptom → section index

| Symptom | Go to |
|---|---|
| Server will not start | §6.1 |
| `/healthz` not `OK` | §6.2 |
| Disk full | §6.3 |
| SQLite locked / corrupt / WAL trouble | §6.4 |
| Files fail to decrypt / integrity errors | §6.5 |
| Backup failed | §6.6 |
| Restore failed | §6.7 |
| Credential leaked | §6.8 |
| Suspicious activity | §6.9 |
| High CPU / memory / traffic | §6.10 |
| Upgrade broke it | §6.11 |
| Admin UI blank / missing assets | §6.12 |
| Upload / download errors | §6.13 |
| Signature / timestamp rejected | §6.14 |
| Accidental data deletion | §6.15 |

---

## 2. Architecture & data layout (what you maintain)

- **Single process** `target/release/filesrv`, two listeners:
  - `TENANT_FS_PUBLIC_BIND` (default `0.0.0.0:8080`) — app-facing API +
    `/healthz` + `/.well-known/security.txt`.
  - `TENANT_FS_ADMIN_BIND` (default `127.0.0.1:8081`) — admin API + admin UI
    (loopback only).
- **Data directory** (`TENANT_FS_DATA`, default `./data`):
  - `fs.db` (SQLite, WAL mode) — apps, users, groups, files/folders metadata,
    ACLs, audit log.
  - `blobs/app_{app_id}/yyyy/mm/<storage_uuid>` — file content, encrypted at
    rest with `SERVER_SECRET`; each file is sharded into its own directory tree.
- **Secrets & config** live in `.env` (see §7.2): `SERVER_SECRET` (encryption
  root key, **must stay identical across backup→restore**), `ADMIN_TOKEN`,
  binds, DB/blob paths, backup settings.
- **CLI** `scripts/filesrv-cli.sh` — admin ops over the loopback admin API;
  non-sensitive `health`/`version` need no token.
- **Backups** (`TENANT_FS_BACKUP_ROOT`, default `data/backups`) hold
  `{db.sqlite, blobs.tar, manifest.json}`; the standalone `backup.sh` produces
  a whole-directory snapshot instead (`fs.db + blobs/... + optional .env`).

---

## 3. Backups — including `.env`

### 3.1 What a full backup MUST contain

| Item | Why | Where |
|---|---|---|
| `data/fs.db` | all metadata, users, ACLs, audit | snapshot root |
| `data/blobs/` | all file content (encrypted) | snapshot root |
| **`.env`** | `SERVER_SECRET`, `ADMIN_TOKEN`, binds/settings | **must** be captured (see below) |
| `backup-manifest.txt` | provenance, time, env location | snapshot root |

> `.env` is easy to forget: it lives at the **project root**, outside `data/`.
> A backup of `data/` alone restores blobs and metadata but leaves you without
> the `SERVER_SECRET` needed to decrypt them.

### 3.2 How to run a backup **together with** `.env`

`.env` is backed up **by default**: `backup.sh` copies it into the backup media
as `<dest>/.env` (chmod 600). Use `--no-env` to keep it out of the media. Choose
the option below per your risk tolerance:

**Option A — Recommended: `.env` kept OUTSIDE the backup media**
(`--env-out <file>`). The `.env` is copied to a separate trusted location
(chmod 600), never into the media. If the media leaks, no credentials leak.
Combined with the default in-media copy, this is belt-and-braces.

```bash
./scripts/backup.sh /backup/tenant-fs \
    --env-out ~/.secrets/tenant-fs.env \
    --secret-out ~/.secrets/tenant-fs.server_secret
```

**Option B — Default: `.env` travels INSIDE the backup** (`--include-env`,
already on by default). The `.env` is copied to `<dest>/.env` (chmod 600).
Restore is then literally "copy the directory back". Only keep this default if
the backup media is trusted/encrypted (e.g. an encrypted volume or an object
store you control), because `.env` holds `SERVER_SECRET` and `ADMIN_TOKEN`.

```bash
./scripts/backup.sh /backup/tenant-fs              # .env in the media (default)
./scripts/backup.sh /backup/tenant-fs --no-env     # keep .env out of the media
```

**Option C — fully manual** (when you are already staging a directory):

```bash
pkill -9 -f filesrv; sleep 3            # for a consistent snapshot
rsync -a --exclude backups/ --exclude 'blobs/dec_cache/' \
      --exclude 'blobs/exports/' --exclude 'blobs/tmp_*' \
      ./data/ /backup/tenant-fs/
cp .env /backup/tenant-fs.env                     # separate, outside the media
```

The `backup-manifest.txt` records `env-in-backup: yes|no` and `env-out:` so you
can always tell later where the environment went.

### 3.3 Restore — step by step

**Fast path — use the `restore.sh` helper** (stops the server, snapshots the
current state, copies data + `.env` back, verifies integrity, then tells you to
start):

```bash
./scripts/restore.sh /backup/tenant-fs --stop
# options: --data <dir>, --env <file> | --no-env, --no-backup, --dry-run, -y
```

**Manual equivalent** (if you prefer to drive it yourself):

1. **Stop the server** and confirm it is down:
   ```bash
   pkill -9 -f filesrv; sleep 3; pgrep -f filesrv || echo stopped
   ```
2. **Restore the data tree** (from a `backup.sh` snapshot):
   ```bash
   rsync -a --exclude backup-manifest.txt --exclude .env /backup/tenant-fs/ ./data/
   ```
3. **Restore `.env`** — pick the matching source:
   - If you used `--include-env` (default): `cp /backup/tenant-fs/.env ./.env`
   - If you used `--env-out`: `cp ~/.secrets/tenant-fs.env ./.env`
   - If you used `--secret-out` only: put the saved `SERVER_SECRET` back into
     your existing `.env`.
4. **Verify the DB** before starting:
   ```bash
   sqlite3 data/fs.db "PRAGMA integrity_check;"   # -> ok
   ```
5. **Start and health-check**:
   ```bash
   nohup ./scripts/start.sh > /tmp/tenant-fs.log 2>&1 &
   sleep 3; curl -s http://127.0.0.1:8080/healthz   # -> OK
   ```
6. **Smoke test one download** (decrypt path) for an app you know exists.

> **Critical**: the `SERVER_SECRET` used at start time **must equal** the one
> that produced the backup. If it differs, every blob decryption fails
> (see §6.5). Rotating `SERVER_SECRET` is now safe and in-place — see §4.4.

### 3.4 Verify a backup / restore drill

- After every backup: confirm `backup-manifest.txt` exists and the expected
  files are present (`ls /backup/tenant-fs`).
- SQLite check on the copy: `sqlite3 /backup/tenant-fs/fs.db "PRAGMA integrity_check;"`.
- **Monthly drill**: restore into a scratch dir on another host/container,
  start on a different port, upload + download one file. Prove the backup is
  actually usable, not just present.

---

## 4. Routine operations

### 4.1 Start / stop / restart

```bash
# start (daemonised)
nohup ./scripts/start.sh > /tmp/tenant-fs.log 2>&1 &

# stop
pkill -9 -f filesrv; sleep 3
pgrep -f filesrv || echo stopped

# restart = stop then start (see §1.1)
```

### 4.2 Logs

- Startup banner + all requests go to the file you redirected at launch
  (e.g. `/tmp/tenant-fs.log`). Inspect:
  ```bash
  tail -f /tmp/tenant-fs.log
  grep -iE 'error|warn|denied|failed' /tmp/tenant-fs.log | tail -50
  ```
- The **audit log** is in the DB, query via CLI:
  ```bash
  sh scripts/filesrv-cli.sh admin audit --app-id <N> --since 86400
  ```

### 4.3 Update the server (new binary + DB migration)

1. Stop the server.
2. Back up first (at minimum `data/fs.db` + `.env`).
3. Build or copy in the new `target/release/filesrv`.
4. Migrations are **idempotent** (`CREATE TABLE IF NOT EXISTS …`); they run on
   the next start. Start the server and confirm the log shows no migration
   error and `/healthz` returns `OK`.
5. Run the relevant subset of `cargo test --release` on the new build before
   production deploy.

### 4.4 Rotate `SERVER_SECRET`

`SERVER_SECRET` is the KEK (SHA-256 of it) that seals each blob's per-file DEK.
Thanks to envelope encryption, rotation is now **in-place and lossless**: the
`rotate-secret.sh` script stops the server, snapshots `fs.db` + `.env`, runs the
`rekey` tool (re-seals every DEK from the old secret to the new one — the file
payloads are never re-encrypted), then updates `.env`. No re-upload.

```bash
./scripts/rotate-secret.sh --stop            # new random secret, stops server
./scripts/rotate-secret.sh --old <s> --new <s> --stop --dry-run   # preview
# options: --old/--new/--blobs/--data/--env/--no-backup/--dry-run
```

Notes:
- **Unwrappable blobs**: if some blobs were encrypted under an **older** secret
  that no longer matches (e.g. `.env` was regenerated once before), `rekey`
  reports them as `unwrappable` and leaves them untouched — they are not
  decrypted by the current secret and cannot be re-keyed. Check the summary;
  those files are effectively already lost unless the older secret is recovered.
- **Rollback**: `rotate-secret.sh` leaves a `--pre-rotate-<ts>` snapshot of
  `fs.db` and `.env`. To undo, restore that `.env` and re-run rotate with
  `--old <new> --new <old>`.
- Practical guidance: rotate when you believe the key leaked, or on a schedule;
  keep the old secret safe so you can always roll back.

### 4.5 Rotate `ADMIN_TOKEN`

Low-risk, instant:

```bash
./scripts/setup-env.sh   # generates a new SERVER_SECRET *and* ADMIN_TOKEN —
                         # see note, this also changes SERVER_SECRET, so if you
                         # only want ADMIN_TOKEN, edit .env directly:
# edit .env: TENANT_FS_ADMIN_TOKEN=<new value>
pkill -9 -f filesrv; sleep 3; nohup ./scripts/start.sh > /tmp/tenant-fs.log 2>&1 &
```

> `setup-env.sh` regenerates **both** secrets and never overwrites an existing
> `.env` (it warns and exits). To rotate only `ADMIN_TOKEN`, edit `.env` by
> hand, then restart.

### 4.6 Add / delete an app or user

```bash
# apps
sh scripts/filesrv-cli.sh admin app create <name>
sh scripts/filesrv-cli.sh admin app set <id> --enabled=false    # disable
sh scripts/filesrv-cli.sh admin app delete <id>                  # soft-delete

# users (pre-provision so their JWT is accepted)
sh scripts/filesrv-cli.sh admin user add <app_id> <user_id>

# groups
sh scripts/filesrv-cli.sh admin group create <app_id> <name>
sh scripts/filesrv-cli.sh admin group member add <app_id> <name> <user_id>
```

---

## 5. Routine check schedule

### 5.1 Daily

- [ ] `curl -s http://127.0.0.1:8080/healthz` returns `OK`.
- [ ] Server process alive: `pgrep -f 'target/release/filesrv'`.
- [ ] No new `error`/`denied`/`failed` lines in the log tail.
- [ ] Disk usage within threshold: `df -h <data_dir>` (see §6.3 for the
       cleanup playbook).
- [ ] Any scheduled backup job finished and wrote a manifest.

### 5.2 Weekly

- [ ] **Verify** the latest backup: `sqlite3 <backup>/fs.db "PRAGMA integrity_check;"`
  → `ok`.
- [ ] Check disk **growth trend** over the week (per-app usage via
  `admin app usage`), confirm no app is approaching quota silently.
- [ ] Review the audit log for unexpected actions
  (`admin audit --since 604800`): look for failed logins, ACL changes,
  deletions, token revokes.
- [ ] Confirm backups rotate correctly (old ones pruned per `RETENTION`).

### 5.3 Monthly

- [ ] **Restore drill** on a scratch host/container (see §3.4): prove a backup
  can actually be restored and files decrypted.
- [ ] Confirm the admin UI loads (`curl -s http://127.0.0.1:8081/admin/` is
  HTML, not 404/500).
- [ ] Check for new releases / CVEs in the Rust dependency set; rebuild if any
  fix is adopted.
- [ ] Review bind addresses: public on `0.0.0.0:8080`, admin still loopback.
- [ ] Sanity-check a file ACL with a group reference still behaves
  (`g:<group>` → member can read, non-member denied).

### 5.4 Quarterly

- [ ] Consider rotating `ADMIN_TOKEN` (cheap) and app secrets
  (`admin app rotate-secret`) where policy requires.
- [ ] Full capacity review: projected growth vs. quota and disk.
- [ ] Re-run a short load/stress test against a staging instance (burst
  upload + download) to confirm no regression.
- [ ] Re-check TLS/termination certificates if the service sits behind a
  reverse proxy.
- [ ] Confirm `.env` backups are themselves backed up (off-site copy of the
  secret file).

---

## 6. Runbook — what to do when X happens

### 6.1 Service will not start

**Symptoms**: process exits immediately; log shows bind/setup errors; port
already in use.

**Diagnose**:
```bash
tail -30 /tmp/tenant-fs.log
pgrep -f 'target/release/filesrv'     # already running?
ss -ltnp | grep -E '8080|8081'                  # port held by a stale process?
```

**Handlers**:
1. **Port in use by a stale process**: `pkill -9 -f filesrv; sleep 3`
   then confirm `pgrep` is empty before restarting.
2. **`.env` missing / wrong permissions**: ensure it exists and is `600`
   (`ls -l .env`). Re-create only if you truly lost it — note that a newly
   generated `SERVER_SECRET` will **not** decrypt existing blobs (§6.5).
3. **Binary not executable / missing**: `chmod +x target/release/filesrv`
   or rebuild `cargo build --release`.
4. **Config error**: check the startup banner against expected binds; fix
   `.env`, then restart.

### 6.2 `/healthz` not `OK`

**Symptoms**: `curl /healthz` non-200, empty, or hangs.

**Diagnose**: log tail; confirm the process is listening
(`ss -ltnp | grep 8080`); try `curl -v`.

**Handlers**:
1. Process down → §6.1.
2. Process up but not answering → likely hung (DB lock / deadlock). Capture a
   stack/thread dump if possible, then restart (§1.1).
3. Wrong port — verify `TENANT_FS_PUBLIC_BIND` in `.env` matches what you
   probe.

### 6.3 Disk full

**Symptoms**: `df -h` shows `data` volume at/near 100%; uploads fail; audit
table growth.

**Handlers** (in order of safety):
1. **Prune old backups**: check `data/backups/` and your snapshot destination;
   enforce `RETENTION`; delete superseded snapshots.
2. **Purge cache dirs** (always safe): `blobs/dec_cache/`, `blobs/exports/`,
   `blobs/tmp_*`.
3. **Enable/disable apps** to stop growth: `admin app set <id> --enabled=false`
   or lower quota via `admin app set <id> --quota-bytes=…`.
4. **VACUUM the DB** (needs free space ~= DB size): stop server, `sqlite3
   data/fs.db "VACUUM;"`, restart.
5. If still critical, move blobs to a larger volume and point `TENANT_FS_BLOBS`
   there (update `.env`, restart).

> Avoid deleting `blobs/` directly — that is the data. Prefer quota + prune.

### 6.4 Database locked / corrupt / WAL trouble

**Symptoms**: `SQLITE_BUSY` on writes; `PRAGMA integrity_check` reports errors;
log shows `database is locked`.

**Handlers**:
1. **Busy/locked** — usually a long-running transaction or a hung process:
   stop the server, delete stale `-wal`/`-shm` only after confirming no process
   is writing, then restart. (With a single process, lock contention is rare.)
2. **Corrupt** — stop server, **back up the damaged DB first** (`cp
   data/fs.db data/fs.db.corrupt`), then attempt recovery:
   ```bash
   sqlite3 data/fs.db ".recover" > recovered.sql
   sqlite3 data/fs.db < recovered.sql          # write into a fresh DB
   sqlite3 data/fs.db "PRAGMA integrity_check;"
   ```
   If `.recover` cannot help, restore from the last good backup (§3.3) and
   accept the data delta.
3. **WAL not checkpointed** during an unclean kill — on next start SQLite
   replays the WAL automatically; if that fails, follow step 2.

### 6.5 Blob decrypt failure / `SERVER_SECRET` mismatch

**Symptoms**: downloads return errors or garbage; log shows decryption/`
integrity` failures after a restore or a secret change.

**Handlers**:
1. Confirm the running `SERVER_SECRET` equals the one used to create the data:
   compare `.env` against the saved `--secret-out` file / `--env-out`.
2. If it changed (rotate or `.env` regeneration), you must restore the old
   secret — **do not** re-encrypt ad hoc. Put the original value back, restart.
3. If the change was an intentional rotation, use `./scripts/rotate-secret.sh`
   (re-seals every DEK in place — see §4.4) rather than editing `.env` by hand,
   which would orphan the blobs.
4. If the original is lost and blobs are encrypted: the data is unrecoverable
   (by design, to protect it). Restore from a backup that also captured the
   matching `.env`.

### 6.6 Backup failed

**Symptoms**: `backup.sh` exits non-zero; WAL checkpoint warning; integrity
check on the copy fails; manifest missing.

**Handlers**:
1. **WAL checkpoint warning** — the server was writing during backup. Stop the
   server, re-run the backup, restart.
2. **Destination inside the data dir** — the script refuses; choose another
   destination.
3. **Integrity check failed on the copy** — do not use it. Investigate the
   source DB (§6.4), fix, re-backup.
4. **No `.env` found** — confirm `.env` exists at the expected path or pass
   `--env <file>` explicitly.

### 6.7 Restore failed

**Symptoms**: server starts but files missing/wrong; integrity fails; secret
mismatch.

**Handlers**:
1. **Secret mismatch** → §6.5 (restore the matching `.env`/secret).
2. **Incomplete copy** — re-sync; confirm `fs.db` and `blobs/` are both present
   (`ls`, `du`).
3. **DB integrity fail** after restore — the backup was bad (§6.6); try an
   older snapshot.
4. **Smoke test fails** — restore step 6 in §3.3: verify one real download, not
   just `/healthz`.

### 6.8 Credential leak (`SERVER_SECRET`, `ADMIN_TOKEN`, app secret)

**Handlers**:
1. **`ADMIN_TOKEN` leaked** — rotate immediately (§4.5). Cheap, no data impact.
2. **App secret leaked** — `admin app rotate-secret <id>`; the old secret is
   invalidated immediately.
3. **`SERVER_SECRET` leaked** — worst case: every blob can be decrypted by the
   attacker **and** rotating breaks decryption. Plan per §4.4: rotate +
   re-encrypt (or accept re-upload), and check whether the media that leaked
   also contained blobs.
4. In all cases: review the audit log for signs of misuse (§6.9) and consider
   a full backup before changing keys.

### 6.9 Suspicious activity (audit review)

**Diagnose**:
```bash
sh scripts/filesrv-cli.sh admin audit --since 604800
sh scripts/filesrv-cli.sh admin audit --app-id <N> --since 86400
```

**Look for**: repeated failed logins, unexpected ACL grants (especially
`g:`/`*`/`public_read`), mass deletes, token revokes you did not issue, exports
you did not request, group membership changes.

**Handlers**: revoke affected tokens/secrets (§6.8), revert ACL changes, remove
unexpected group members, capture the audit evidence, and consider isolating
the app (`--enabled=false`).

### 6.10 High CPU / memory / traffic spike

**Diagnose**:
```bash
top -b -n1 | head -20          # which process?
tail -200 /tmp/tenant-fs.log   # what requests?
sh scripts/filesrv-cli.sh admin app usage
```

**Handlers**:
1. A single app saturating — inspect its usage; set/ lower quota; temporarily
   disable (`admin app set <id> --enabled=false`).
2. A traffic flood — the API is HMAC+nonce protected, but a misbehaving client
   can still burn CPU. Block the source IP at the firewall/proxy, or rate-limit.
3. If sustained and legit, scale the host (CPU/RAM) or move blobs to faster
   storage.

### 6.11 Upgrade broke it — roll back

1. Stop the server.
2. Restore the **previous** `target/release/filesrv` binary.
3. If the new binary also ran DB migrations that the old one does not
   understand, restore `data/fs.db` from the backup you took before upgrading
   (§4.3 step 2).
4. Start, verify `/healthz`, then open a report with the migration failure
   details.

### 6.12 Admin UI blank / missing assets

**Symptoms**: `http://127.0.0.1:8081/admin/` shows blank; console errors about
`style.css`/`app.js` 404 or CSP violations.

**Diagnose**: the UI is compiled into the binary (`include_str!`) and served by
the loopback admin listener. Reload and check the network tab.

**Handlers**:
1. If you edited the UI, you must **rebuild** (`cargo build --release`) and
   restart — the assets are embedded at compile time.
2. Make sure you load `/admin/` **with the trailing slash**; `/admin` redirects,
   and relative assets resolve against the wrong root otherwise.
3. If CSP blocks a stylesheet (the console flags `style-src`), that is a code
   bug — fix the CSP header / inline style, rebuild, restart.

### 6.13 Upload / download errors

**Diagnose**: read the error body (has `code` + `request_id`), check the
request size, token validity, ACL, quota.

**Handlers**:
- **Payload too large** → `max_payload_bytes` limit; raise per app
  (`admin app set <id> --max-payload-bytes=…`) or split the file.
- **Quota exceeded** → `usage_bytes >= quota_bytes`; raise quota or prune.
- **Token invalid/revoked/expired/IP-mismatch** → issue a new token; tokens are
  idempotent within TTL unless revoked.
- **ACL denied** → confirm the user is a member of an allowed group (`g:`), is
  `*`/owner, or `public_read` applies; check `app_users` registration (a valid
  JWT still 401s if the user is not pre-provisioned).
- **Corrupt/storage error** → §6.4 / §6.5.

### 6.14 Time-skew signature rejection

**Symptoms**: app calls fail with a timestamp-window error; `X-Timestamp` far
from server time.

**Handlers**: HMAC uses a ±300s window. Fix the **client** clock (NTP) or the
server clock, whichever is skewed. Confirm both on UTC. After the clock is
corrected, retry (nonce replay protection means a rejected request cannot be
replayed as-is).

### 6.15 Accidental data deletion — recovery

1. **Stop the server** immediately to freeze state.
2. Restore from the most recent snapshot (§3.3) — this reverts to that point;
   anything newer is lost unless you back it up first.
3. If only some files/apps were deleted: consider exporting the current DB
   state before restore, to merge the delta manually.
4. Verify per-app usage and a smoke download after restore.

---

## 7. Appendix

### 7.1 Key files & ports

| Item | Value |
|---|---|
| Binary | `target/release/filesrv` |
| Config/secrets | `.env` (project root, mode 600) |
| Data | `data/` (`fs.db` + `blobs/`) |
| Built-in backups | `data/backups/<name>/` (`db.sqlite`, `blobs.tar`, `manifest.json`) |
| Snapshot backups | whatever you pass to `backup.sh` (`fs.db`, `blobs/`, optional `.env`) |
| Public API | `0.0.0.0:8080` (`/v1/*`, `/healthz`, `/.well-known/security.txt`) |
| Admin API + UI | `127.0.0.1:8081` (`/admin/*`) |
| CLI | `scripts/filesrv-cli.sh` |
| Log | the file you redirect `start.sh` output to |

### 7.2 Environment variables (`.env`)

| Variable | Purpose | Notes |
|---|---|---|
| `TENANT_FS_SERVER_SECRET` | blob encryption root key | must be stable across backup→restore (§6.5) |
| `TENANT_FS_ADMIN_TOKEN` | bearer token for admin API/UI | rotate cheaply (§4.5) |
| `TENANT_FS_PUBLIC_BIND` | public listener address | default `0.0.0.0:8080` |
| `TENANT_FS_ADMIN_BIND` | admin listener address | default `127.0.0.1:8081` |
| `TENANT_FS_DB` | SQLite path | default `data/fs.db` |
| `TENANT_FS_BLOBS` | blob root | default `data/blobs` |
| `TENANT_FS_BACKUP_ROOT` | built-in backups dir | default `data/backups` |
| `TENANT_FS_RETENTION` | built-in backup retention (days) | default 7 |
| `TENANT_FS_SCHEDULE_SECS` | built-in backup schedule interval | `0` = off |
| `TENANT_FS_MAX_*` | batch ACL / payload / quota limits | per-cap |

### 7.3 Command quick reference

```bash
# ops
./scripts/setup-env.sh                          # create .env (never overwrites)
./scripts/start.sh                              # start (redirect to a log)
./scripts/backup.sh <dest> [--env-out <f>|--secret-out <f>|--no-env|--no-verify]
./scripts/restore.sh <backup-dir> [--stop|--data <dir>|--env <f>|--no-env|--dry-run|-y]
./scripts/rotate-secret.sh [--old <s>|--new <s>|--stop|--dry-run|--no-backup]
target/release/rekey --blobs <dir> --old <s> --new <s> [--dry-run]
sh scripts/filesrv-cli.sh health
sh scripts/filesrv-cli.sh version
sh scripts/filesrv-cli.sh admin apps
sh scripts/filesrv-cli.sh admin audit --since 86400
sh scripts/filesrv-cli.sh admin backup run|list|detail|config

# DB
sqlite3 data/fs.db "PRAGMA integrity_check;"
sqlite3 data/fs.db "VACUUM;"
```

### 7.4 Disaster-recovery plan summary

1. **Off-site**: keep at least one snapshot + the `.env` (via `--env-out`) on a
   different host/region than the live data.
2. **Recovery target**: any Linux box with the same `target/release` binary,
   the restored `data/` and the matching `.env`.
3. **Steps**: stop → rsync data back → restore `.env` → `integrity_check` →
   start → `/healthz` → smoke download.
4. **RTO/RPO**: bounded by snapshot frequency and the duration of a `rsync`
   restore; test it monthly (§5.3).
