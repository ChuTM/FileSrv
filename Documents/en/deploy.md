# Deployment Guide — tenant-fs-server

> This is the English version. 中文（繁體）版見 [`/zh/deploy.md`](../zh/deploy.md).
> Target: a Linux server (Debian/Ubuntu shown). macOS-only instructions are
> intentionally excluded.

A multi-tenant file server: HMAC-signed uploads, JWT user identities, ACL-gated
access, envelope-encrypted blobs at rest, token-based downloads, audit log.

- **Public port** — the file API (`/v1/*`, `/healthz`, `/.well-known/security.txt`).
- **Admin port** — the management API + console (`/admin/*`), loopback only by
  default (refuses to bind to a non-loopback address unless explicitly overridden).

Configuration lives in a single `.env` file — **no manual environment-variable
exports**. Two helper scripts handle it:

| Script | What it does |
|---|---|
| `scripts/setup-env.sh` | Generates `.env` from `.env.example`, auto-filling random `SERVER_SECRET` / `ADMIN_TOKEN` (never overwrites an existing `.env`). |
| `scripts/start.sh` | Loads every `KEY=VALUE` from `.env`, validates required secrets, starts the server. |

---

## 1. Prerequisites (Linux)

| Tool | Purpose |
|---|---|
| Rust toolchain (stable) | build (`cargo`) |
| `sqlite3` CLI | `integrity_check` in `backup.sh` |
| `rsync` | `backup.sh` |
| `openssl` | `setup-env.sh` (generate secrets) |

```bash
sudo apt update && sudo apt install -y sqlite3 rsync openssl
# Rust: https://rustup.rs
cargo --version && sqlite3 --version && rsync --version && openssl version
```

## 2. Build

```bash
cd /opt/rust-file-server          # or wherever you keep the source
cargo build --release
# binary: target/release/tenant-fs-server
```

Run as a dedicated non-root user (example: `useradd -r -s /usr/sbin/nologin tenantfs`).

## 3. Configure — one `.env` file

```bash
./scripts/setup-env.sh            # creates .env (mode 600), fills random secrets
chmod 700 .env                    # already 600; optional stricter
nano .env                         # review / edit every setting
```

`.env` holds **all** configuration; the server (or systemd) reads it for you.
`SERVER_SECRET` and `ADMIN_TOKEN` are filled automatically; everything else has
a safe default.

| Variable | Default | Meaning |
|---|---|---|
| `TENANT_FS_SERVER_SECRET` | auto-gen | Root key; derives the KEK sealing every app secret and blob. **Never** back it up with the data. |
| `TENANT_FS_ADMIN_TOKEN` | auto-gen | Admin API bearer token; keep off the public network. |
| `TENANT_FS_PUBLIC_BIND` | `0.0.0.0:8080` | Public file-API bind. |
| `TENANT_FS_ADMIN_BIND` | `127.0.0.1:8081` | Admin bind. Loopback only; server refuses non-loopback unless `ALLOW_NON_LOOPBACK_ADMIN=true`. |
| `TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN` | `false` | Dangerous override to expose the admin surface. |
| `TENANT_FS_TRUST_XFF` | `false` | Trust `X-Forwarded-For` for client IP (behind a trusted proxy only). |
| `TENANT_FS_DB` | `data/fs.db` | SQLite database path. |
| `TENANT_FS_BLOBS` | `data/blobs` | Blob storage root (`app_<id>/yyyy/mm/<uuid>`). |
| `TENANT_FS_ENCRYPT_BLOBS` | `true` | Envelope-encrypt blobs at rest. Keep on. |
| `TENANT_FS_RATE_LIMIT_PER_MIN` | `120` | Per-app budget per 60s window (upload/generate/export/download shared). `0` off. |
| `TENANT_FS_RATE_LIMIT_MAX_ENTRIES` | `10000` | In-memory rate-limit map capacity. |
| `TENANT_FS_MAX_BATCH_ACL` | `1000` | Max entries per batch-ACL call. |
| `TENANT_FS_EMBED_TTL` | `1800` | Embed-download token TTL (s). |
| `TENANT_FS_SHARE_TTL` | `300` | Share-download token TTL (s). |
| `TENANT_FS_IDEMPOTENCY_WINDOW_SECS` | `3600` | Idempotency-Key reuse window (s). |
| `TENANT_FS_IDEMPOTENCY_MAX_ENTRIES` | `10000` | Idempotency-cache capacity. |
| `TENANT_FS_UPLOAD_TTL_SECS` | `86400` | Chunked-upload session TTL (s). |
| `TENANT_FS_EXPORT_TTL_SECS` | `86400` | Export artifact TTL (s). |
| `TENANT_FS_DEC_CACHE_TTL_SECS` | `86400` | Plaintext decrypt-cache TTL (s). |
| `TENANT_FS_AUDIT_RETENTION_DAYS` | `30` | Audit-log retention (days). |
| `TENANT_FS_SOFT_DELETE_DAYS` | `7` | Soft-delete grace before purge (days). |
| `TENANT_FS_PURGE_INTERVAL_SECS` | `600` | Maintenance loop interval (s). |
| `TENANT_FS_BACKUP_ROOT` | `data/backups` | Built-in backup output dir. |
| `TENANT_FS_BACKUP_RETENTION` | `7` | Built-in backup retention (count). |
| `TENANT_FS_BACKUP_SCHEDULE_SECS` | `0` | Scheduled built-in backups; `0` off. |

## 4. Run

### Foreground (for testing)

```bash
./scripts/start.sh
```

`start.sh` exports `.env` and execs the release binary. Press Ctrl-C to stop.

### systemd (production) — reads `.env` via `EnvironmentFile`

Create `/etc/systemd/system/tenant-fs.service`:

```ini
[Unit]
Description=tenant-fs-server
After=network.target

[Service]
Type=simple
User=tenantfs
WorkingDirectory=/opt/rust-file-server
# Load all settings from .env — no Environment= lines needed.
EnvironmentFile=/opt/rust-file-server/.env
ExecStart=/opt/rust-file-server/target/release/tenant-fs-server
Restart=on-failure
# harden
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/rust-file-server/data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tenant-fs
sudo systemctl status tenant-fs          # confirm running
```

> `EnvironmentFile` reads `KEY=VALUE` lines exactly like `.env` — set the
> file mode to 600 and make it root/tenantfs-readable. Do **not** keep the
> plaintext secret in the unit file.

## 5. TLS / reverse proxy

The server speaks plain HTTP. Put TLS in front of the **public** port (Caddy is
the least configuration). Never proxy the admin port.

Caddy:

```caddyfile
files.scc.edu.hk {
    reverse_proxy 127.0.0.1:8080
    # security.txt is served at /.well-known/security.txt by the server itself
}
```

Nginx:

```nginx
server {
    listen 443 ssl;
    server_name files.scc.edu.hk;
    ssl_certificate     /etc/letsencrypt/live/files.scc.edu.hk/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/files.scc.edu.hk/privkey.pem;
    client_max_body_size 0;   # per-app max_payload is enforced server-side
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # only if TENANT_FS_TRUST_XFF=true
    }
}
```

## 6. Data layout

```
data/
├── fs.db                  # SQLite (WAL) — authoritative metadata, ACL, audit
├── blobs/
│   ├── app_<id>/yyyy/mm/<uuid>   # sharded encrypted blobs
│   ├── dec_cache/                # plaintext re-creatable cache (TTL-swept)
│   └── exports/                  # export artifacts (TTL-swept)
└── backups/               # built-in backup output (TENANT_FS_BACKUP_ROOT)
```

## 7. Backup & restore

The **simplest and recommended** option is a whole-directory snapshot — a copy
of `data/` is a valid backup, and "put it back + start" is a valid restore.
A ready-made script lives at `scripts/backup.sh`:

```bash
./scripts/backup.sh /mnt/backup/tenant-fs --data ./data --secret-out /root/.secrets/tenant-fs.secret
```

It WAL-checkpoints, rsyncs `data/` (excluding `backups/ dec_cache/ exports/
tmp_*`), runs `integrity_check`, and can separately save `SERVER_SECRET`
(chmod 600) **outside** the backup media.

**Critical**: keep `SERVER_SECRET` safe and out of the backup. A data backup
without it is undecryptable.

## 8. security.txt

`/.well-known/security.txt` is served on the public port (RFC 9116). Before
going live, edit `src/admin_ui/static/.well-known/security.txt`:

- set `Contact` to your real security inbox;
- uncomment `Canonical` with your public origin;
- keep `Expires` within one year (update yearly).

## 9. Hardening checklist

- [ ] `setup-env.sh` generated fresh `SERVER_SECRET`/`ADMIN_TOKEN`; `.env` is mode 600.
- [ ] Admin port is never exposed publicly; `TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN=false`.
- [ ] TLS in front of the public port (Caddy/Nginx).
- [ ] `TENANT_FS_TRUST_XFF=true` only behind a trusted reverse proxy.
- [ ] `TENANT_FS_ENCRYPT_BLOBS=true`.
- [ ] systemd unit runs as a dedicated non-root user with `ProtectSystem=strict`.
- [ ] `security.txt` Contact/Canonical updated; verified at `/.well-known/security.txt`.
- [ ] Backups tested: restore into a fresh dir and confirm the server starts.
- [ ] Rate limit left on (`TENANT_FS_RATE_LIMIT_PER_MIN` > 0).
