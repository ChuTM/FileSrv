# 部署指南 — filesrv

> 本頁為繁體中文版。English version: [`/en/deploy.md`](../en/deploy.md).
> 目標：Linux 伺服器（以 Debian/Ubuntu 為例）。刻意不包含 macOS 專屬指令。

一個多租戶檔案伺服器：HMAC 簽章上傳、JWT 使用者身分、ACL 存取控制、信封加密（blob 靜態加密）、令牌式下載、稽核日誌。

- **公共埠** — 檔案 API（`/v1/*`、`/healthz`、`/.well-known/security.txt`）。
- **管理埠** — 管理 API 與控制台（`/admin/*`），預設僅限本機迴路（loopback）；除非明確覆寫，否則拒絕綁定非 loopback 位址。

所有設定都放在單一 `.env` 檔——**無需手動 export 環境變數**。兩個輔助腳本處理：

| 腳本 | 作用 |
|---|---|
| `scripts/setup-env.sh` | 由 `.env.example` 產生 `.env`，自動填入隨機 `SERVER_SECRET` / `ADMIN_TOKEN`（絕不覆寫既有 `.env`）。 |
| `scripts/start.sh` | 讀取 `.env` 中每個 `KEY=VALUE`、驗證必要密鑰、啟動伺服器。 |

---

## 1. 前置需求（Linux）

| 工具 | 用途 |
|---|---|
| Rust 工具鏈（stable） | 編譯（`cargo`） |
| `sqlite3` CLI | `backup.sh` 的 `integrity_check` |
| `rsync` | `backup.sh` |
| `openssl` | `setup-env.sh`（產生密鑰） |

```bash
sudo apt update && sudo apt install -y sqlite3 rsync openssl
# Rust: https://rustup.rs
cargo --version && sqlite3 --version && rsync --version && openssl version
```

## 2. 建置

```bash
cd /opt/rust-file-server          # 或存放原始碼的位置
cargo build --release
# 執行檔：target/release/filesrv
```

以專屬非 root 使用者執行（例：`useradd -r -s /usr/sbin/nologin tenantfs`）。

## 3. 設定 — 單一 `.env` 檔

```bash
./scripts/setup-env.sh            # 產生 .env（mode 600），自動填入隨機密鑰
nano .env                         # 檢視 / 編輯每個設定
```

`.env` 存放**全部**設定；伺服器（或 systemd）會自動讀取。`SERVER_SECRET` 與 `ADMIN_TOKEN` 自動產生；其餘皆有安全預設值。

| 變數 | 預設 | 說明 |
|---|---|---|
| `TENANT_FS_SERVER_SECRET` | 自動產生 | 根金鑰；衍生出封存所有 app secret 與 blob 的 KEK。**切勿**隨資料備份。 |
| `TENANT_FS_ADMIN_TOKEN` | 自動產生 | 管理 API 的 Bearer 權杖；請勿暴露於公共網路。 |
| `TENANT_FS_PUBLIC_BIND` | `0.0.0.0:8080` | 公共檔案 API 綁定位址。 |
| `TENANT_FS_ADMIN_BIND` | `127.0.0.1:8081` | 管理埠綁定位址。僅限 loopback；除非設 `ALLOW_NON_LOOPBACK_ADMIN=true`，否則綁定非 loopback 位址會直接 panic。 |
| `TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN` | `false` | 危險覆寫，會把管理面暴露到網路上。 |
| `TENANT_FS_TRUST_XFF` | `false` | 是否信任 `X-Forwarded-For`（僅在受信任反向代理後方）。 |
| `TENANT_FS_DB` | `data/fs.db` | SQLite 資料庫路徑。 |
| `TENANT_FS_BLOBS` | `data/blobs` | Blob 儲存根目錄（`app_<id>/yyyy/mm/<uuid>`）。 |
| `TENANT_FS_ENCRYPT_BLOBS` | `true` | blob 靜態信封加密。建議保持開啟。 |
| `TENANT_FS_RATE_LIMIT_PER_MIN` | `120` | 每 app 每 60 秒視窗預算（upload/generate/export/download 共用）。`0` = 停用。 |
| `TENANT_FS_RATE_LIMIT_MAX_ENTRIES` | `10000` | 記憶體限流表容量。 |
| `TENANT_FS_MAX_BATCH_ACL` | `1000` | 單次批次 ACL 呼叫上限。 |
| `TENANT_FS_EMBED_TTL` | `1800` | embed 下載令牌 TTL（秒）。 |
| `TENANT_FS_SHARE_TTL` | `300` | share 下載令牌 TTL（秒）。 |
| `TENANT_FS_IDEMPOTENCY_WINDOW_SECS` | `3600` | Idempotency-Key 重複使用視窗（秒）。 |
| `TENANT_FS_IDEMPOTENCY_MAX_ENTRIES` | `10000` | 冪等快取容量。 |
| `TENANT_FS_UPLOAD_TTL_SECS` | `86400` | 分片上傳工作階段 TTL（秒）。 |
| `TENANT_FS_EXPORT_TTL_SECS` | `86400` | 匯出產物 TTL（秒）。 |
| `TENANT_FS_DEC_CACHE_TTL_SECS` | `86400` | 明文解密快取 TTL（秒）。 |
| `TENANT_FS_AUDIT_RETENTION_DAYS` | `30` | 稽核日誌保留天數。 |
| `TENANT_FS_SOFT_DELETE_DAYS` | `7` | 軟刪除寬限期（天）。 |
| `TENANT_FS_PURGE_INTERVAL_SECS` | `600` | 維護迴圈間隔（秒）。 |
| `TENANT_FS_BACKUP_ROOT` | `data/backups` | 內建備份輸出目錄。 |
| `TENANT_FS_BACKUP_RETENTION` | `7` | 內建備份保留份數。 |
| `TENANT_FS_BACKUP_SCHEDULE_SECS` | `0` | 內建備份排程；`0` = 停用。 |

## 4. 執行

### 前台（測試用）

```bash
./scripts/start.sh
```

`start.sh` 會 export `.env` 並 exec release 執行檔。Ctrl-C 停止。

### systemd（正式環境）— 以 `EnvironmentFile` 讀取 `.env`

建立 `/etc/systemd/system/tenant-fs.service`：

```ini
[Unit]
Description=filesrv
After=network.target

[Service]
Type=simple
User=tenantfs
WorkingDirectory=/opt/rust-file-server
# 由 .env 載入所有設定 — 不需 Environment= 逐行。
EnvironmentFile=/opt/rust-file-server/.env
ExecStart=/opt/rust-file-server/target/release/filesrv
Restart=on-failure
# 加固
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
sudo systemctl status tenant-fs          # 確認運行中
```

> `EnvironmentFile` 會像 `.env` 一樣逐行讀取 `KEY=VALUE`——請將檔案權限設為 600，並確保 tenantfs/root 可讀。**切勿**把明文密鑰寫入 unit 檔。

## 5. TLS / 反向代理

伺服器本身僅提供 HTTP。TLS 放在**公共埠**前方（Caddy 設定最少）。**切勿**代理管理埠。

Caddy：

```caddyfile
files.scc.edu.hk {
    reverse_proxy 127.0.0.1:8080
    # security.txt 由伺服器本身在 /.well-known/security.txt 提供
}
```

Nginx：

```nginx
server {
    listen 443 ssl;
    server_name files.scc.edu.hk;
    ssl_certificate     /etc/letsencrypt/live/files.scc.edu.hk/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/files.scc.edu.hk/privkey.pem;
    client_max_body_size 0;   # 單檔上限由伺服器端的 max_payload 控管
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # 僅在 TENANT_FS_TRUST_XFF=true 時
    }
}
```

## 6. 資料目錄結構

```
data/
├── fs.db                  # SQLite（WAL）— 權威中繼資料、ACL、稽核
├── blobs/
│   ├── app_<id>/yyyy/mm/<uuid>   # 分片加密 blob
│   ├── dec_cache/                # 明文可重建快取（TTL 自動清理）
│   └── exports/                  # 匯出產物（TTL 自動清理）
└── backups/               # 內建備份輸出（TENANT_FS_BACKUP_ROOT）
```

## 7. 備份與還原

**最簡單且建議**的方式是整目錄快照——複製一份 `data/` 即為有效備份，「放回 + 啟動」即為有效還原。專用腳本位於 `scripts/backup.sh`：

```bash
./scripts/backup.sh /mnt/backup/tenant-fs --data ./data --secret-out /root/.secrets/tenant-fs.secret
```

它會：WAL checkpoint、rsync 同步 `data/`（排除 `backups/ dec_cache/ exports/ tmp_*`）、執行 `integrity_check`，並可選擇把 `SERVER_SECRET` 另存（chmod 600）於**備份介質之外**。

**關鍵**：請妥善保管 `SERVER_SECRET` 且勿隨備份存放。缺少它的資料備份無法解密。

## 8. security.txt

`/.well-known/security.txt` 於公共埠提供（RFC 9116）。正式上線前，請編輯 `src/admin_ui/static/.well-known/security.txt`：

- 將 `Contact` 改為您的真實安全收件信箱；
- 取消註解 `Canonical` 並填入您的公共網域；
- 讓 `Expires` 維持在一年內（每年更新）。

## 9. 加固檢查清單

- [ ] `setup-env.sh` 已產生全新 `SERVER_SECRET`/`ADMIN_TOKEN`；`.env` 為 mode 600。
- [ ] 管理埠永不公開暴露；`TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN=false`。
- [ ] 公共埠前方有 TLS（Caddy/Nginx）。
- [ ] `TENANT_FS_TRUST_XFF=true` 僅在受信任反向代理後方。
- [ ] `TENANT_FS_ENCRYPT_BLOBS=true`。
- [ ] systemd unit 以專屬非 root 使用者執行，含 `ProtectSystem=strict`。
- [ ] 已更新 `security.txt` 的 Contact/Canonical，並於 `/.well-known/security.txt` 驗證。
- [ ] 備份已實測還原：還原至全新目錄並確認伺服器可啟動。
- [ ] 限流保持開啟（`TENANT_FS_RATE_LIMIT_PER_MIN` > 0）。
