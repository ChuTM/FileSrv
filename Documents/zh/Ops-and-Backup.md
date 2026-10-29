# Tenant File Server — 營運與備份筆記（繁體中文）

> 本頁為繁體中文版。English: [`../Ops-and-Backup.md`](../Ops-and-Backup.md)
> 適用於**目前實作**（SQLite + 本機 blob 目錄、信封加密 blob、內建備份 API）。
> 若與已定案的 roadmap 有出入，會在文中標明。

---

## 1. 伺服器實際上持久化了什麼

預設所有東西都位於工作目錄之下（整棵樹就是你要做快照備份的那個「data」目錄，見 §5.5）：

```
data/                          <- 唯一需要備份的樹
├── fs.db                      <- TENANT_FS_DB     (SQLite, WAL mode)
├── blobs/                     <- TENANT_FS_BLOBS  (所有使用者檔案內容)
│   ├── app_<id>/yyyy/mm/<uuid>   信封加密的 blob 檔（「拆散」配置）
│   ├── dec_cache/              可重建的明文快取（TTL 清理，見 §4）
│   ├── exports/                已完成的 tar/zip 產物（TTL 清理）
│   └── tmp_*                   中斷上傳的分片（開機時清理）
└── backups/                   <- TENANT_FS_BACKUP_ROOT（內建備份輸出）
```

| 資料 | 位置 | 格式 |
|---|---|---|
| 權威資料庫（apps、檔案中繼資料、ACL、資料夾、權杖、nonce、稽核日誌、備份紀錄、上傳工作、設定） | `TENANT_FS_DB`（預設 `data/fs.db`） | SQLite 3、WAL 模式、外鍵開啟 |
| Blob 內容 | `TENANT_FS_BLOBS`（預設 `data/blobs`） | `blobs/app_<id>/yyyy/mm/<uuid>` 下的信封加密檔（含自描述 `TSFS` 檔頭）；舊版明文 blob 可透明讀取 |
| 內建備份輸出 | `TENANT_FS_BACKUP_ROOT`（預設 `data/backups`） | 每次執行一個目錄，含 `db.sqlite` + `blobs.tar` + `manifest.json` |

所以是的：**資料庫與每個使用者檔案本來就在 `data/` 之下**，使用者檔案也已依
`app_<id>/yyyy/mm/<uuid>` 配置拆散在磁碟上。要做檔案層級還原，不需要再做其他事。

Blob 是**不可變**的（以 UUID 寫入一次、永不修改）。權杖可重新產生（受 TTL 約束）。
這對備份一致性很重要：內建備份會把 blob 樹與 DB 當作單一一致單位一起快照。

---

## 2. 備份：目前如何運作

**有一套內建備份介面。** 它暴露在 loopback admin API 上：

| Method | Path | 行為 |
|---|---|---|
| POST | `/admin/v1/backups/run` | 同步執行：DB 快照（`VACUUM INTO`）+ `blobs.tar` + `manifest.json`（每個檔案的 sha256）。完成後立即回傳。 |
| GET | `/admin/v1/backups` | 列出紀錄，最新在前。 |
| GET | `/admin/v1/backups/{id}` | 詳細資料，含 `target_path` 與解析後的 manifest。 |
| PATCH | `/admin/v1/backups/config` | `{ schedule?, target?, retention? }`，持久化到 DB。 |

一次執行會在 `TENANT_FS_BACKUP_ROOT`（預設 `data/backups`）下產生一個目錄，內含：

- `db.sqlite` —— 透過 `VACUUM INTO` 取得的一致線上快照（不是在伺服器運行時做原始檔
  拷貝）。
- `blobs.tar` —— 信封加密的 app blob 樹。明文快取（`dec_cache/`）、已完成的匯出產物
  （`exports/`）與中斷的 `tmp_*` 分片**刻意排除**；只封存 `app_*` 樹。
- `manifest.json` —— `backup_id`、`created_at`、每個檔案的 `{name, size, sha256}`，
  以及一段註明「不包含任何金鑰材料」的說明。

設定旋鈕：

- `TENANT_FS_BACKUP_ROOT`（預設 `data/backups`）——所有 target 都掛在其下。
- `TENANT_FS_BACKUP_RETENTION`（預設 7，夾制 1–1000）——只保留最新的 N 份；
  較舊的目錄與 DB 列會被移除。
- `TENANT_FS_BACKUP_SCHEDULE_SECS`（預設 0 = 關閉）——當 > 0 時，背景維護迴圈會在上次
  備份後間隔到期時觸發一次執行。營運端可於運行時以 `PATCH /admin/v1/backups/config`
  覆寫 schedule / target / retention（DB 值優先於環境變數預設值）。

**鎖定注意事項（F3 修正）：**一次執行只在短暫的 `VACUUM INTO` 快照與簿記更新時持有
全域 DB mutex。較慢的 blob 樹 tar 封存是在**不加 DB 鎖**下進行的，因此大型備份不再
讓整個備份期間的每個 API 請求都停擺。

---

## 3. 備份去哪裡（target 白名單）

`PATCH /admin/v1/backups/config` 中的 `target` 是 `TENANT_FS_BACKUP_ROOT` 之下的
**相對目錄名稱**。它會被驗證：

- 絕對路徑、`..`、`:` 與 `\` 直接拒絕；
- 候選路徑會被 canonicalize，且必須仍以 `canonical_root` 開頭（`starts_with`）——
  這同時擋掉路徑穿越與 symlink 逃逸（canonicalize 會解析連結）。

因此備份在建構上就被限制在設定的根目錄內。若要離線副本，請掛載／同步備份根目錄
（例如在一次執行後用 `restic` / `rsync` 同步該根目錄）——伺服器本身尚未支援
S3 / restic 遠端。

---

## 4. 靜態加密與金鑰政策

Blob 預設採信封加密（`TENANT_FS_ENCRYPT_BLOBS=true`）：

```
[0..4]   "TSFS"  [4] version=1
[5..17]  dek_nonce (12)      [17..65] sealed_dek (48, AES-256-GCM(KEK, dek_nonce, DEK[32]))
[65..77] body_nonce (12)     [77..]  ciphertext = AES-256-GCM(DEK, body_nonce, plaintext)
```

- 每個 blob 有各自的隨機 256 位元 DEK；同一段明文加密兩次，逐位元組不同。
- **KEK = SHA-256(SERVER_SECRET)**，與密封 app secret 用的是同一個推導。
  `SERVER_SECRET` 只存在於部署環境中，**永不**寫入備份（DB 快照、`blobs.tar`、
  manifest、磁碟區快照、CI fixture）。manifest 會明確聲明這點。
- 因為密封後的 DEK 隨 blob 檔頭一起存放，被偷走的備份若沒有 `SERVER_SECRET`，
  就只會是一堆打不開的密文。
- 舊版明文 blob（無 `TSFS` magic）會走明文路徑被透明地提供；
  `migrate_plaintext_blobs()` 會就地把它們改寫為信封格式（冪等）。
- 讀取時，加密 blob 會物化成 `blob_root/dec_cache/` 下每個 uuid 一份的明文快取
  （原子置換）。該快取會從備份與匯出中排除；刪除／清除會移除真正的加密檔。
  快取現在會 **TTL 清理**（`TENANT_FS_DEC_CACHE_TTL_SECS`，預設 86400）：超過 TTL 的
  項目由維護迴圈移除，因此明文不會無限留在磁碟上（F2 修正）。

**營運端職責：把 `SERVER_SECRET` 分開且安全地存放。** 它是 app secret 密封與 blob
加密的單一根信任來源。遺失它會讓所有備份與所有已密封的 app secret 無法還原；
洩漏它（連同備份）則等同於繞過加密。

---

## 5. 還原（營運端手動程序）

目前**沒有還原端點**。還原是手動 runbook：

1. 停止伺服器（或接受下一步是在一份拷貝上重新啟動）。
2. 把快照 `db.sqlite` 放成新的 `TENANT_FS_DB`。
3. 把 `blobs.tar` 解回 blob 根目錄，恢復 `app_<id>/yyyy/mm/<uuid>` 配置。
4. 以產生這份備份的**同一個 `SERVER_SECRET`** 啟動伺服器。缺少它，已密封的 app secret
   與每個信封 blob 都無法解密。
5. 驗證：`GET /admin/v1/apps/{id}/usage` 與一次已知檔案的測試下載。若某列對應的 blob
   缺失，下載／匯出會以「File content missing.」略過它——DB 是權威，blob 是內容。

因為 blob 不可變、DB 是單一 SQLite 檔，你也可以在一次 `run` 後用 `restic` / `borg` /
`rsync` 在備份根目錄之上疊加離線副本——但離線備份一定要配一份安全存放的
`SERVER_SECRET` 副本（放在備份介質之外）。

---

## 5.5 最簡單的做法：快照整個 `data/` 目錄

> 倉庫隨附一個現成的 script：`scripts/backup.sh <目標路徑>
> [--data <data目錄>] [--secret-out <密鑰檔>] [--no-verify]`。它會執行 WAL
> checkpoint、下面的 rsync、可選的 `integrity_check`，以及可選地另存一份
> `SERVER_SECRET`。下面手動步驟與它等價。

由於 DB 與每個 blob 都在同一個目錄之下（§1），最低摩擦的備份就是**對 `data/` 做整目錄
拷貝**——完全不涉及內建 API。還原就等於「拷回去並啟動伺服器」。

**備份（`data/` → 備份介質）：**

1. 停止伺服器；若必須維持在線，就在拷貝前一刻執行
   `sqlite3 data/fs.db 'PRAGMA wal_checkpoint(TRUNCATE);'`（對 WAL 模式 DB 的線上
   檔案拷貝並不保證一致）。
2. 拷貝整棵樹，排除可重建／巢狀的部分：
   ```bash
   rsync -a --delete \
     --exclude 'backups/'       # 巢狀的內建備份輸出
     --exclude 'blobs/dec_cache/'   # 明文快取，隨需重建
     --exclude 'blobs/exports/'     # 已完成的匯出產物，可重建
     --exclude 'blobs/tmp_*'        # 中斷上傳的分片
     data/  /backup/media/data-$(date +%F)/
   ```
3. 把 `SERVER_SECRET` **與備份介質分開**存放（它是解密一切的唯一金鑰；絕不能躺在
   這份拷貝裡面）。

**還原（備份介質 → `data/`）：**

1. 停止伺服器。
2. 用這份拷貝**整個取代** `data/` 目錄（或解到相同路徑）。被排除的子目錄
   （`dec_cache/`、`exports/`、`tmp_*`、`backups/`）本來就缺席，或由伺服器隨需重建。
3. 以製作備份時**相同的 `SERVER_SECRET`** 與相同的 `TENANT_FS_DB` / `TENANT_FS_BLOBS`
   路徑啟動伺服器。服務會直接在還原後的檔案上啟動——不需要重新匯入、沒有遷移步驟。
4. 驗證：`GET /admin/v1/apps/{id}/usage` 與一次測試下載。

為何安全：blob 不可變且以 UUID 為鍵、DB 是單一 SQLite 檔、兩者都在 `data/` 之下。
排除 `dec_cache/` / `exports/` 可在不遺失任何東西的前提下，讓明文不進入備份介質
（維持靜態加密的敘事）——兩者都可隨需重建。

---

## 6. 目前建置的營運注意事項

- **資料安全**：SQLite WAL + 外鍵；單一寫入者 mutex 序列化寫入（正確，但也是寫入瓶頸
  ——預期每秒約 1k+ 小寫入）。
- **密鑰衛生**：`TENANT_FS_SERVER_SECRET` 與 `TENANT_FS_ADMIN_TOKEN` 都有 dev 預設值；
  伺服器會對**兩者**打印響亮的啟動警告，且當任一仍是 dev 預設值時會**拒絕啟動**，
  除非設 `TENANT_FS_DEV_ALLOW_DEFAULT_SECRETS=true`（僅供開發的逃逸口——生產環境
  切勿設定）。生產環境請兩者都明確設定，並把 `SERVER_SECRET` 獨立於備份介質存放。
- **過期清理**：背景維護迴圈（`TENANT_FS_PURGE_INTERVAL_SECS`，預設 600 秒）會清除
  nonce、舊稽核列（`TENANT_FS_AUDIT_RETENTION_DAYS`，預設 30）、過期的 `tokens` 列、
  超過寬限期（`TENANT_FS_SOFT_DELETE_DAYS`，預設 7——會實體移除其 blob）的軟刪除
  tombstone、超過 `TENANT_FS_EXPORT_TTL_SECS`（預設 86400）的已完成匯出，以及超過
  TTL 的中斷分塊上傳工作階段。
- **軟刪除語意**：`DELETE` 立即回收配額、丟棄該檔的權杖，但 blob 會存活過寬限期；
  清除是實體性的。設 `TENANT_FS_SOFT_DELETE_DAYS=0` 會在下一拍清除（測試 / E2E 用）。
- **網路姿態**：公共 bind 預設 `0.0.0.0:8080`；admin 只綁定 `127.0.0.1`
  （且控制台靜態資源在公共 router 上回 404）。伺服器現在會在非 loopback admin bind 上
  **拒絕啟動**（F6 修正），除非明確設定 `TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN=true`——
  該覆寫**不建議**。請把公共埠放在 TLS（反向代理）後方。若使用的代理會改寫
  `X-Forwarded-For`，就設 `TENANT_FS_TRUST_XFF=true`；否則保持關閉，以免用戶端偽造
  IP 綁定的 share 權杖。
- **限流**：下載（GET/HEAD `/v1/download/{token}`）現在與上傳 / generate / export
  共用同一每 app 預算（`TENANT_FS_RATE_LIMIT_PER_MIN`，預設 120/min）——熱門連結無法
  用無窮的權杖流量耗盡伺服器 I/O（F7 修正）。
- **下載稽核（選用）**：預設成功下載不記稽核（維持高讀取負載下的日誌量小）。設
  `TENANT_FS_AUDIT_DOWNLOADS=true` 會為每次 GET 記錄一條 `download` 稽核列——當敏感
  檔案需要逐次下載軌跡時很有用。舊列仍依 `TENANT_FS_AUDIT_RETENTION_DAYS` 清除。
- **使用者目錄**：使用者由營運端透過 `POST /admin/v1/apps/{id}/users` 佈建
  （管理控制台：每個 app 上的「用戶」按鈕）；app 也可以在上傳時以 `X-User-Id`
  替使用者背書。
- **Blob 在磁碟上已加密**（信封 KEK/DEK，§4）。你仍需要磁碟區層級加密或加密的離線
  副本做縱深防禦。

---

## 7. 值得知道的缺口

- 沒有備份**還原**端點——還原是 §5 的手動 runbook。
- 程序內不終止 TLS / HSTS——請在反向代理終止。
- 不掃描上傳內容的惡意軟體／防毒。
- 單一共用的 `ADMIN_TOKEN`——沒有營運者／稽核者角色分離。
- 匯出工作完成時沒有 webhook / 推播通知（請輪詢狀態端點）。
- 備份目標限本機磁碟相對路徑；S3 / restic 型遠端尚未實作。
- **大檔案記憶體**：加密 blob 解密時會把整個檔案讀進記憶體（分塊上傳的 finalize 也是）。
  高並發 + 大檔案時會拉高 RAM 用量。目前的緩解做法：把 `max_payload_bytes`／配額設在
  合理範圍、並據此規劃主機記憶體；串流解密列為未來工作。
