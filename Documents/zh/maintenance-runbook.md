# 維護與營運 Runbook — filesrv（繁體中文）

> 本頁為繁體中文版。English: [`../maintenance.md`](../maintenance.md)
> 多租戶檔案伺服器的營運參考。涵蓋「出問題時該怎麼做」與例行檢查排程。配套文件：
> [`Ops-and-Backup.md`](Ops-and-Backup.md)（資料與金鑰政策）、
> [`deploy.md`](deploy.md)（Linux 部署）、`api.md`（App-facing API）、
> [`admin-api.md`](admin-api.md)（admin API）。

所有命令假設以 **Linux** 為目標（部署環境）。在開發用 Mac 上運作方式相同，但路徑／
init 樣式可能不同。

---

## 1. 快速參考卡

### 1.1 健康檢查與重啟

```bash
# 健康檢查（不需憑證）
curl -s http://127.0.0.1:8080/healthz            # -> OK
# 或用 CLI
sh scripts/filesrv-cli.sh health

# 重啟
pkill -9 -f filesrv ; sleep 3
pgrep -f 'target/release/filesrv' || echo "stopped"   # 必須打印 "stopped"
nohup ./scripts/start.sh > /tmp/tenant-fs.log 2>&1 &
sleep 3; curl -s http://127.0.0.1:8080/healthz                  # -> OK
```

### 1.2 備份與還原（快速路徑）

```bash
# 備份 —— .env 預設會一併備份（進到媒體內）。建議另把憑證放在媒體之外：
./scripts/backup.sh /backup/tenant-fs \
    --env-out ~/.secrets/tenant-fs.env \
    --secret-out ~/.secrets/tenant-fs.server_secret
#     .env 預設進媒體；加 --no-env 可把它留在外面。

# 最簡單的單目錄還原（備份時 .env 在內）：
./scripts/backup.sh /backup/tenant-fs --include-env   # （已是預設）

# 還原 —— 用輔助 script（會停伺服器、快照目前狀態、把 data + .env 拷回、驗證完整性）：
./scripts/restore.sh /backup/tenant-fs --stop

# 就地輪換 SERVER_SECRET（重新密封每個 DEK，payload 不動）：
./scripts/rotate-secret.sh --stop
```

### 1.3 症狀 → 章節索引

| 症狀 | 前往 |
|---|---|
| 伺服器無法啟動 | §6.1 |
| `/healthz` 不是 `OK` | §6.2 |
| 磁碟滿 | §6.3 |
| SQLite 鎖定／損壞／WAL 出問題 | §6.4 |
| 檔案無法解密／完整性錯誤 | §6.5 |
| 備份失敗 | §6.6 |
| 還原失敗 | §6.7 |
| 憑證洩漏 | §6.8 |
| 可疑活動 | §6.9 |
| 高 CPU／記憶體／流量 | §6.10 |
| 升級弄壞了它 | §6.11 |
| Admin UI 空白／資源缺失 | §6.12 |
| 上傳／下載錯誤 | §6.13 |
| 簽章／時間戳被拒 | §6.14 |
| 意外刪除資料 | §6.15 |

---

## 2. 架構與資料配置（你要維護的東西）

- **單一程序** `target/release/filesrv`，兩個監聽器：
  - `TENANT_FS_PUBLIC_BIND`（預設 `0.0.0.0:8080`）——App-facing API +
    `/healthz` + `/.well-known/security.txt`。
  - `TENANT_FS_ADMIN_BIND`（預設 `127.0.0.1:8081`）——admin API + admin UI
    （僅 loopback）。
- **資料目錄**（`TENANT_FS_DB` / `TENANT_FS_BLOBS`，預設在 `./data` 之下）：
  - `fs.db`（SQLite、WAL 模式）——apps、使用者、群組、檔案／資料夾中繼資料、
    ACL、稽核日誌。
  - `blobs/app_{app_id}/yyyy/mm/<storage_uuid>`——檔案內容，以 `SERVER_SECRET`
    靜態加密；每個檔案各自拆散在自己的目錄樹中。
- **密鑰與設定**都放在 `.env`（見 §7.2）：`SERVER_SECRET`（加密根金鑰，**在備份 →
  還原之間必須保持相同**）、`ADMIN_TOKEN`、綁定位址、DB/blob 路徑、備份設定。
- **CLI** `scripts/filesrv-cli.sh`——透過 loopback admin API 做營運操作；
  非敏感的 `health`／`version` 不需 token。
- **備份**（`TENANT_FS_BACKUP_ROOT`，預設 `data/backups`）存放
  `{db.sqlite, blobs.tar, manifest.json}`；獨立的 `backup.sh` 則是產生整目錄快照
  （`fs.db + blobs/... + 可選 .env`）。

---

## 3. 備份 —— 包含 `.env`

### 3.1 完整備份必須包含什麼

| 項目 | 為何 | 位置 |
|---|---|---|
| `data/fs.db` | 所有中繼資料、使用者、ACL、稽核 | 快照根 |
| `data/blobs/` | 所有檔案內容（已加密） | 快照根 |
| **`.env`** | `SERVER_SECRET`、`ADMIN_TOKEN`、綁定／設定 | **必須**擷取（見下） |
| `backup-manifest.txt` | 出處、時間、env 位置 | 快照根 |

> `.env` 很容易被忘記：它在**專案根目錄**，`data/` 之外。只備份 `data/` 能還原 blob
> 與中繼資料，卻少了解密所需的 `SERVER_SECRET`。

### 3.2 如何**連同** `.env` 一起備份

`.env` **預設**會一併備份：`backup.sh` 會把它複製成 `<dest>/.env`（chmod 600）。
用 `--no-env` 可把它留在媒體之外。依你的風險承受度選擇下列選項：

**選項 A —— 建議：`.env` 放在備份媒體之外**
（`--env-out <file>`）。`.env` 會被複製到另一個受信任的位置（chmod 600），絕不進媒體。
媒體外洩時憑證不會外洩。再搭配預設的媒體內副本，就是雙保險。

```bash
./scripts/backup.sh /backup/tenant-fs \
    --env-out ~/.secrets/tenant-fs.env \
    --secret-out ~/.secrets/tenant-fs.server_secret
```

**選項 B —— 預設：`.env` 跟著備份走**（`--include-env`，本就預設開啟）。`.env` 會被
複製成 `<dest>/.env`（chmod 600）。還原就等於「把目錄拷回去」。只有當備份媒體受信任／
已加密（例如加密磁碟區，或你掌握的物件儲存）時才保留此預設，因為 `.env` 含
`SERVER_SECRET` 與 `ADMIN_TOKEN`。

```bash
./scripts/backup.sh /backup/tenant-fs              # .env 在媒體內（預設）
./scripts/backup.sh /backup/tenant-fs --no-env     # 把 .env 留在媒體外
```

**選項 C —— 完全手動**（當你本來就在暫存一個目錄時）：

```bash
pkill -9 -f filesrv; sleep 3            # 取得一致的快照
rsync -a --exclude backups/ --exclude 'blobs/dec_cache/' \
      --exclude 'blobs/exports/' --exclude 'blobs/tmp_*' \
      ./data/ /backup/tenant-fs/
cp .env /backup/tenant-fs.env                     # 分開存放，在媒體之外
```

`backup-manifest.txt` 會記錄 `env-in-backup: yes|no` 與 `env-out:`，讓你在日後永遠能
分辨環境變數去了哪裡。

### 3.3 還原 —— 逐步

**快速路徑 —— 用 `restore.sh` 輔助 script**（會停伺服器、快照目前狀態、把 data + `.env`
拷回、驗證完整性，然後告訴你啟動）：

```bash
./scripts/restore.sh /backup/tenant-fs --stop
# 選項：--data <dir>、--env <file> | --no-env、--no-backup、--dry-run、-y
```

**手動等效做法**（如果你想自己動手）：

1. **停伺服器**並確認已停止：
   ```bash
   pkill -9 -f filesrv; sleep 3; pgrep -f filesrv || echo stopped
   ```
2. **還原資料樹**（從 `backup.sh` 快照）：
   ```bash
   rsync -a --exclude backup-manifest.txt --exclude .env /backup/tenant-fs/ ./data/
   ```
3. **還原 `.env`** —— 選對應來源：
   - 若用 `--include-env`（預設）：`cp /backup/tenant-fs/.env ./.env`
   - 若用 `--env-out`：`cp ~/.secrets/tenant-fs.env ./.env`
   - 若只用 `--secret-out`：把保存的 `SERVER_SECRET` 放回你既有的 `.env`。
4. **啟動前先驗證 DB**：
   ```bash
   sqlite3 data/fs.db "PRAGMA integrity_check;"   # -> ok
   ```
5. **啟動並健康檢查**：
   ```bash
   nohup ./scripts/start.sh > /tmp/tenant-fs.log 2>&1 &
   sleep 3; curl -s http://127.0.0.1:8080/healthz   # -> OK
   ```
6. **對一個你知道存在的 app 做一次下載冒煙測試**（解密路徑）。

> **關鍵**：啟動時用的 `SERVER_SECRET` **必須等於**產生這份備份的那個。若不同，每個
> blob 解密都會失敗（見 §6.5）。輪換 `SERVER_SECRET` 現在是安全且就地的——見 §4.4。

### 3.4 驗證備份／還原演練

- 每次備份後：確認 `backup-manifest.txt` 存在、預期檔案都在（`ls /backup/tenant-fs`）。
- 對副本做 SQLite 檢查：`sqlite3 /backup/tenant-fs/fs.db "PRAGMA integrity_check;"`。
- **每月演練**：在另一台主機／容器還原到暫存目錄、用不同埠啟動、上傳＋下載一個檔案。
  證明備份真的可用，而不只是存在。

---

## 4. 例行操作

### 4.1 啟動／停止／重啟

```bash
# 啟動（daemon 化）
nohup ./scripts/start.sh > /tmp/tenant-fs.log 2>&1 &

# 停止
pkill -9 -f filesrv; sleep 3
pgrep -f filesrv || echo stopped

# 重啟 = 先停再啟（見 §1.1）
```

### 4.2 日誌

- 啟動橫幅與所有請求都進你在啟動時導向的那個檔案（例如 `/tmp/tenant-fs.log`）。檢視：
  ```bash
  tail -f /tmp/tenant-fs.log
  grep -iE 'error|warn|denied|failed' /tmp/tenant-fs.log | tail -50
  ```
- **稽核日誌**在 DB 裡，用 CLI 查詢：
  ```bash
  sh scripts/filesrv-cli.sh admin audit --app-id <N> --since 86400
  ```

### 4.3 更新伺服器（新二進制 + DB 遷移）

1. 停止伺服器。
2. 先備份（至少 `data/fs.db` + `.env`）。
3. 建置或複製新的 `target/release/filesrv`。
4. 遷移是**冪等**的（`CREATE TABLE IF NOT EXISTS …`）；它們在下次啟動時執行。
   啟動伺服器，並確認日誌沒有遷移錯誤、`/healthz` 回 `OK`。
5. 在部署到正式環境前，對新 build 執行相關的 `cargo test --release` 子集。

### 4.4 輪換 `SERVER_SECRET`

`SERVER_SECRET` 是 KEK（取其 SHA-256）的來源，用來密封每個 blob 的每檔案 DEK。
拜信封加密之賜，輪換現在是**就地且無損**的：`rotate-secret.sh` 會停伺服器、快照
`fs.db` + `.env`、執行 `rekey` 工具（把每個 DEK 從舊密鑰重新密封到新密鑰——檔案
payload 從不重新加密），然後更新 `.env`。不需重新上傳。

```bash
./scripts/rotate-secret.sh --stop            # 新隨機密鑰，停伺服器
./scripts/rotate-secret.sh --old <s> --new <s> --stop --dry-run   # 預覽
# 選項：--old/--new/--blobs/--data/--env/--no-backup/--dry-run
```

注意：

- **無法解封的 blob**：若有些 blob 是在**更舊**、已不再相符的密鑰下加密的（例如 `.env`
  曾重新產生過一次），`rekey` 會把這些回報為 `unwrappable` 並保持原樣——它們不會被
  目前密鑰解密，也無法重新換鑰。請查看摘要；除非找回較舊的密鑰，否則那些檔案實際上
  已經遺失。
- **回滾**：`rotate-secret.sh` 會留下 `--pre-rotate-<ts>` 的 `fs.db` 與 `.env` 快照。
  要復原，就還原那份 `.env`，再用 `--old <new> --new <old>` 反向重跑一次 rotate。
- 實務建議：當你懷疑金鑰外洩時、或按排程輪換；把舊密鑰安全保存，好隨時能回滾。

### 4.5 輪換 `ADMIN_TOKEN`

低風險、即時：

```bash
./scripts/setup-env.sh   # 會產生新的 SERVER_SECRET *和* ADMIN_TOKEN ——
                         # 注意：這也會改 SERVER_SECRET；若只想輪換 ADMIN_TOKEN，
                         # 直接編輯 .env：
# 編輯 .env：TENANT_FS_ADMIN_TOKEN=<新值>
pkill -9 -f filesrv; sleep 3; nohup ./scripts/start.sh > /tmp/tenant-fs.log 2>&1 &
```

> `setup-env.sh` 會**同時**重新產生兩個密鑰，而且絕不覆寫既有的 `.env`（會警告並退出）。
> 若要只輪換 `ADMIN_TOKEN`，請手動編輯 `.env` 再重啟。

### 4.6 新增／刪除 app 或使用者

```bash
# apps
sh scripts/filesrv-cli.sh admin app create <name>
sh scripts/filesrv-cli.sh admin app set <id> --enabled=false    # 停用
sh scripts/filesrv-cli.sh admin app delete <id>                  # 軟刪除

# 使用者（先預佈建，其 JWT 才會被接受）
sh scripts/filesrv-cli.sh admin user add <app_id> <user_id>

# 群組
sh scripts/filesrv-cli.sh admin group create <app_id> <name>
sh scripts/filesrv-cli.sh admin group member add <app_id> <name> <user_id>
```

---

## 5. 例行檢查排程

### 5.1 每日

- [ ] `curl -s http://127.0.0.1:8080/healthz` 回 `OK`。
- [ ] 伺服器程序存活：`pgrep -f 'target/release/filesrv'`。
- [ ] 日誌尾部沒有新的 `error`／`denied`／`failed` 行。
- [ ] 磁碟用量在門檻內：`df -h <data_dir>`（清理劇本見 §6.3）。
- [ ] 排定的備份工作完成並寫出 manifest。

### 5.2 每週

- [ ] **驗證**最新備份：`sqlite3 <backup>/fs.db "PRAGMA integrity_check;"` → `ok`。
- [ ] 檢查整週磁碟**成長趨勢**（透過 `admin app usage` 看每 app 用量），確認沒有 app
  悄悄逼近配額。
- [ ] 檢視稽核日誌是否有未預期動作（`admin audit --since 604800`）：找失敗登入、ACL
  變更、刪除、權杖撤銷。
- [ ] 確認備份正確輪替（舊的依 `RETENTION` 被清除）。

### 5.3 每月

- [ ] 在暫存主機／容器做**還原演練**（見 §3.4）：證明備份真的能還原、檔案能解密。
- [ ] 確認 admin UI 能載入（`curl -s http://127.0.0.1:8081/admin/` 是 HTML，不是
  404/500）。
- [ ] 檢查 Rust 依賴集合是否有新版本／CVE；若採用任何修正就重新建置。
- [ ] 檢視綁定位址：公共埠在 `0.0.0.0:8080`、admin 仍是 loopback。
- [ ] 抽查一個帶群組參照的檔案 ACL 行為仍正常（`g:<group>` → 成員可讀、非成員被拒）。

### 5.4 每季

- [ ] 考慮輪換 `ADMIN_TOKEN`（便宜）與 app 密鑰（`admin app rotate-secret`）——依政策
  需求。
- [ ] 完整容量檢視：預估成長對上配額與磁碟。
- [ ] 對暫存實例重跑一次短負載／壓力測試（突發上傳＋下載），確認沒有回歸。
- [ ] 若服務在反向代理後方，重新檢查 TLS／終止憑證。
- [ ] 確認 `.env` 的備份本身也有備份（密鑰檔的異地副本）。

---

## 6. Runbook —— 發生 X 時該怎麼做

### 6.1 服務無法啟動

**症狀**：程序立即退出；日誌顯示 bind／設定錯誤；連接埠已被占用。

**診斷**：
```bash
tail -30 /tmp/tenant-fs.log
pgrep -f 'target/release/filesrv'     # 已在執行？
ss -ltnp | grep -E '8080|8081'                  # 連接埠被舊程序佔用？
```

**處理**：
1. **連接埠被舊程序占用**：`pkill -9 -f filesrv; sleep 3`，確認 `pgrep` 為空後再重啟。
2. **`.env` 缺失／權限錯誤**：確認存在且為 `600`（`ls -l .env`）。只在真的遺失時重新
   產生——注意新產生的 `SERVER_SECRET` 將**無法**解密既有 blob（§6.5）。
3. **以 dev 預設密鑰拒絕啟動**：當 `TENANT_FS_SERVER_SECRET`／`TENANT_FS_ADMIN_TOKEN`
   仍是 dev 預設值時伺服器會 panic。請用 `./scripts/setup-env.sh` 產生真正的 `.env`
   （或手動設定）；除本機開發外**切勿**設 `TENANT_FS_DEV_ALLOW_DEFAULT_SECRETS=true`。
4. **二進制不可執行／缺失**：`chmod +x target/release/filesrv` 或重新建置
   `cargo build --release`。
5. **設定錯誤**：檢查啟動橫幅是否符合預期綁定；修正 `.env` 後重啟。

### 6.2 `/healthz` 不是 `OK`

**症狀**：`curl /healthz` 非 200、空白、或卡住。

**診斷**：日誌尾部；確認程序在監聽（`ss -ltnp | grep 8080`）；試 `curl -v`。

**處理**：
1. 程序掛掉 → §6.1。
2. 程序在但沒回應 → 可能卡住（DB 鎖／死鎖）。若可能就抓 stack／thread dump，然後重啟
   （§1.1）。
3. 連接埠錯誤——確認 `.env` 中的 `TENANT_FS_PUBLIC_BIND` 與你探測的一致。

### 6.3 磁碟滿

**症狀**：`df -h` 顯示 `data` 磁碟區接近／100%；上傳失敗；稽核表增長。

**處理**（按安全度排序）：
1. **清除舊備份**：檢查 `data/backups/` 與你的快照目標；執行 `RETENTION`；刪除已被
   取代的快照。
2. **清除快取目錄**（永遠安全）：`blobs/dec_cache/`、`blobs/exports/`、`blobs/tmp_*`。
3. **停用／啟用 app** 以停止增長：`admin app set <id> --enabled=false`，或透過
   `admin app set <id> --quota-bytes=…` 調低配額。
4. **VACUUM DB**（需要約等於 DB 大小的可用空間）：停伺服器，`sqlite3 data/fs.db
   "VACUUM;"`，重啟。
5. 若仍危急，把 blobs 移到更大的磁碟區，並把 `TENANT_FS_BLOBS` 指過去
   （更新 `.env`，重啟）。

> 避免直接刪 `blobs/`——那是資料。優先採用配額 + 清除。

### 6.4 資料庫鎖定／損壞／WAL 出問題

**症狀**：寫入時 `SQLITE_BUSY`；`PRAGMA integrity_check` 回報錯誤；日誌顯示
`database is locked`。

**處理**：
1. **忙線／鎖定**——通常是長時間交易或卡住的程序：停伺服器，確認沒有程序在寫入後才刪
   掉過期的 `-wal`／`-shm`，然後重啟。（單一程序下，鎖競爭很少見。）
2. **損壞**——停伺服器，**先備份損壞的 DB**（`cp data/fs.db data/fs.db.corrupt`），
   再嘗試復原：
   ```bash
   sqlite3 data/fs.db ".recover" > recovered.sql
   sqlite3 data/fs.db < recovered.sql          # 寫入一份全新的 DB
   sqlite3 data/fs.db "PRAGMA integrity_check;"
   ```
   若 `.recover` 無法解決，從最後一份良好備份還原（§3.3）並接受資料落差。
3. **非正常關機時 WAL 未 checkpoint**——下次啟動時 SQLite 會自動重放 WAL；若失敗，
   依步驟 2 處理。

### 6.5 Blob 解密失敗／`SERVER_SECRET` 不符

**症狀**：下載回錯誤或亂碼；還原或密鑰變更後，日誌顯示解密／`integrity` 失敗。

**處理**：
1. 確認執行的 `SERVER_SECRET` 等於建立資料時用的那個：把 `.env` 對上保存的
   `--secret-out` 檔／`--env-out`。
2. 若它變了（輪換或 `.env` 重新產生），必須還原舊密鑰——**不要**臨時重新加密。
   把原值放回，重啟。
3. 若變更是刻意的輪換，請用 `./scripts/rotate-secret.sh`（就地重新密封每個 DEK——見
   §4.4），而不是手動編輯 `.env`，否則會讓 blob 孤立。
4. 若原值遺失且 blob 已加密：資料不可復原（這是刻意的保護設計）。請從一份也擷取了
   相符 `.env` 的備份還原。

### 6.6 備份失敗

**症狀**：`backup.sh` 非零退出；WAL checkpoint 警告；副本的完整性檢查失敗；manifest
缺失。

**處理**：
1. **WAL checkpoint 警告**——備份時伺服器正在寫入。停伺服器、重跑備份、重啟。
2. **目標在資料目錄內**——script 會拒絕；另選目標。
3. **副本完整性檢查失敗**——不要用它。調查來源 DB（§6.4）、修正、重新備份。
4. **找不到 `.env`**——確認 `.env` 在預期路徑存在，或明確傳 `--env <file>`。

### 6.7 還原失敗

**症狀**：伺服器啟動但檔案缺失／錯誤；完整性失敗；密鑰不符。

**處理**：
1. **密鑰不符** → §6.5（還原相符的 `.env`／密鑰）。
2. **拷貝不完整**——重新同步；確認 `fs.db` 與 `blobs/` 都在（`ls`、`du`）。
3. **還原後 DB 完整性失敗**——備份壞了（§6.6）；試較舊的快照。
4. **冒煙測試失敗**——§3.3 還原步驟 6：驗證一次真實下載，而不只是 `/healthz`。

### 6.8 憑證洩漏（`SERVER_SECRET`、`ADMIN_TOKEN`、app secret）

**處理**：
1. **`ADMIN_TOKEN` 洩漏**——立即輪換（§4.5）。便宜、無資料影響。
2. **app secret 洩漏**——`admin app rotate-secret <id>`；舊密鑰立即失效。
3. **`SERVER_SECRET` 洩漏**——最糟情況：攻擊者可解密每個 blob，**且**輪換會破壞
   解密。依 §4.4 規劃：輪換 + 重新加密（或接受重新上傳），並檢查外洩的媒體是否也含
   blob。
4. 任何情況下：檢視稽核日誌找濫用跡象（§6.9），並在更動金鑰前考慮做一次完整備份。

### 6.9 可疑活動（稽核檢視）

**診斷**：
```bash
sh scripts/filesrv-cli.sh admin audit --since 604800
sh scripts/filesrv-cli.sh admin audit --app-id <N> --since 86400
```

**要找**：重複的失敗登入、未預期的 ACL 授予（尤其是 `g:`／`*`／`public_read`）、大量
刪除、不是你發出的權杖撤銷、你沒要求的匯出、群組成員變更。

**處理**：撤銷受影響的權杖／密鑰（§6.8）、還原 ACL 變更、移除未預期的群組成員、留存
稽核證據，並考慮隔離該 app（`--enabled=false`）。

### 6.10 高 CPU／記憶體／流量尖峰

**診斷**：
```bash
top -b -n1 | head -20          # 哪個程序？
tail -200 /tmp/tenant-fs.log   # 哪些請求？
sh scripts/filesrv-cli.sh admin app usage
```

**處理**：
1. 單一 app 飽和——檢查其用量；設定／調低配額；暫時停用
   （`admin app set <id> --enabled=false`）。
2. 流量洪流——API 有 HMAC+nonce 保護，但行為不當的 client 仍可能燒 CPU。在防火牆／
   代理擋掉來源 IP，或限流。
3. 若持續且合法，擴充主機（CPU/RAM）或把 blobs 移到更快的儲存。

### 6.11 升級弄壞了它 —— 回滾

1. 停止伺服器。
2. 還原**先前**的 `target/release/filesrv` 二進制。
3. 若新二進制也執行了舊版看不懂的 DB 遷移，就從升級前（§4.3 步驟 2）的備份還原
   `data/fs.db`。
4. 啟動、驗證 `/healthz`，然後附上遷移失敗細節開一份報告。

### 6.12 Admin UI 空白／資源缺失

**症狀**：`http://127.0.0.1:8081/admin/` 顯示空白；console 回報 `style.css`／`app.js`
404 或 CSP 違規。

**診斷**：UI 是編譯進二進制的（`include_str!`），由 loopback admin 監聽器提供。重新
載入並檢查 network tab。

**處理**：
1. 若你編輯了 UI，必須**重新建置**（`cargo build --release`）並重啟——資源在編譯期
   嵌入。
2. 務必用**帶尾斜線**的 `/admin/` 載入；`/admin` 會重新導向，否則相對資源會解析到
   錯誤的根。
3. 若 CSP 擋掉樣式表（console 標記 `style-src`），那是程式 bug——修正 CSP 檔頭／內聯
   樣式、重新建置、重啟。

### 6.13 上傳／下載錯誤

**診斷**：讀錯誤 body（有 `code` + `request_id`），檢查請求大小、權杖有效性、ACL、
配額。

**處理**：
- **Payload 過大** → `max_payload_bytes` 上限；依 app 調高
  （`admin app set <id> --max-payload-bytes=…`）或拆分檔案。
- **超出配額** → `usage_bytes >= quota_bytes`；調高配額或清除。
- **權杖無效／已撤銷／過期／IP 不符** → 發出新權杖；權杖在 TTL 內具冪等性（除非被撤銷）。
- **ACL 拒絕** → 確認使用者是某個允許群組（`g:`）的成員、是 `*`／owner、或適用
  `public_read`；檢查 `app_users` 註冊（JWT 有效但使用者未預先佈建仍會 401）。
- **損壞／儲存錯誤** → §6.4 / §6.5。

### 6.14 時間偏差簽章被拒

**症狀**：app 呼叫回時間戳視窗錯誤；`X-Timestamp` 離伺服器時間很遠。

**處理**：HMAC 用 ±300 秒視窗。修正**用戶端**時鐘（NTP）或伺服器時鐘，看哪邊偏差。
確認兩者都用 UTC。時鐘修正後重試（nonce 重放防護意味著被拒的請求無法原樣重放）。

### 6.15 意外刪除資料 —— 復原

1. **立即停伺服器**以凍結狀態。
2. 從最近的快照還原（§3.3）——這會回到那個時間點；更新的東西在你先備份前會遺失。
3. 若只刪了部分檔案／app：還原前考慮先匯出目前 DB 狀態，手動合併落差。
4. 還原後驗證每 app 用量與一次冒煙下載。

---

## 7. 附錄

### 7.1 關鍵檔案與連接埠

| 項目 | 值 |
|---|---|
| 二進制 | `target/release/filesrv` |
| 設定／密鑰 | `.env`（專案根目錄，mode 600） |
| 資料 | `data/`（`fs.db` + `blobs/`） |
| 內建備份 | `data/backups/<name>/`（`db.sqlite`、`blobs.tar`、`manifest.json`） |
| 快照備份 | 你傳給 `backup.sh` 的任何目標（`fs.db`、`blobs/`、可選 `.env`） |
| 公共 API | `0.0.0.0:8080`（`/v1/*`、`/healthz`、`/.well-known/security.txt`） |
| Admin API + UI | `127.0.0.1:8081`（`/admin/*`） |
| CLI | `scripts/filesrv-cli.sh` |
| 日誌 | 你啟動 `start.sh` 時導向的那個檔案 |

### 7.2 環境變數（`.env`）

| 變數 | 用途 | 備註 |
|---|---|---|
| `TENANT_FS_SERVER_SECRET` | blob 加密根金鑰 | 備份 → 還原間必須穩定（§6.5） |
| `TENANT_FS_ADMIN_TOKEN` | admin API/UI 的 bearer token | 便宜輪換（§4.5） |
| `TENANT_FS_DEV_ALLOW_DEFAULT_SECRETS` | 僅供開發的逃逸口 | 密鑰仍為 dev 預設時伺服器拒絕啟動，除非設 `true` |
| `TENANT_FS_AUDIT_DOWNLOADS` | 逐次下載稽核 | 預設 `false`（關閉） |
| `TENANT_FS_PUBLIC_BIND` | 公共監聽位址 | 預設 `0.0.0.0:8080` |
| `TENANT_FS_ADMIN_BIND` | admin 監聽位址 | 預設 `127.0.0.1:8081` |
| `TENANT_FS_DB` | SQLite 路徑 | 預設 `data/fs.db` |
| `TENANT_FS_BLOBS` | blob 根 | 預設 `data/blobs` |
| `TENANT_FS_BACKUP_ROOT` | 內建備份目錄 | 預設 `data/backups` |
| `TENANT_FS_BACKUP_RETENTION` | 內建備份保留份數 | 預設 7 |
| `TENANT_FS_BACKUP_SCHEDULE_SECS` | 內建備份排程間隔 | `0` = 關閉 |
| `TENANT_FS_MAX_*` | 批次 ACL／payload／配額上限 | 依上限 |

### 7.3 指令速查

```bash
# 營運
./scripts/setup-env.sh                          # 建立 .env（絕不覆寫）
./scripts/start.sh                              # 啟動（導向日誌）
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

### 7.4 災難復原計畫摘要

1. **異地**：至少保留一份快照 + `.env`（經 `--env-out`）在與線上資料不同的主機／區域。
2. **復原目標**：任何 Linux 主機，只要帶同一個 `target/release` 二進制、還原的 `data/`
   與相符的 `.env`。
3. **步驟**：停 → rsync 資料回去 → 還原 `.env` → `integrity_check` → 啟動 →
   `/healthz` → 冒煙下載。
4. **RTO/RPO**：由快照頻率與一次 `rsync` 還原的耗時決定；每月測試一次（§5.3）。
