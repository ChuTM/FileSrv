# 維護手冊

本文檔是文件服務器的運維配套：備份數字的含義、出問題時怎麼辦、以及日常檢查計劃。結構與 `deploy.md` 對應，命令保留英文。

---

## 1. 備份與保留策略

### 1.1 備份如何工作

- `scripts/backup.sh` 會在 `$BACKUP_ROOT`（默認 `data/backups/`）下按時間點生成一份拷貝，每次備份一個目錄，命名為 `bk_<id>`。
- 一份備份包含：數據庫（`data/fs.db`）、blob 存儲（`data/blobs`），以及——**默認包含**——`.env` 文件。這樣完整恢覆時能把數據和密鑰（服務端密鑰、管理 token、綁定配置）一起還原。
- Settings 頁的 Backup 卡片讀取這些信息並顯示：備份根目錄、當前保留的份數、保留上限、備份總字節數，以及最近一次備份的 id / 狀態 / 時間。

### 1.2 “Retention: 7 copies”是什麼意思

`.env` 中設置 `RETENTION=7`。這是**磁盤上最多保留的備份代數**。行為很簡單：

- 任何時刻，服務器最多保留 `RETENTION` 份備份（默認 7 份）。
- 當新備份創建時，如果已經存在 `RETENTION` 份，會自動刪除**最舊**的一份。因此你始終保留最近的 7 代，永遠不會無限堆積。
- Settings 中 “Copies kept” = 當前實際存在的備份份數，“Retention” = 配置的上限。兩者獨立讀取：如果本周期還沒跑過備份，份數可以低於上限。
- **想保留更多歷史**：調高 `.env` 里的 `RETENTION`（更占磁盤）。**想省空間**：調低。該值在啟動時讀取，改後需重啟服務。

### 1.3 恢覆

- `scripts/restore.sh` 會把一份備份解回線上 `data/`（或你指定的目標目錄）。具體命令與安全注意事項見 `deploy.md` 的 “Backup / restore” 章節。正式依賴恢覆前，務必先在臨時目錄完整測一次恢覆。

---

## 2. 常規檢查計劃

### 每日
- 確認服務在線：`curl http://127.0.0.1:8080/healthz` 應返回 `OK`。
- 查看最近一次備份時間是否正常（不是悄然過期）。
- 大致看下磁盤用量；blob 存儲會隨每次上傳增長。

### 每周
- 打開 Settings → **Storage Maintenance**，運行 **Audit files (integrity)**，校驗磁盤上每個 blob 是否存在、大小與 SHA-256 是否一致。
- 確認 “Copies kept” 在保留上限內、備份仍在正常生成。
- 核對可用磁盤空間與 `data/fs.db` + `data/blobs` + `data/backups` 的合計。

### 每月
- 在臨時目錄完整測一次恢覆流程。
- 翻閱 admin 審計日志，查找失敗或可疑請求。
- 若服務端密鑰曾泄露或共享過，按 3.4 輪換。

---

## 3. 常見問題處理

### 3.1 服務起不來

- 看啟動日志：`./scripts/start.sh` 會打印解析後的綁定信息。
- 常見原因：
  - 端口被占用 → 先停舊進程（`pkill -9 -f filesrv`）再啟動。
  - `.env` 缺失或格式錯誤 → 運行 `./scripts/setup-env.sh`（不會覆蓋已有 `.env`），再檢查 `TENANT_FS_DB` 與 `TENANT_FS_BLOBS` 指向可寫路徑。
  - 數據庫被鎖 / 損壞 → 見 3.5。

### 3.2 備份失敗

- 檢查 `$BACKUP_ROOT` 所在磁盤是否有空間。
- 檢查 `.env` 是否可讀（備份會包含 `.env`；若讀不到，備份可能照常進行但不含密鑰，恢覆後就沒有密鑰）。
- 確認上一個備份目錄沒有被其他進程鎖定。
- 若備份寫到一半，retention 清理的是最舊的完整備份，不會清理正在寫入的那份；只有在確認沒有進程寫入後，才手動刪除半成品 `bk_*` 目錄。

### 3.3 Audit 報 “missing” 文件（孤兒 blob）

`Audit files` 會遍歷每條文件記錄，檢查其 blob 在磁盤上是否存在、大小與 SHA-256 是否匹配。結果字段含義：

| 字段 | 含義 |
|---|---|
| `checked` | 掃描的文件記錄數 |
| `ok` | 存在且正確的 blob 數 |
| `missing` | 數據庫有記錄，但 blob 文件**已從磁盤消失** |
| `size_mismatch` | blob 存在，但字節大小與記錄不一致 |
| `sha_mismatch` | blob 存在，但哈希與記錄不一致 |
| `bytes_ok` | 通過校驗的總字節數 |

**`missing` 是最需要關注的。** 它表示數據庫仍引用一個磁盤上已不存在的 blob 文件——通常是手動清理 `data/blobs`、中斷的 wipe、或未完整恢覆的備份導致的。該文件內容**已永久丟失**，無法從磁盤找回。清理步驟：

1. 找出缺失 blob 屬於哪個 app：
   `sqlite3 data/fs.db "SELECT app_id, blob_path FROM files WHERE blob_path LIKE '<sample>';"`
2. 確認該 app 以及你能接受這份丟失。
3. 刪除孤兒文件記錄，讓數據庫不再引用不存在的文件（這是一個有意的、手動步驟——系統刻意不做用戶數據的自動刪除）。
4. 重新運行 Audit files，`missing` 應變為 `0`。

> `size_mismatch` / `sha_mismatch` 通常意味著損壞或寫入中斷；如果有備份，先從備份恢覆該 blob，否則視為丟失。

### 3.4 輪換服務端密鑰

- 使用 `scripts/rotate-secret.sh`；針對某個 app 自身密鑰，可用 admin 里的 **Rotate Secret** 操作。腳本會先備份 `.env`、生成新的 `TENANT_FS_SERVER_SECRET` 並重寫 `.env`。
- 如果 blob 是用舊密鑰加密的，輪換後請運行 `blob_rekey`（見 `deploy.md`），讓已有內容在輪換後仍可讀。
- 輪換後，之前簽發的所有 HMAC 簽名 / 用戶 JWT 立即失效。繼續前先更新後端。
- 管理 token（`TENANT_FS_ADMIN_TOKEN`）可單獨通過 `filesrv admin rotate-token` 輪換——CLI 會先備份、輪換、打印新 token，並重寫 `.env`。確認風險提示後，更新所有持有舊 token 的地方。

### 3.5 數據庫損壞或被鎖

- 先停服務。
- 若 SQLite 報損壞，用最新備份恢覆數據庫（`restore.sh`）——這正是備份要包含數據庫的原因。
- 服務運行期間絕不要刪除 `data/fs.db`（SQLite 鎖）。
- 恢覆後運行 Audit files，確認 blob 與恢覆出的記錄仍能對上。

### 3.6 磁盤滿

- 無空間時服務器拒絕寫入，上傳會幹凈地失敗。
- 釋放空間的辦法：調低 `RETENTION`、wipe 已歸檔的 app（Wipe out 會刪除它們的 blob）、或把 `data/blobs` 通過 `TENANT_FS_BLOBS` 移到更大的磁盤。
- 釋放空間後運行 Audit files，確認 blob 存儲完好。

### 3.7 管理 token 丟失

- token 只存在於 `.env` 和 admin 會話里，其他地方不會落盤。若丟失，請在機器上輪換（見 3.4），而不是猜測。
- admin API 只綁定本機（`127.0.0.1:8081`）；把它當作 loopback 控制面。

### 3.8 更新 Web UI / 二進制

admin 控制台的靜態資源（`login.html`、`dashboard/*.html`、`app.js`、
`dashboard.css`、`style.css`、`gsap.min.js`）在 `src/admin_ui.rs` 里通過
`include_str!` **編譯期嵌入**進二進制，運行時並不讀磁盤文件。所以只改文件
本身沒有任何效果——`start.sh` 只是啟動已編譯好的二進制，它不會重新編譯。

更新步驟：

1. 編輯 `src/admin_ui/static/…` 下的文件。
2. 改過的靜態資源要**遞增版本號**（否則瀏覽器會用緩存舊版）。例如：
   ```bash
   sed -i '' 's/app.js?v=16/app.js?v=17/g' \
     src/admin_ui/static/login.html src/admin_ui/static/dashboard/*.html
   # 改了 CSS 就同步遞增 dashboard.css?v=N
   ```
3. 重新編譯——這一步才把文件打進二進制：
   ```bash
   cargo build --release
   ```
4. 重啟：
   ```bash
   pkill -9 -f 'target/release/filesrv'; sleep 2
   nohup ./scripts/start.sh > /tmp/filesrv.log 2>&1 &
   ```

只改 Rust 代碼（路由/邏輯）同樣需要編譯 + 重啟；版本號只針對靜態資源。

---

## 4. 速查表

| 關注項 | 位置 |
|---|---|
| 數據庫 | `data/fs.db`（`$TENANT_FS_DB`） |
| Blob 存儲 | `data/blobs`（`$TENANT_FS_BLOBS`） |
| 備份 | `data/backups`（`$BACKUP_ROOT`） |
| 密鑰 / 配置 | `.env` |
| 備份腳本 | `scripts/backup.sh` |
| 恢覆腳本 | `scripts/restore.sh` |
| 密鑰輪換 | `scripts/rotate-secret.sh` |
| 管理 CLI | `filesrv admin …` |
| 完整性審計 | Settings → Storage Maintenance → Audit files |
