# Tenant File Server — Admin API（僅限 loopback）（繁體中文）

> 本頁為繁體中文版。English: [`../../development/admin-api.md`](../../development/admin-api.md)
> 範圍：營運者／管理員端點，**只綁定在 loopback admin 介面上**——絕不暴露於公共
> router。
> Base path：`http://127.0.0.1:<admin-port>/admin/v1`
> 驗證：`Authorization: Bearer <ADMIN_TOKEN>`——此介面**永不**接受 `X-App-Key` /
> HMAC。
> 傳輸：預設為 loopback 上的純 HTTP；若 admin bind 可能被他機觸及，請在反向代理／
> 防火牆終止。
> **App-facing API** 另外記載於 `Documents/en/api.md`（及 `Documents/zh/api.md`）；
> 本檔是與之對應的 admin 端文件。

---

## 1. 概覽

- 這裡所有操作都會改動伺服器／租戶狀態，因此需要 admin bearer token，且只監聽
  `TENANT_FS_ADMIN_BIND`（預設 `127.0.0.1:8081`）。
- Web 控制台與本機 CLI（`scripts/filesrv-cli.sh`）都是這些端點的輕量 client。
- 控制台回應套用加固檔頭：`Content-Security-Policy`、`X-Frame-Options: DENY`、
  `Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、
  `Referrer-Policy: no-referrer`。

---

## 2. 管理控制台（靜態資源）

一個小型 HTML/JS 控制台在編譯期嵌入，且**只在** loopback admin bind 上提供；
公共 router 會對其全部回 404。

| Method | Path | 說明 |
|---|---|---|
| GET | `/admin` | 308 → `/admin/` |
| GET | `/admin/`, `/admin/index.html` | HTML 外殼 |
| GET | `/admin/app.js`, `/admin/style.css` | client 端資源 |

頁面是純 client-side：它在 `sessionStorage` 存放 admin bearer token，並自己呼叫
`/admin/v1/*`。靜態資源裡不含任何資料。

---

## 3. Apps

| Method | Path | 說明 |
|---|---|---|
| POST | `/admin/v1/apps` | 建立 app → `{app_id, app_key, app_secret}`（**密鑰只回傳一次**） |
| GET | `/admin/v1/apps` | 列出含用量／配額（含軟刪除 app、`enabled=false`） |
| GET | `/admin/v1/apps/{id}` | 詳細；軟刪除 app → `404` |
| PATCH | `/admin/v1/apps/{id}` | `{enabled?, quota_bytes?, max_payload_bytes?}` |
| POST | `/admin/v1/apps/{id}/secret/rotate` | 輪換密鑰（舊密鑰立即失效） |
| DELETE | `/admin/v1/apps/{id}` | 軟刪除（立即停用） |
| GET | `/admin/v1/apps/{id}/usage` | `usage_bytes / quota_bytes / file_count / active_token_count` |
| POST | `/admin/v1/apps/{id}/users` | 預先佈建使用者：`{"user_id": "..."}`（`INSERT OR IGNORE`） |
| GET | `/admin/v1/apps/{id}/users` | 列出該 app 已預先佈建的使用者 |
| POST | `/admin/v1/apps/{id}/groups` | 建立群組：`{"name": "..."}`（空成員） |
| GET | `/admin/v1/apps/{id}/groups` | 列出群組（各含成員） |
| GET | `/admin/v1/apps/{id}/groups/{name}` | 群組詳細 + 成員 |
| DELETE | `/admin/v1/apps/{id}/groups/{name}` | 刪除群組 |
| POST | `/admin/v1/apps/{id}/groups/{name}/members` | 新增成員：`{"user_id": "..."}` |
| DELETE | `/admin/v1/apps/{id}/groups/{name}/members/{user_id}` | 移除成員 |

### 使用者群組

群組讓營運端能依成員資格授權，而不用在每個檔案 ACL 裡逐條列出每個 `user_id`。
檔案 ACL 規則可以 `g:<group>` 參照群組（例如
`{"action":"read","add":["g:eng"]}`）——任何已註冊、且是該群組成員的使用者，就會被
允許該動作。群組成員透過上述 admin API 管理；一個群組只作用於單一 app。

規則：

- 群組名稱：`1..=64` 字元，不可含 `/`、`\` 或空格；每 app 內唯一。
- 新增既有成員具冪等性；移除不存在的成員是 no-op。
- 刪除群組**不會**改寫既有的檔案 ACL——對已刪除群組的 `g:<name>` 參照只是匹配不到
  任何人（使用者失去該存取權）。
- 成員資格本身**不會**賦予使用者 JWT 有效性；使用者仍必須先註冊在 `app_users`
  （見 `/apps/{id}/users`），其 user-context JWT 才會被接受。

```json
// 建立群組
POST /admin/v1/apps/{id}/groups   {"name": "eng"}
// 新增成員
POST /admin/v1/apps/{id}/groups/eng/members   {"user_id": "alice"}
```

### 建立請求

```json
{
  "name": "my-app",
  "quota_bytes": 1073741824,
  "max_payload_bytes": 67108864
}
```

建立回應（`app_secret` 只顯示一次，之後無法再取回——請在伺服器端妥善保存）：

```json
{
  "app_id": 3,
  "app_key": "app_YRhbtjMbi9g88KJh",
  "app_secret": "vuk0a5dZPtRO6Uy/dEllSdjJxoCOJPLr7EPfTANzF7U=",
  "enabled": true,
  "name": "my-app",
  "quota_bytes": 1073741824,
  "max_payload_bytes": 67108864
}
```

`user_id` 沿用與上傳路徑相同的驗證規則，因此匯出檔的條目名稱永遠不可能包含穿越序列。

---

## 4. 稽核

| Method | Path | 說明 |
|---|---|---|
| GET | `/admin/v1/audit?app_id=&since=` | 查詢稽核日誌（append-only），最新在前，LIMIT 200 |

過濾器：`app_id`（整數）與 `since`（Unix 秒）。每筆帶有
`at, actor, action, app_id, target, ip, decision`。

下載**預設不記稽核**（維持高讀取負載下的日誌量小）。設 `TENANT_FS_AUDIT_DOWNLOADS=true`
會為每次成功的 GET 記錄一條 `download` 列（actor 為 `token`，target 為 storage uuid）。

---

## 5. 備份

| Method | Path | 說明 |
|---|---|---|
| POST | `/admin/v1/backups/run` | 同步執行一次備份——見 §6 |
| GET | `/admin/v1/backups` | 列出已知備份，最新在前（`id, backup_id, status, created_at, finished_at, size, path`） |
| GET | `/admin/v1/backups/{id}` | 詳細，含 `target_path` 與解析後的 manifest；未知 id → `404` |
| PATCH | `/admin/v1/backups/config` | 設定——見下（此端點無 GET） |

`PATCH /admin/v1/backups/config` body：

```json
{ "schedule"?: 86400, "target"?: "nightly", "retention"?: 7 }
```

- `schedule`：每次執行的間隔秒數（0 = 關閉）。`target`：`TENANT_FS_BACKUP_ROOT` 之下的
  **相對**目錄名稱（會 canonicalize 並 `starts_with(root)`；絕對路徑、`..`、`:` 與
  `\` 一律拒絕）。`retention`：1..1000。
- 回傳有效的 `{schedule_secs, target, retention}`。會持久化到 DB，並套用於下次執行。

---

## 6. 備份與災難復原

`POST /admin/v1/backups/run` 會在 `TENANT_FS_BACKUP_ROOT`（預設 `data/backups`）之下
產生一個備份目錄，內含：

- `db.sqlite` —— 透過 `VACUUM INTO` 取得的一致 DB 快照；
- `blobs.tar` —— 信封加密的 app blob 樹（略過 `dec_cache/`、已完成的匯出與
  `tmp_*` 分片）；
- `manifest.json` —— 每個檔案的名稱、大小與 sha256。

回應：

```json
{
  "backup_id": "bk_…",
  "id": 2,
  "status": "ready",
  "size": 152172544,
  "files": [ { "name": "...", "size": 123, "sha256": "..." } ]
}
```

- **備份中絕不會出現金鑰材料**：`SERVER_SECRET`、admin token 與 app secret 都留在部署
  環境中。DB 快照包含 `apps.secret_sealed`（以 KEK 密封的 app secret），沒有
  `SERVER_SECRET` 就毫無用處。因此被偷走的備份只會是不可開啟的密文。
- **保留份數**保留最新的 N 份（`TENANT_FS_BACKUP_RETENTION`，預設 7；可透過
  `PATCH /backups/config` 覆寫為 1–1000）。過時的目錄與列會被移除。
- **排程**預設關閉（`TENANT_FS_BACKUP_SCHEDULE_SECS=0`）。設 > 0（或在 DB 中覆寫）時，
  維護迴圈會在上次備份後間隔到期時觸發一次執行。
- **目標白名單**：`target` 必須是相對目錄名稱；會被 canonicalize 且必須留在備份根目錄
  內——絕對路徑、`..`、`:` 與 `\` 都會被拒絕，擋掉路徑／symlink 逃逸。

**還原**（營運端手動程序；目前沒有還原端點）：停止伺服器，把快照 `fs.db` 放回、
把 `blobs.tar` 解回 blob 根目錄，再以相同的 `SERVER_SECRET` 啟動伺服器。缺失的 blob
檔案在下載時會顯示為「File content missing.」。

---

## 7. 金鑰政策（營運端視角）

- `SERVER_SECRET` 只存在於部署環境中，**永不**被複製進備份、磁碟區快照或 CI fixture。
- KEK 是 `SHA-256(SERVER_SECRET)`，既用來密封 app secret（`apps.secret_sealed`），也
  用來包裹每個 blob 的每檔案 DEK（AES-256-GCM 信封）。同一段明文的兩次加密必不同。
- 金鑰材料永不寫入日誌。

---

## 8. 路線圖（admin 範圍，尚未實作）

| 功能 | 備註 |
|---|---|
| 備份**還原**端點 | 備份會產生；還原目前是手動營運程序（§6）。 |
| 營運者／稽核者角色分離 | 目前單一共用 `ADMIN_TOKEN`；無角色拆分。 |
| 匯出完成時的 webhook / 推播通知 | 請改為輪詢狀態端點。 |

> 注意：`TENANT_FS_ADMIN_TOKEN` 仍有 development 預設值；伺服器會打印響亮的啟動
> WARNING（與 `SERVER_SECRET` 同樣處理）。生產環境請兩者都明確設定。
