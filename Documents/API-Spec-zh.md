# 多租戶檔案儲存服務 — API 規範（中文版）

> 版本：v1.0　類型：API 使用規範（對齊實際實作）
> 基準路徑（App API）：`https://<host>/v1`
> 管理路徑（Admin API）：`http://127.0.0.1:<admin-port>/admin/v1`（僅本機）
> 傳輸：HTTP/HTTPS｜版本化：`/v1`｜內容類型：`application/json`

---

## 1. 概覽

- 身分分四種，對應不同端點（見 §2）。
- 所有資料操作（上傳／列舉／meta／刪除／導出／下載）都經過統一鑑權＋規則閘道，**deny-by-default**。
- 每個請求最終判決寫入審計日誌（可追溯）。
- 錯誤一律回傳統一 JSON 錯誤模型（§1.1），HTTP 狀態碼語意化。
- **語言**：所有 API 輸出（response payload、欄位值、錯誤 `message`）一律使用**英文（en-US）**；本文件為中文翻譯，僅屬文件敘述，不屬 API 輸出。

### 1.1 錯誤模型

```json
{
  "error": {
    "code": "app_not_found",
    "message": "App not found or disabled.",
    "request_id": "req_01J..."
  }
}
```

---

## 2. 鑑權方式

| 標識 | 機制 | 端點 |
|---|---|---|
| App 級 | `X-App-Key` + `X-App-Signature`（HMAC） | 上傳、導出、generate（以 App 身分） |
| 使用者級 | `Authorization: Bearer <user-jwt>`（App 以自身 secret 簽署） | 上傳、列舉、meta、刪除、generate（以使用者身分） |
| 能力 token | `GET /v1/download/<token>` — 無需 App Key | 下載 |
| 管理 | `Authorization: Bearer <admin-token>`（僅 loopback） | admin 端點 |

### 2.1 App 層 HMAC 簽名

- `X-App-Key`：應用的公開識別符。
- `X-App-Signature`：以 `app_secret` 對「canonical request + timestamp + nonce」簽署的 HMAC-SHA256。
- `X-Timestamp` 與 `X-Nonce` 必帶（防重放：±300 秒時間窗、nonce 不得重複）。

```
signature = HMAC_SHA256(app_secret, "<method>\n<path>\n<query>\n<body-hash>\n<timestamp>\n<nonce>")
```

### 2.2 user-context JWT（委派身份）

App 後端用它的 secret 替最終使用者簽短效 JWT（內含 `user_id`）；伺服器驗籤後以 JWT 為準。**請求體／header 自帶的 `user_id` 一律忽略並覆蓋。**

```json
{ "iss": "app:{app_id}", "sub": "u_8f3a…", "exp": 1800000000, "scope": "files:rw" }
```

---

## 3. 規則與 ACL（分動作）

`user_id` 是 App 指定的不透明識別符（不是顯示名），App 內唯一。

```json
{
  "owner": "u_8f3a",
  "read":   ["u_2c9d", "group:team_ops"],
  "write":  ["u_2c9d"],
  "delete": [],
  "list":   ["u_2c9d", "group:team_ops"],
  "export": ["group:admins"],
  "deny":   ["u_mallory"],
  "public_read": false
}
```

- `"*"` = 所有人；`group:{name}` = 群組；**`deny` 優先於一切 allow。**
- **繼承**：檔案若無顯式 ACL，向上繼承資料夾→祖先→App 預設；**`deny` 全鏈收集、檔案蓋不掉繼承的 deny**；owner 預設可存取（除非被 deny）。
- **誰能改 ACL**：① User 層 — 只有 **owner** 能改自己擁有檔案的 ACL；② **App 層（tenant admin）** 能改 App 內**任一**檔／資料夾 ACL，含批量與資料夾遞迴（見 §8.4、§8.5）。

---

## 4. 上傳 API

### `POST /v1/upload`

以 **user-context JWT** 或 **App 身分** 呼叫。

| Header | 值 |
|---|---|
| `Authorization: Bearer <user-jwt>` 或 `X-App-Key`+`X-App-Signature` | 身分 |
| `X-User-Id` | **App 級上傳必帶** — App 擔保的使用者 |
| `Content-Type` | 檔案 MIME（原樣儲存；伺服器不從檔名推測） |

Body：檔案內容（先串流寫入暫存檔，再驗證）。

| Header | 值 |
|---|---|
| `Idempotency-Key` | **選填** — 重試冪等防護（見 §4.2） |

回應 `200`：

```json
{
  "file_id": 3,
  "app_id": "app_1",
  "owner": "u1",
  "storage_uuid": "a5cd67dc-...",
  "size": 1048576,
  "sha256": "9b1deb4d...",
  "classification": "internal",
  "content_type": "application/octet-stream"
}
```

- 剝離原始檔名；內容以不透明 UUID 寫入該 App 專用目錄。`logical_path` 與下載檔名均為 storage UUID。
- 邊傳邊卡 `max_payload_bytes`：超過→`413`；配額滿→`429`。
- 可選 `?folder_id=` query 指定目標資料夾（必須屬於該 App）。

### 4.2 上傳冪等重試

`POST /v1/upload` 可帶用戶端自行生成的 `Idempotency-Key` 標頭。在設定視窗內
（`TENANT_FS_IDEMPOTENCY_WINDOW_SECS`，預設 3600 秒，下限 60 秒），**同一身分**帶**同一 key** 重試時，直接回傳**首次**上傳結果——不重複寫 blob、不重複計費額。視窗過期後 key 失效，等同新上傳。快取在記憶體內（最佳努力的重試防護，非持久佇列），硬容量 `TENANT_FS_IDEMPOTENCY_MAX_ENTRIES`（預設 10000，LRU 淘汰）。

### 4.3 分塊／斷點續傳上傳

大檔案或不穩定網路使用三步式工作階段：

| 步驟 | 方法與路徑 | 行為 |
|---|---|---|
| 1. init | `POST /v1/upload/init` | Body `{ "total_size"?: <位元組>, "folder_id"?: <id> }`。回傳 `{ "upload_id": "up_…", "status": "open", "total_size", "received_size": 0, "chunk_ttl_secs", "max_payload_bytes" }`。`total_size > 0` 若超過 App 的 `max_payload_bytes` → 拒絕。 |
| 2. chunk | `PUT /v1/upload/{upload_id}` | 原始 chunk 本文，標頭 `X-Chunk-Offset: <位元組偏移>`。chunk 必須**連續**到達：offset 必須等於伺服器目前 `received_size`。錯位 → `409`，回傳 `{ "error": { "code": "conflict", "message": "Unexpected chunk offset; resume at N." } }`，用戶端可對準續傳。App 級 HMAC 逐 chunk 驗簽。回傳 `{ "upload_id", "received_size", "status": "open" }`。 |
| 3. finalize | `POST /v1/upload/{upload_id}/finalize` | 校驗接收位元組數等於 `total_size`、原子複查配額、對暫存檔算 SHA-256、經儲存層加密落盤（見 §13），回傳與 `POST /v1/upload` 相同的中繼資料形狀。 |

- 身分規則同 `POST /v1/upload`（User JWT，或 App HMAC 帶 `X-User-Id`）；未知／過期／跨租戶工作階段 → `404`。
- 中斷的工作階段於 `TENANT_FS_UPLOAD_TTL_SECS`（預設 86400 秒，下限 60 秒）後過期，暫存檔由背景任務清除。
- 三個呼叫都計入每 App 限流（§11）。

---

## 5. 生成下載連結

### `POST /v1/links/generate`

以 **App 身分** 或 **user-context JWT** 呼叫（僅請求，token 由伺服器鑄幣）。

```json
{
  "file_id": 3,
  "ttl_seconds": 1800,
  "scope": "embed",
  "allowed_ip": "203.0.113.45"
}
```

- `scope: "embed"`：**冪等** — 同 (file, user, scope) 回傳**同一個** token，TTL 自首次起算、刷新不續命。以請求使用者鍵控（User JWT 用 `user_id`；App 身分回退 `file.owner`）。
- `scope: "share"`：一次性分享 — 每次新 token，可綁 `allowed_ip`。
- 伺服器重查檔、重跑 ACL、deny-by-default；`file_id` 不屬於當前 app → `404`。

回應 `200`：

```json
{
  "token": "tk_....",
  "url": "/v1/download/tk_....",
  "scope": "embed",
  "expires_at": 1800000000,
  "reused": false
}
```

（`reused:true` 表示回傳了既有 token。）

---

## 6. 下載 API

### `GET /v1/download/:token`

面向終端使用者，**無需 App Key**。能力 token 綁定 `(app_id, file_id, TTL)`；share token 可另綁 client IP。

- Token 過期／撤銷 → `404`（隱藏存在性）。
- 支援 **Range**（`206`）、`ETag`、`If-None-Match`（→`304`）；不滿足的 range → `416`。
- 安全標頭：`Content-Disposition: attachment`＋`X-Content-Type-Options: nosniff`。
- **IP 綁定用的 client IP**：預設取 TCP peer IP；`X-Forwarded-For` 僅在受信代理模式（`TENANT_FS_TRUST_XFF=true`）下才採用，否則偽造 header 無效。

### `HEAD /v1/download/:token`

鑑權、token 規則與 404 語意與 `GET` 完全相同，但只回應標頭、無本文。回傳 `Content-Length`、`ETag`（`"sha256-<hex>"`）、`Content-Type`、`Content-Disposition`、`X-Content-Type-Options: nosniff`；`If-None-Match` → `304`；未知／過期 token → `404`。用於串流前預先探知大小／etag。

---

## 7. 撤銷 Token

### `POST /v1/tokens/revoke`

以 **App 身分** 呼叫。撤銷後 token **即時失效**；下次 generate 會鑄**新** token。

```json
{ "token": "tk_...." }
```

回應 `200`：`{ "revoked": true }`；未知 token → `404`。

---

## 8. 檔案與資料夾 CRUD

### 8.1 檔案

`GET /v1/files/:id` — 取得 meta。需 `read` 權限。

`GET /v1/files?folder_id=&cursor=` — 列舉，游標分頁，`WHERE app_id = 身份.app_id`；User JWT 額外按存取權過濾（`list`/`read`）。

`DELETE /v1/files/:id` — 需 `delete`；**歸屬校驗**（app + 使用者 ACL）。軟刪除：打 tombstone（`deleted_at`）、即時回退該 App 儲存用量、刪除該檔所有下載 token（token 即時 404）。磁碟 blob 與 DB 列保留一個寬限期（`TENANT_FS_SOFT_DELETE_DAYS`，預設 7 天），之後由背景 purge 迴圈每 `TENANT_FS_PURGE_INTERVAL_SECS`（預設 600 秒）實體清除。成功→`204`。

### 8.2 資料夾

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/v1/folders` | 建資料夾：`{ parent_id?, name }` |
| GET | `/v1/folders/:id` | 資料夾明細＋其 ACL |
| GET | `/v1/folders/:id/files` | 資料夾下檔案列表 |
| PATCH | `/v1/folders/:id` | 改名／移入其他父資料夾 |
| DELETE | `/v1/folders/:id` | 刪資料夾（需 `delete`；級聯刪其下檔案） |

### 8.3 權限（ACL）管理（單檔）

`PATCH /v1/files/:id/acl` — 改單檔 ACL（owner 或 App 層）。Body：

```json
{ "action": "read", "add": ["u_2c9d", "group:ops"], "remove": ["u_mallory"], "deny": ["u_mallory"] }
```

### 8.4 資料夾 ACL（可遞迴）

`PATCH /v1/folders/:id/acl`

```json
{ "action": "read", "add": ["group:team_ops"], "recursive": true }
```

`recursive:true` 套用到底下資料夾；`deny` 仍全鏈最優先。

### 8.5 批量 ACL

`POST /v1/files/batch/acl` — 一次改多檔權限（App 層）。Body：

```json
{ "file_ids": [1, 2, 3], "action": "read", "add": ["u_2c9d"], "remove": [] }
```

- 批次上限（`TENANT_FS_MAX_BATCH_ACL`，預設 1000）、冪等、整批單一審計。只作用於已驗證 App 自己的檔案，不接受跨 App 目標。

---

## 9. App 自助導出

### `POST /v1/apps/export`

以 **App 身分** 呼叫（硬綁已驗證的 `app_id`，不接受目標 app_id 參數）。

```json
{ "format": "tar", "scope": "all" }
```

`format` 接受 `"tar"`（預設）或 `"zip"`。`zip` 由 `zip` crate 產生（無外部程序），目錄結構與 tar 相同：`files/<user_id>/<storage_uuid>`。

回應 `202`：

```json
{ "job_id": 1, "status": "pending" }
```

### `GET /v1/apps/exports/:id`／`GET /v1/apps/exports/:id/download`

`200`：`{ "status": "ready", "size": 12345, ... }`；進行中 → `202`（狀態端點）。產物為 **tar** 或 **zip**，含所有未刪除檔案，目錄結構 `files/<user_id>/<storage_uuid>`。

完成的導出產物與其 DB 列於 `TENANT_FS_EXPORT_TTL_SECS`（預設 86400 秒，下限 1 秒）後由背景維護迴圈清除。

---

## 10. 內部管理 API（僅 loopback）

Header：`Authorization: Bearer <ADMIN_TOKEN>`。**永不接受 `X-App-Key`／HMAC。**

### Apps

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/admin/v1/apps` | 建 App → `{app_id, app_key, app_secret}`（**app_secret 只回一次**） |
| GET | `/admin/v1/apps` | 列表＋用量／配額 |
| GET | `/admin/v1/apps/{id}` | 明細 |
| PATCH | `/admin/v1/apps/{id}` | `{enabled?, quota_bytes?, max_payload_bytes?}` |
| POST | `/admin/v1/apps/{id}/secret/rotate` | 輪換 Secret（舊 secret 即時失效） |
| DELETE | `/admin/v1/apps/{id}` | 軟刪除（即時停用） |
| GET | `/admin/v1/apps/{id}/usage` | `usage_bytes / quota_bytes / file_count / active_token_count` |

### 審計

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/admin/v1/audit?app_id=&since=` | 查審計日誌（append-only），最新在前，LIMIT 200 |

### 備份（§14）

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/admin/v1/backups/run` | 同步執行備份：DB 快照（`VACUUM INTO`）＋ `blobs.tar`（信封加密的 blob 樹，排除 `dec_cache/`、完成的導出產物、`tmp_*` 暫存）＋ `manifest.json`（每檔 sha256）。回傳 `{ "backup_id": "bk_…", "id", "status": "ready", "size", "files": [{name, size, sha256}] }`。 |
| GET | `/admin/v1/backups` | 列出已知備份，最新在前（`id, backup_id, status, created_at, finished_at, size`）。 |
| GET | `/admin/v1/backups/{id}` | 明細，含 `target_path` 與解析後的 manifest；未知 id → `404`。 |
| PATCH | `/admin/v1/backups/config` | Body `{ "schedule"?: <秒>, "target"?: "<相對目錄>", "retention"?: <1..1000> }`。寫入 DB 並套用於下次執行。`target` 必須是 `TENANT_FS_BACKUP_ROOT` 內的相對目錄名（canonicalize + `starts_with(root)`；拒絕絕對路徑、`..`、`:`、`\`）。回傳生效值 `{schedule_secs, target, retention}`。 |

備份組態：`TENANT_FS_BACKUP_ROOT`（預設 `data/backups`）、`TENANT_FS_BACKUP_RETENTION`（預設 7，保留最新）、`TENANT_FS_BACKUP_SCHEDULE_SECS`（預設 0＝關閉；>0 時維護迴圈距上次備份達間隔即觸發）。

### Admin 控制台（靜態資產）

小型 HTML/JS 控制台於編譯時嵌入，**僅掛在 loopback admin bind**——public 路由器全部 404：

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/admin`、`/admin/`、`/admin/index.html` | HTML 殼 |
| GET | `/admin/app.js`、`/admin/style.css` | 用戶端資產 |

頁面為純用戶端：admin bearer token 存在 `sessionStorage`，由頁面自行呼叫 `/admin/v1/*`。每個回應都帶安全標頭：`Content-Security-Policy`、`X-Frame-Options: DENY`、`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`。

---

## 11. 限流與配額

- **儲存配額** `quota_bytes`（App 級）與 `max_payload_bytes`（單檔）— 原子強制；超配額 → `429 quota_exceeded`。
- 超過單檔上限 → `413 payload_too_large`。
- **每 App 限流**：`generate`、`upload`（一般與分塊 init/chunk/finalize）、`export` 共用同一個依 `app_id` 的固定 60 秒視窗。視窗用盡時回 `429`，回應標頭 `Retry-After: <視窗重置前秒數>`，本文 `{ "error": { "code": "rate_limited", ... } }`。
  組態：`TENANT_FS_RATE_LIMIT_PER_MIN`（預設 120；0＝停用）、`TENANT_FS_RATE_LIMIT_MAX_ENTRIES`（預設 10000；map 硬容量，過期視窗先清掃再插入）。

---

## 12. 錯誤碼表

| 狀態碼 | code | 情境 |
|---|---|---|
| 400 | `invalid_request` | 參數格式錯誤 |
| 401 | `unauthorized` | 缺少／錯誤身分、壞簽名、重放 |
| 403 | `forbidden` | 規則拒絕（deny／無權限） |
| 404 | `not_found` | 檔／App／token 不存在或已過期（404 而非 403 隱藏存在性） |
| 409 | `conflict` | 狀態衝突（如導出未就緒；分塊 offset 錯位） |
| 413 | `payload_too_large` | 超過單檔上限 |
| 429 | `quota_exceeded` | App 儲存配額滿 |
| 429 | `rate_limited` | 每 App 請求視窗用盡；附 `Retry-After` 標頭 |
| 500 | `internal` | 伺服器錯誤 |

> 安全提示：不存在的資源一律回 **404**，絕不回 403。

---

## 13. 靜態加密與金鑰策略

Blob 預設靜態加密落盤（`TENANT_FS_ENCRYPT_BLOBS=true`）。每個 blob 是自含信封：

```
[0..4]    magic "TSFS"
[4]       格式版本 = 1
[5..17]   dek_nonce   (12 位元組，用 KEK 封存 DEK 的 nonce)
[17..65]  sealed_dek  (48 位元組 = AES-256-GCM(KEK, dek_nonce, DEK[32]))
[65..77]  body_nonce  (12 位元組)
[77..]    密文        = AES-256-GCM(DEK, body_nonce, 明文)
```

- 每個 blob 有自己隨機的 256 位元 DEK；同一份明文兩次加密產生不同位元組。
- **KEK 策略**：KEK 由 `SHA-256(SERVER_SECRET)` 派生——與封存 app secret 的派生相同。`SERVER_SECRET` **只**存在於部署環境，**絕不**進入任何備份（DB 快照、blob 壓縮檔、manifest、磁碟快照、CI 樣品）。封存的 DEK 隨 blob 表頭一起保存，因此偷走備份卻沒有 `SERVER_SECRET`，拿到的只是無法打開的密文。金鑰素材絕不寫入日誌。
- **舊明文相容**：加密前寫的 blob（無 `TSFS` magic）走舊明文路徑透明讀取。`migrate_plaintext_blobs()` 是冪等的一次性遷移，把舊 blob 原地改寫成信封格式。
- **解密快取**：服務加密 blob 時，會在 `blob_root/dec_cache/` 下對每個 uuid 生成一份明文快取（原子交換）。該快取刻意排除在備份與導出樹之外；刪除與 purge 作用在真正的加密檔上。

## 14. 備份與災難恢復

- **`POST /admin/v1/backups/run`** 在 `TENANT_FS_BACKUP_ROOT`（預設 `data/backups`）下產生一個備份目錄，含 `db.sqlite`（`VACUUM INTO` 一致快照）、`blobs.tar`（信封加密的 App blob 樹；`dec_cache/`、完成的導出產物、`tmp_*` 暫存略過）、`manifest.json`（每檔大小與 sha256）。
- **備份內絕無金鑰素材**：`SERVER_SECRET`、admin token、app secret 留在部署環境。DB 快照含 `apps.secret_sealed`（以 KEK 封存的 app secret），沒有 `SERVER_SECRET` 毫無用處。
- **保留**：只留最新 N 份（`TENANT_FS_BACKUP_RETENTION`，預設 7；可經 `PATCH /backups/config` 設 1–1000）。過期目錄與 DB 列一併清除。
- **排程**：預設關閉（`TENANT_FS_BACKUP_SCHEDULE_SECS=0`）。設 > 0（或經 `PATCH /backups/config` 寫入 DB）後，維護迴圈距上次備份達間隔即自動執行。
- **目標白名單**：`target` 必須是相對目錄名；canonicalize 後必須仍在 backup root 內——拒絕絕對路徑、`..`、`:`、`\`，阻擋路徑／符號連結逃逸。
- **還原**為運維側流程（尚無還原端點）：停伺服器、放回快照 `fs.db`、把 `blobs.tar` 解回 blob 根目錄、以同一把 `SERVER_SECRET` 啟動。缺 blob 檔時下載回傳 "File content missing."。

---

## 15. 規範已定但尚未實作（路線圖）

| 功能 | 說明 |
|---|---|
| 備份**還原**端點 | 備份可產出；還原目前是人工運維流程（§14）。 |
| TLS／HSTS 終止 | 伺服器跑純 HTTP；TLS 在反向代理終止。 |
| 上傳防毒／惡意軟體掃描 | 無。 |
| operator／auditor 角色分離 | 目前共用單一 `ADMIN_TOKEN`，無角色拆分。 |
| 導出完成 webhook／推送通知 | 改為輪詢狀態端點。 |

> 註：`TENANT_FS_ADMIN_TOKEN` 仍有開發預設值；伺服器啟動時印出明顯 WARNING（與 `SERVER_SECRET` 相同處理）。正式部署兩者都要顯式設定。

---

## 16. 附錄：上傳呼叫範例（curl）

以 App 身分上傳：

```bash
ts=$(date +%s); nonce=$(openssl rand -hex 16)
body_hash=$(sha256sum file.bin | cut -d' ' -f1)
sig=$(printf "POST\n/v1/upload\n\n%s\n%s\n%s" "$body_hash" "$ts" "$nonce" \
  | openssl dgst -sha256 -hmac "$APP_SECRET" -hex | cut -d' ' -f2)

curl -X POST http://<host>:8080/v1/upload \
  -H "X-App-Key: $APP_KEY" -H "X-App-Signature: $sig" \
  -H "X-Timestamp: $ts" -H "X-Nonce: $nonce" \
  -H "X-User-Id: u_8f3a" \
  --data-binary @file.bin
```

生成 embed 連結並用其下載：

```bash
# 1) generate（App 身分；重複呼叫回傳同一 token）
curl -X POST http://<host>:8080/v1/links/generate \
  -H "X-App-Key: $APP_KEY" -H "X-App-Signature: $sig2" ... \
  -d '{"file_id":3,"ttl_seconds":1800,"scope":"embed"}'

# 2) 下載（無需 App Key）
curl http://<host>:8080/v1/download/tk_.... -o out.bin
```

撤銷該 token（App 身分）：

```bash
curl -X POST http://<host>:8080/v1/tokens/revoke \
  -H "X-App-Key: $APP_KEY" ... -d '{"token":"tk_...."}'
# → 舊連結即時失效；下次 generate 鑄新 token
```
