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

`DELETE /v1/files/:id` — 需 `delete`；**歸屬校驗**（app + 使用者 ACL）；軟刪（tombstone）、實體 blob 即時移除、token 清空、usage 回收。成功→`204`。

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

回應 `202`：

```json
{ "job_id": 1, "status": "pending" }
```

### `GET /v1/apps/exports/:id`／`GET /v1/apps/exports/:id/download`

`200`：`{ "status": "ready", "size": 12345, ... }`；進行中 → `202`（狀態端點）。產物為 **tar**，含所有未刪除檔案，目錄結構 `files/<user_id>/<storage_uuid>`。

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

---

## 11. 限流與配額

- **儲存配額** `quota_bytes`（App 級）與 `max_payload_bytes`（單檔）— 原子強制；超配額 → `429 quota_exceeded`。
- 超過單檔上限 → `413 payload_too_large`。

> 註：每 App 的 rate limit（generate／upload／export）在路線圖中，**尚未實作**（見 §13）。

---

## 12. 錯誤碼表

| 狀態碼 | code | 情境 |
|---|---|---|
| 400 | `invalid_request` | 參數格式錯誤 |
| 401 | `unauthorized` | 缺少／錯誤身分、壞簽名、重放 |
| 403 | `forbidden` | 規則拒絕（deny／無權限） |
| 404 | `not_found` | 檔／App／token 不存在或已過期（404 而非 403 隱藏存在性） |
| 409 | `conflict` | 狀態衝突（如導出未就緒） |
| 413 | `payload_too_large` | 超過單檔上限 |
| 429 | `quota_exceeded` | App 儲存配額滿 |
| 500 | `internal` | 伺服器錯誤 |

> 安全提示：不存在的資源一律回 **404**，絕不回 403。

---

## 13. 規範已定但尚未實作（路線圖）

| 功能 | 規範出處 | 狀態 |
|---|---|---|
| 備份 API（`/admin/v1/backups/run`、`/backups`、`PATCH /backups/config {schedule?, target?, retention?}`） | 規範 §10 備份 | **未實作** — 見 `Ops-and-Backup.md` |
| 分塊／斷點續傳上傳（`/v1/upload/init` → `PUT /v1/upload/{id}` → `finalize`） | 規範 §4 | 未實作 |
| 每 App rate limit＋`Retry-After` | 規範 §11 | 未實作 |
| Admin 網頁／HTML 控制台 | 規劃 | 未實作（目前僅 API） |
| 上傳 `Idempotency-Key` | 規範 §4（建議） | 未實作 |
| 下載 `HEAD`、`zip` 導出格式 | 規範 §6/§9 | 未實作（僅 GET；僅 tar） |
| 導出產物 TTL＋到期清理 | 規範 §9 | 未實作 |
| blob 靜態加密（信封 KEK/DEK） | 規劃 §12 | 未實作（blob 明文落盤） |
| 軟刪寬限期後實體清除 | 規範 §8.1 | 未實作（實體即時移除） |

---

## 14. 附錄：上傳呼叫範例（curl）

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
