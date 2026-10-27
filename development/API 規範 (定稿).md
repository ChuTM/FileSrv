# 多租戶檔案儲存服務 — API 規範

> 版本：v1.0　類型：API 使用規範
> 基準路徑（App API）：`https://<host>/v1`
> 管理路徑（Admin API）：`http://127.0.0.1:<admin-port>/admin/v1`（僅本機）
> 傳輸：一律 HTTPS（管理面走 loopback）｜版本化：`/v1`｜內容類型：`application/json`

---

## 1. 概覽

- 身分分四種，對應不同端點（見 §2）。
- 所有資料操作（上傳／列舉／meta／刪除／導出／下載）都經過統一鑑權＋規則閘道，**deny-by-default**。
- 每個請求最終判決寫入審計日誌（可追溯）。
- 錯誤一律回傳統一 JSON 錯誤模型（見 §1.1），HTTP 狀態碼語意化。
- **語言**：所有 API 輸出（response payload、欄位值、錯誤 `message`）一律使用**英文（en-US）**；本文件其餘文字為中文，僅屬文件敘述，不屬 API 輸出。

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

| 標識 | 用途 | 端點 |
|---|---|---|
| `X-App-Key` + `X-App-Signature`（HMAC） | App 級身分 | 上傳、導出、generate（以 App 身分） |
| `Authorization: Bearer <user-jwt>` | 使用者級身分（App 委派簽署） | 上傳、列舉、meta、刪除（以使用者身分） |
| `/v1/download/:token`（能力 token） | 下載，無需 App Key | 下載 |
| `Authorization: Bearer <admin-token>`（僅 localhost） | 管理 | admin 端點 |

### 2.1 App 層 HMAC 簽名

- **`X-App-Key`**：應用的公鑰（可公開）。
- **`X-App-Signature`**：用 `app_secret` 對「canonical request + timestamp + nonce」簽署的 HMAC-SHA256。
- **`X-Timestamp`** 與 **`X-Nonce`** 必帶，防止 replay（時間窗內、nonce 不重複）。

```
signature = HMAC_SHA256(app_secret, "<method>\n<path>\n<query>\n<body-hash>\n<timestamp>\n<nonce>")
```

### 2.2 user-context JWT（委派身份）

App 後端用它的 key 替最終使用者簽短效 JWT，內含 `user_id`；伺服器驗籤後以 JWT 為準。**請求體／header 自帶的 `user_id` 一律忽略並覆蓋。**

```json
{ "iss": "app:{app_id}", "sub": "u_8f3a…", "exp": 1800000000, "scope": "files:rw" }
```

---

## 3. 規則與 ACL（分動作）

`user_id` 是 **App 指定的不透明識別符**（不是顯示名），App 內唯一。以下範例中的 `u_8f3a…`、`u_2c9d…` 皆為這種不透明 ID。

每個檔案／資料夾的 ACL 決定誰能做什麼：

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

- `"*"` = 所有人；`group:{name}` = 群組；`deny` 優先於一切 allow。
- **繼承**：檔案若無顯式 ACL，則向上繼承其資料夾→祖先→App 預設；**`deny` 全鏈最優先**，檔案蓋不掉繼承的 deny；owner 預設可存取（除非被 deny）。
- **誰能改 ACL**：① User 層（owner）只能改**自己擁有**檔案的 ACL；② **App 層（tenant admin）**能改該 App 內**任一**檔/資料夾 ACL，含批量與資料夾遞迴（見 §8.4、§8.5）。

---

## 4. 上傳 API

### `POST /v1/upload`

以 **user-context JWT** 或 **App 身分** 呼叫。

| Header | 值 |
|---|---|
| `Authorization: Bearer <user-jwt>` 或 `X-App-Key`+`X-App-Signature` | 身分 |
| `Content-Type` | 檔案的 MIME（伺服器覆核，不信任檔名） |
| `Idempotency-Key` | （建議）重試不重複建檔 |

Body：檔案內容（streaming）。

回應 `201`：

```json
{
  "file_id": "f_uuid_xxxx",
  "app_id": "app_01j8x2a9",
  "owner": "u_8f3a…",
  "size": 1048576,
  "sha256": "9b1deb4d...",
  "classification": "confidential"
}
```

- 剝離原始檔名（如 `index.php`），以 UUID 寫入該 App 專用目錄。
- 邊傳邊卡 `max_payload_bytes`；超過→`413`；配額滿→`429`。
- 分塊／斷點續傳：`POST /v1/upload/init` → `PUT /v1/upload/{upload_id}`（每塊帶 offset＋checksum）→ `POST /v1/upload/{upload_id}/finalize`。

---

## 5. 生成下載連結

### `POST /v1/links/generate`

以 **App 身分** 或 **user-context JWT** 呼叫（App 只能請求，token 由伺服器鑄幣）。

```json
{
  "file_id": "f_uuid_xxxx",
  "ttl_seconds": 1800,
  "scope": "embed",
  "allowed_ip": "203.0.113.45"
}
```

- `scope: "embed"`：冪等，同 (file,user,scope) 回傳**同一個** token，固定 TTL 從首次起算、刷新不續命。
- `scope: "share"`：一次性分享，每次新 token，可綁 `allowed_ip`。
- 伺服器重查檔、重跑 ACL、deny-by-default；`file_id` 不屬於當前 app → `404`。

回應 `200`：

```json
{
  "token": "tk_....",
  "url": "/v1/download/tk_....",
  "expires_at": 1800000000,
  "reused": false
}
```

（`reused:true` 表示回傳了既有 token。）

---

## 6. 下載 API

### `GET /v1/download/:token`

面向終端使用者，**無需 App Key**。能力 token 綁定 `(app_id, file_id, user_id, TTL)`。

- Token 過期／被撤銷 → `404`。
- 支援 **Range 斷點續傳**（`206`）、`HEAD`、`ETag`、`If-None-Match`（→`304`）。
- 安全標頭：`Content-Disposition: attachment`＋`X-Content-Type-Options: nosniff`（視檔案類別；敏感／可執行類一律 attachment）。
- 下載按 token／client IP 限流。

---

## 7. 撤銷 Token

### `POST /v1/tokens/revoke`

以 **App 身分** 呼叫。撤銷後 token **即時失效**；下次 generate 會鑄**新** token。

```json
{ "token": "tk_...." }
```

回應 `200`：`{ "revoked": true }`；token 未知或已過期 → `404`。

---

## 8. 檔案與資料夾 CRUD

### 8.1 檔案

`GET /v1/files/:id` — 取得 meta。需對該檔 `read` 權限。

`GET /v1/files?user_id=&folder_id=&cursor=` — 列舉。需 `list` 權限；分頁用游標；查詢一律 `WHERE app_id = 身份.app_id`（＋`user_id`／`folder_id`）。

`DELETE /v1/files/:id` — 刪除。需 `delete` 權限；**歸屬校驗**（app+user）；軟刪（tombstone）→ 寬限期後實體 rm＋撤銷該檔 token。成功→`204`。

### 8.2 資料夾

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/v1/folders` | 建資料夾：`{ parent_id?, name }`（根資料夾 parent 可空） |
| GET | `/v1/folders/:id` | 資料夾明細＋其 ACL |
| GET | `/v1/folders/:id/files` | 資料夾下檔案列表 |
| PATCH | `/v1/folders/:id` | 改名／移入其他父資料夾 |
| DELETE | `/v1/folders/:id` | 刪資料夾（需 `delete` 權限；含其下檔案） |

### 8.3 權限（ACL）管理

`PATCH /v1/files/:id/acl` — 改單檔 ACL（owner 或 App 層）。Body：

```json
{ "action": "read", "add": ["u_2c9d", "group:ops"], "remove": ["u_mallory"], "deny": ["u_mallory"] }
```

### 8.4 資料夾 ACL（可遞迴）

`PATCH /v1/folders/:id/acl`

```json
{ "action": "read", "add": ["group:team_ops"], "recursive": true }
```

`recursive:true` 套用到底下所有未覆蓋的檔案；`deny` 仍全鏈最優先。

### 8.5 批量 ACL

`POST /v1/files/batch/acl` — 一次改多檔權限（App 層）。Body：

```json
{ "file_ids": ["f_1","f_2","f_3"], "action": "read", "add": ["u_2c9d"], "remove": [] }
```

- 有**批次上限**（如 1000）、冪等、整批單一審計、rate-limit。
- 只作用於已驗證 App 自己的檔案，不接受跨 App 目標。

---

## 9. App 自助導出

### `POST /v1/apps/export`

以 **App 身分** 呼叫（硬綁已驗證的 `app_id`，不接受目標 app_id 參數）。

```json
{ "format": "zip", "scope": "all" }
```

回應 `202`：

```json
{ "export_id": "exp_xxx", "status": "pending" }
```

### `GET /v1/apps/exports/:id`

`200`：`{ "status": "ready", "download_url": "/v1/export/exp_xxx?...", "size": 12345 }`；進行中→`202`。

- 導出產物有 **TTL、到期清理、靜態加密、不留明文暫存**；下載用短 TTL 能力連結。
- 導出為重大動作，寫入審計；可選需 admin 批准。

---

## 10. 內部管理 API（僅 `127.0.0.1`）

Header：`Authorization: Bearer <ADMIN_TOKEN>`。**永不接受 `X-App-Key`／HMAC。**

### Apps

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/admin/v1/apps` | 建 App → `{app_id, app_key, app_secret}`（**app_secret 只回一次**） |
| GET | `/admin/v1/apps` | 列表＋用量/配額 |
| GET | `/admin/v1/apps/{id}` | 明細 |
| PATCH | `/admin/v1/apps/{id}` | `{enabled?, quota_bytes?, max_payload_bytes?}` |
| POST | `/admin/v1/apps/{id}/secret/rotate` | 輪換 Secret（寬限期） |
| DELETE | `/admin/v1/apps/{id}` | 軟刪除（quarantine→tombstone→清 blobs+Redis） |
| GET | `/admin/v1/apps/{id}/usage` | 儲存／token 數／限流命中／下載數 |

### 備份

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/admin/v1/backups/run` | 立即備份 |
| GET | `/admin/v1/backups` · `/backups/{id}` | 任務／狀態 |
| PATCH | `/admin/v1/backups/config` | `{schedule?, target?, retention?}` |

### 審計

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/admin/v1/audit?app_id=&since=` | 查審計日誌（append-only） |

---

## 11. 限流與配額

- **每 App**：generate / upload / export 各自 rate limit（例如 generate 每秒 100 次）。
- **儲存配額**：`quota_bytes`（App 級）、`max_payload_bytes`（單檔）。
- 超限回應：`429 Too Many Requests`（附 `Retry-After`）。

---

## 12. 錯誤碼表

| 狀態碼 | code | 情境 |
|---|---|---|
| 400 | `invalid_request` | 參數格式錯誤 |
| 401 | `unauthorized` | 缺少／錯誤身分 |
| 403 | `forbidden` | 規則拒絕（deny／無權限） |
| 404 | `not_found` | 檔／App／token 不存在或已過期（用 404 而非 403 隱藏存在性） |
| 409 | `conflict` | 冪等衝突、狀態衝突 |
| 413 | `payload_too_large` | 超過單檔上限 |
| 429 | `rate_limited` / `quota_exceeded` | 限流／配額滿 |
| 500 | `internal` | 伺服器錯誤（fail-closed 下的系統性拒絕） |

> 安全提示：不存在的資源一律回 **404** 而非 403，避免洩漏資源是否存在。

---

## 13. 附錄：上傳呼叫範例（curl）

以 App 身分上傳：

```bash
ts=$(date +%s); nonce=$(openssl rand -hex 16)
body_hash=$(sha256sum file.bin | cut -d' ' -f1)
sig=$(printf "POST\n/v1/upload\n\n%s\n%s\n%s" "$body_hash" "$ts" "$nonce" \
  | openssl dgst -sha256 -hmac "$APP_SECRET" -hex | cut -d' ' -f2)

curl -X POST https://<host>/v1/upload \
  -H "X-App-Key: $APP_KEY" -H "X-App-Signature: $sig" \
  -H "X-Timestamp: $ts" -H "X-Nonce: $nonce" \
  --data-binary @file.bin
```

生成 embed 連結並用其下載：

```bash
# 1) generate（App 身分；重複呼叫回傳同一 token）
curl -X POST https://<host>/v1/links/generate \
  -H "X-App-Key: $APP_KEY" -H "X-App-Signature: $sig2" ... \
  -d '{"file_id":"f_uuid_xxxx","ttl_seconds":1800,"scope":"embed"}'

# 2) 下載（無需 App Key）
curl https://<host>/v1/download/tk_.... -o out.bin
```

撤銷該 token（App 身分）：

```bash
curl -X POST https://<host>/v1/tokens/revoke \
  -H "X-App-Key: $APP_KEY" ... -d '{"token":"tk_...."}'
# → 舊連結即時失效；下次 generate 鑄新 token
```
