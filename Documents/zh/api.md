# 多租戶檔案儲存服務 — App-facing API 規範（繁體中文）

> 版本：v1.1 · 範圍：**面向 app 的公開 API 僅此**
> Base path：`https://<host>/v1`
> 傳輸：HTTP/HTTPS · 版本化：`/v1` · Content-Type：`application/json`
> **Admin API**（僅 loopback、`Authorization: Bearer <ADMIN_TOKEN>`）是另一套
> 獨立介面，記載於 `development/admin-api.md`，**不在本文範圍內**。

---

## 1. 概覽

- 對 app 呼叫者暴露三種身份，各自對應特定端點（見 §2）。
- 每一項資料操作（上傳／列表／元資料／刪除／導出／下載）都統一經過
  auth + rules 閘道，**預設拒絕（deny-by-default）**。
- 每個請求的最終判定都會寫入稽核日誌（可追蹤）。
- 錯誤一律使用統一的 JSON 錯誤模型（§1.1）；HTTP 狀態碼具語意。
- **語言**：所有 API 輸出（回應 payload、欄位值、錯誤 `message`）均為英文
  （en-US）。

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

| 身份 | 機制 | 端點 |
|---|---|---|
| App 層 | `X-App-Key` + `X-App-Signature`（HMAC） | upload、export、generate（以 app 身份） |
| User 層 | `Authorization: Bearer <user-jwt>`（由 app 密鑰簽署） | upload、list、meta、delete、generate（以 user 身份） |
| Capability token | `GET /v1/download/<token>` — 不需 app key | download |

### 2.1 App 層 HMAC 簽名

- `X-App-Key`：app 的公開識別碼。
- `X-App-Signature`：對 canonical 請求 + 時間戳 + nonce 的 HMAC-SHA256，
  以 app 密鑰簽署。
- `X-Timestamp` 與 `X-Nonce` 為必填（重放防護：±300 秒窗口，nonce 不得重複）。

```
signature = HMAC_SHA256(app_secret, "<method>\n<path>\n<query>\n<body-hash>\n<timestamp>\n<nonce>")
```

### 2.2 user-context JWT（委派身份）

App 後端為其終端使用者（`user_id`）簽署短效 JWT；伺服器驗證簽名並信任該
JWT。任何在請求 body／header 中攜帶的 `user_id` 都會被忽略並覆寫。

```json
{ "iss": "app:{app_id}", "sub": "u_8f3a…", "exp": 1800000000, "scope": "files:rw" }
```

---

## 3. 規則與 ACL（分動作）

`user_id` 是 app 指派的模糊識別碼（非顯示名稱），在 app 內唯一。

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

- `"*"` = 所有人；`g:<group>` = 該群組的任一成員；**`deny` 優先於任何 allow。**
- **繼承**：無顯式 ACL 的檔案繼承自其資料夾 → 上層 → app 預設；**`deny` 沿
  整個鏈累積，檔案的顯式 ACL 無法覆寫繼承而來的 deny**；owner 預設保有
  存取權，除非被 deny。
- **誰可修改 ACL**：① User 層 — 僅 **owner** 可修改其擁有的檔案的 ACL；
  ② **App 層（tenant admin）** 可修改 app 內任何檔案／資料夾的 ACL，含批次
  與資料夾遞迴（見 §8.4、§8.5）。

---

## 4. 上傳 API

### `POST /v1/upload`

以 **user-context JWT** 或 **app 身份**呼叫。

| Header | 值 |
|---|---|
| `Authorization: Bearer <user-jwt>` 或 `X-App-Key`+`X-App-Signature` | 身份 |
| `X-User-Id` | **app 層上傳必填** — app 為之背書的使用者 |
| `Content-Type` | 檔案的 MIME（原樣儲存；伺服器絕不依檔名推測） |

Body：檔案內容（串流至暫存檔後驗證）。

| Header | 值 |
|---|---|
| `Idempotency-Key` | **選填** — 重試防護（見 §4.2） |

Response `200`：

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

- 原始檔名會被剝離；內容以不透明 UUID 儲存在該 app 的專屬目錄。`logical_path`
  與下載檔名皆為 storage UUID。
- Payload 在串流時即設上限：超過 `max_payload_bytes` → `413`；配額滿 → `429`。
- 選填 `?folder_id=` query 指向資料夾（須屬於該 app）。

### 4.2 上傳冪等重試

在 `POST /v1/upload` 上送客戶端產生的 `Idempotency-Key` header。在設定的
窗口內（`TENANT_FS_IDEMPOTENCY_WINDOW_SECS`，預設 3600 秒，下限 60 秒），
以**相同 key 且相同身份**重試會拿到**原始**上傳結果 — 不會再寫入第二個
blob、不會重複扣配額。窗口到期後該 key 被遺忘，視為全新上傳。快取為記憶體
（best-effort 重試防護，非常駐佇列），硬上限為
`TENANT_FS_IDEMPOTENCY_MAX_ENTRIES`（預設 10000，LRU 淘汰）。

### 4.3 分塊／斷點續傳上傳

用於大檔或網路不穩，採用三步式 session：

| 步驟 | Method & path | 行為 |
|---|---|---|
| 1. init | `POST /v1/upload/init` | Body `{ "total_size"?: <bytes>, "folder_id"?: <id> }`。回傳 `{ "upload_id": "up_…", "status": "open", "total_size", "received_size": 0, "chunk_ttl_secs", "max_payload_bytes" }`。`total_size > 0` 若超過 app 的 `max_payload_bytes` 會被拒。 |
| 2. chunk | `PUT /v1/upload/{upload_id}` | 原始 chunk body，header `X-Chunk-Offset: <byte offset>`。Chunk 必須**連續**抵達：offset 須等於伺服器目前的 `received_size`。有缺口 → `409` 帶 `{ "error": { "code": "conflict", "message": "Unexpected chunk offset; resume at N." } }`，客戶端可據此重新對位。App 層 HMAC 逐 chunk 驗證。回傳 `{ "upload_id", "received_size", "status": "open" }`。 |
| 3. finalize | `POST /v1/upload/{upload_id}/finalize` | 驗證已收位元組數對得上 `total_size`，原子性地重查配額，SHA-256 暫存檔，經儲存層加密寫入 blob（見 §12），回傳與 `POST /v1/upload` 相同的元資料結構。 |

- 身份規則與 `POST /v1/upload` 相同（user JWT，或帶 `X-User-Id` 的 app
  HMAC）；未知／過期／跨租戶的 session → `404`。
- 中斷的 session 在 `TENANT_FS_UPLOAD_TTL_SECS`（預設 86400 秒，下限 60 秒）
  後過期；暫存的部分檔案由背景迴圈清除。
- 三個呼叫皆受 per-app rate limiter 計量（§10）。

---

## 5. 生成下載連結

### `POST /v1/links/generate`

以 **app 身份**或 **user-context JWT** 呼叫（僅請求；token 由伺服器鑄造）。

```json
{
  "file_id": 3,
  "ttl_seconds": 1800,
  "scope": "embed",
  "allowed_ip": "203.0.113.45"
}
```

- `scope: "embed"`：**冪等** — 相同（file, user, scope）回傳**相同** token，
  TTL 自首次鑄造起固定，重新整理不會延長。對 user JWT 以請求者為鍵（app
  身份時回退至檔案 owner）。
- `scope: "share"`：一次性分享 — 每次鑄造新 token，可選綁定 `allowed_ip`。
- 伺服器會重讀檔案、重跑 ACL、deny-by-default；`file_id` 不在目前 app → `404`。

Response `200`：

```json
{
  "token": "tk_....",
  "url": "/v1/download/tk_....",
  "scope": "embed",
  "expires_at": 1800000000,
  "reused": false
}
```

（`reused: true` 表示回傳了既有的 token。）

---

## 6. 下載 API

### `GET /v1/download/:token`

供終端使用者使用，**不需 app key**。Capability token 綁定
`(app_id, file_id, TTL)`；share token 可額外綁定客戶端 IP。

- 過期／撤銷的 token → `404`（隱藏存在性）。
- 支援 **Range**（`206`）、`ETag`、`If-None-Match`（→ `304`）；不可滿足的
  range → `416`。
- 安全 header：`Content-Disposition: attachment` + `X-Content-Type-Options:
  nosniff`。
- **IP-bound token 的客戶端 IP**：預設為 TCP peer IP；`X-Forwarded-For`
  僅在伺服器處於 trusted-proxy 模式（`TENANT_FS_TRUST_XFF=true`）時才被採納，
  否則偽造的 header 無效。

### `HEAD /v1/download/:token`

與 `GET` 相同的鑑權、token 規則與 404 語意，但僅回傳 header，無 body。
回傳 `Content-Length`、`ETag`（`"sha256-<hex>"`）、`Content-Type`、
`Content-Disposition`、`X-Content-Type-Options: nosniff`；`If-None-Match` →
`304`；未知／過期 token → `404`。可在串流前做 pre-flight 尺寸／etag 檢查。

---

## 7. 撤銷 Token

### `POST /v1/tokens/revoke`

以 **app 身份**呼叫。被撤銷的 token 立即失效；下一次 generate 會鑄造**新**
token。

```json
{ "token": "tk_...." }
```

Response `200`：`{ "revoked": true }`；未知 token → `404`。

---

## 8. 檔案與資料夾 CRUD

### 8.1 檔案

`GET /v1/files/:id` — 檔案元資料。需對該檔案具 `read` 權限。

`GET /v1/files?folder_id=&cursor=` — 以 cursor 分頁列出，`WHERE app_id =
identity.app_id`。user JWT 的列表會依存取權限（`list`／`read`）過濾。

`DELETE /v1/files/:id` — 需 `delete`；**ownership 檢查**（app + user ACL）。
Soft-delete：設墓碑（`deleted_at`），立即釋放該 app 的儲存用量並撤銷該檔案
所有下載 token（token 即刻 `404`）。磁碟上的 blob 與 DB 列會存活一段寬限
期（`TENANT_FS_SOFT_DELETE_DAYS`，預設 7 天），由背景清理迴圈每隔
`TENANT_FS_PURGE_INTERVAL_SECS`（預設 600 秒）實體移除。成功 → `204`。

### 8.2 資料夾

| Method | Path | 說明 |
|---|---|---|
| POST | `/v1/folders` | 建立：`{ parent_id?, name }` |
| GET | `/v1/folders/:id` | 資料夾詳情 + ACL |
| GET | `/v1/folders/:id/files` | 資料夾下的檔案 |
| PATCH | `/v1/folders/:id` | 更名／移至另一 parent 之下 |
| DELETE | `/v1/folders/:id` | 刪除（需 `delete`；串接至檔案） |

### 8.3 權限（ACL）管理（單檔）

`PATCH /v1/files/:id/acl` — 修改單一檔案的 ACL（owner 或 app 層）。Body：

```json
{ "action": "read", "add": ["u_2c9d", "group:ops"], "remove": ["u_mallory"], "deny": ["u_mallory"] }
```

### 8.4 資料夾 ACL（可遞迴）

`PATCH /v1/folders/:id/acl`

```json
{ "action": "read", "add": ["group:team_ops"], "recursive": true }
```

`recursive: true` 套用至子資料夾；`deny` 維持鏈上優先。

### 8.5 批量 ACL

`POST /v1/files/batch/acl` — 一次修改多個檔案（app 層）。Body：

```json
{ "file_ids": [1, 2, 3], "action": "read", "add": ["u_2c9d"], "remove": [] }
```

- 批次上限（`TENANT_FS_MAX_BATCH_ACL`，預設 1000），冪等，單一稽核紀錄。
  僅限已鑑權 app 的檔案；跨 app 目標會被拒。

---

## 9. 群組 API（由 app 管理）

群組讓 app 用「成員身分」統一授權，而不必在每個檔案的 ACL 逐一列出
`user_id`。由 **app 級身份**（`X-App-Key` + HMAC）管理；**使用者 JWT 不可**管理
群組。檔案或資料夾的 ACL 規則可用 `g:<群組名>` 引用（見 §3）——該群組的
任一已登記使用者即對該動作放行。

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/v1/groups` | 建立群組：`{"name": "..."}`（空成員） |
| GET | `/v1/groups` | 列出此 app 的群組（含成員） |
| GET | `/v1/groups/{name}` | 群組詳情＋成員 |
| DELETE | `/v1/groups/{name}` | 刪除群組 |
| POST | `/v1/groups/{name}/members` | 加成員：`{"user_id": "..."}` |
| DELETE | `/v1/groups/{name}/members/{user_id}` | 移除成員 |

規則：
- 群組名：`1..=64` 字元，不可含 `/`、`\` 或空格；每個 app 內唯一。
- 加既有成員為冪等；移除不存在的成員為無操作。
- 刪除群組**不會**改寫既有 ACL——指向已刪群組的 `g:<name>` 引用自然不匹配
  （該訪問權即失效）。
- 成員身分**不**等同 JWT 有效；使用者仍須先登記於 `app_users`（admin API
  `/apps/{id}/users`），其 JWT 才會被接受。
- 群組按 app 隔離：一個 app 只能管理自己的群組。

---

## 10. App 自助導出

### `POST /v1/apps/export`

以 **app 身份**呼叫（硬綁定至已驗證的 `app_id`；不接受目標 app_id 參數）。

```json
{ "format": "tar", "scope": "all" }
```

`format` 接受 `"tar"`（預設）或 `"zip"`。`zip` 由 `zip` crate 產生（無外部
行程），並以與 tar 相同的方式組織條目：`files/<user_id>/<storage_uuid>`。

Response `202`：

```json
{ "job_id": 1, "status": "pending" }
```

### `GET /v1/apps/exports/:id`／`GET /v1/apps/exports/:id/download`

`200`：`{ "status": "ready", "size": 12345, ... }`；仍在執行 → `202`（狀態
端點）。封存為 **tar** 或 **zip**，內含所有未刪除的檔案，組織為
`files/<user_id>/<storage_uuid>`。

完成的導出產物與其列在 `TENANT_FS_EXPORT_TTL_SECS`（預設 86400 秒，下限
1 秒）後由背景維護迴圈清除。

---

## 11. 限流與配額

- **儲存配額** `quota_bytes`（app 層）與 `max_payload_bytes`（單檔）—
  原子性執行；超配額 → `429 quota_exceeded`。
- Payload 超上限 → `413 payload_too_large`。
- **Per-app rate limiting**：`generate`、`upload`（普通與分塊的
  init/chunk/finalize）與 `export` 共用每個 `app_id` 的固定 60 秒窗口。窗口
  用盡時呼叫以 `429` 失敗，回應 header 帶 `Retry-After: <視窗重置剩餘秒數>`，
  body 為 `{ "error": { "code": "rate_limited", ... } }`。
  旋鈕：`TENANT_FS_RATE_LIMIT_PER_MIN`（預設 120；0 = 停用）、
  `TENANT_FS_RATE_LIMIT_MAX_ENTRIES`（預設 10000；硬 map 容量，過期窗口
  於其增長前清除）。

---

## 12. 錯誤碼表

| 狀態 | code | 情境 |
|---|---|---|
| 400 | `invalid_request` | 參數格式錯誤 |
| 401 | `unauthorized` | 身分缺失／錯誤、簽名錯誤、重放 |
| 403 | `forbidden` | 規則拒絕（deny／無權限） |
| 404 | `not_found` | 檔案／app／token 缺失或過期（以 404 而非 403 隱藏存在性） |
| 409 | `conflict` | 狀態衝突（如導出尚未就緒；chunk offset 不符） |
| 413 | `payload_too_large` | 超過單檔上限 |
| 429 | `quota_exceeded` | app 儲存配額已滿 |
| 429 | `rate_limited` | per-app 請求窗口用盡；已設 `Retry-After` header |
| 500 | `internal` | 伺服器錯誤 |

> 安全註記：不存在的資源一律回傳 **404**，絕不回 403。

---

## 13. 靜態加密與金鑰策略

Blob 預設靜態加密（`TENANT_FS_ENCRYPT_BLOBS=true`）。每個 blob 是自足的
封包：

```
[0..4]    magic "TSFS"
[4]       format version = 1
[5..17]   dek_nonce   (12 bytes, nonce sealing the DEK under the KEK)
[17..65]  sealed_dek  (48 bytes = AES-256-GCM(KEK, dek_nonce, DEK[32]))
[65..77]  body_nonce  (12 bytes)
[77..]    ciphertext  = AES-256-GCM(DEK, body_nonce, plaintext)
```

- 每個 blob 各用隨機 256-bit DEK；相同明文的兩次加密會產生不同位元組。
- **KEK 策略**：KEK 由 `SHA-256(SERVER_SECRET)` 推導 — 與密封 app secret
  相同的推導。`SERVER_SECRET` **只**存在於部署環境，**絕不**複製進備份（DB
  匯出、blob 封存、manifest、volume 快照、CI fixture）。因 sealed DEK 位於
  blob header 內，缺少 `SERVER_SECRET` 的被竊備份只持有無法開啟的密文。
  金鑰材料絕不寫入日誌。
- **Legacy 明文**：加密前寫入的 blob（無 `TSFS` magic）會透明地經 legacy
  明文路徑提供。`migrate_plaintext_blobs()` 是冪等的一次性遷移，可將 legacy
  blob 就地重寫為封包格式。
- **解密讀取快取**：服務加密 blob 時伺服器會在 `blob_root/dec_cache/`
  產生 per-uuid 明文快取（原子交換）。該快取刻意排除在備份與導出樹之外；
  刪除與清理針對真實的加密檔。

---

## 14. 附錄：上傳呼叫範例（curl）

App 層上傳：

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

生成 embed 連結並下載：

```bash
# 1) generate（app 身份；重複呼叫回傳相同 token）
curl -X POST http://<host>:8080/v1/links/generate \
  -H "X-App-Key: $APP_KEY" -H "X-App-Signature: $sig2" ... \
  -d '{"file_id":3,"ttl_seconds":1800,"scope":"embed"}'

# 2) download（不需 app key）
curl http://<host>:8080/v1/download/tk_.... -o out.bin
```

撤銷 token（app 身份）：

```bash
curl -X POST http://<host>:8080/v1/tokens/revoke \
  -H "X-App-Key: $APP_KEY" ... -d '{"token":"tk_...."}'
# → 舊連結立即失效；下一次 generate 會鑄造新 token
```
