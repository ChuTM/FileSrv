# 管理控制台前端資產 — 整合說明（給接線階段）

> 對象：`src/admin_ui/static/` 下的三個檔案（`index.html` / `app.js` / `style.css`）。
> 本階段未動任何 `.rs` 檔；此文件說明如何用 `include_str!` 把它們掛進管理埠。

---

## (a) 路由建議與資產

控制台**只掛在管理埠**（`ADMIN_BIND`，目前 `127.0.0.1:18081`），與 `admin_router` 同源；**不要**掛到公共埠（`PUBLIC_BIND`）。

| 路由 | 內容 | Content-Type |
|---|---|---|
| `GET /admin/` 或 `GET /admin/index.html` | `index.html` | `text/html; charset=utf-8` |
| `GET /admin/app.js` | `app.js` | `application/javascript; charset=utf-8` |
| `GET /admin/style.css` | `style.css` | `text/css; charset=utf-8` |

Rust 側建議（示意，非本次交付）：

```rust
const ADMIN_HTML: &str = include_str!("admin_ui/static/index.html");
const ADMIN_JS:   &str = include_str!("admin_ui/static/app.js");
const ADMIN_CSS:  &str = include_str!("admin_ui/static/style.css");
// 在 admin_router 上額外掛：
//   .route("/admin/",          get(|| async { (ADMIN_HTML_HEADER, ADMIN_HTML) }))
//   .route("/admin/index.html", get(|| async { (ADMIN_HTML_HEADER, ADMIN_HTML) }))
//   .route("/admin/app.js",     get(|| async { (ADMIN_JS_HEADER,   ADMIN_JS) }))
//   .route("/admin/style.css",  get(|| async { (ADMIN_CSS_HEADER,  ADMIN_CSS) }))
```

注意：
- 這三個靜態路由**不要**要求 Bearer token（不然瀏覽器打不開頁面）；但整個管理埠本來就只 bind loopback，暴露面等同於機器本機。
- 頁面位置與 API 前綴同層（`/admin/` ↔ `/admin/v1/`），JS 用相對路徑解析，**不要**硬編碼 host/port。

## (b) JS 呼叫的全部端點

基底：`/admin/v1`（由頁面位置相對解析）。全部附 `Authorization: Bearer <admin-token>`。

| 方法 | 路徑 | 請求體 | 回應 |
|---|---|---|---|
| GET | `/admin/v1/apps` | — | `{ "apps": [ AppRow… ] }` |
| POST | `/admin/v1/apps` | `{ name, quota_bytes, max_payload_bytes }` | `{ app_id, name, app_key, app_secret, quota_bytes, max_payload_bytes, enabled }` |
| GET | `/admin/v1/apps/{id}/usage` | — | `{ app_id, usage_bytes, quota_bytes, file_count, active_token_count }` |
| PATCH | `/admin/v1/apps/{id}` | `{ enabled: bool }`（啟用/停用切換） | `204 No Content` |
| POST | `/admin/v1/apps/{id}/secret/rotate` | — | `{ app_id, app_secret }` |
| DELETE | `/admin/v1/apps/{id}` | — | `204 No Content`（軟刪除） |
| GET | `/admin/v1/audit?app_id=&since=<unix秒>` | — | `{ "entries": [ { id, actor, action, app_id, target, ip, decision, at } ] }` |
| GET | `/admin/v1/backups`（**探測**） | — | 成功→備份列表；**404/501 時前端自動顯示「此功能尚未啟用」** |
| POST | `/admin/v1/backups/run`（備份可用時才呼叫） | — | 未實作時 404，前端在備份視圖內呈現降級提示 |

`AppRow`（list 回傳）：`{ app_id, name, app_key, quota_bytes, max_payload_bytes, usage_bytes, enabled, created_at, deleted_at }`。

錯誤一律為 `{ "error": { code, message, request_id } }`；`401` 時前端自動登出回到登入頁。

## (c) 鑑權流程（純客戶端，無服務端 session）

1. 首次開啟 → 登入視圖，輸入 `TENANT_FS_ADMIN_TOKEN`。
2. 前端以該 token 打一次 `GET /admin/v1/apps` 驗證；401 即拒絕進入。
3. 成功後 token 寫入 `sessionStorage['fs_admin_token']`（**僅工作分頁、絕不用 localStorage、不進 URL query、不寫 cookie**）。
4. 後續所有 fetch 自動帶 `Authorization: Bearer …`。
5. 任何回應 401 → 清除 sessionStorage、退回登入頁。
6. 關閉分頁即失效；「登出」按鈕主動清除。

## (d) 建議伺服器響應頭

對 `/admin/*`（含三個資產）一律加上：

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store
```

說明：
- 資產無外部 CDN、無 inline script、無 inline style（CSP 可嚴格）。
- `no-store` 避免 token 相關響應/頁面被快取。
- 整個管理埠本就 loopback，`X-Frame-Options` 是額外防禦。

## (e) XSS 轉義核對清單（已應用）

- [x] 所有動態資料以 `textContent` 渲染；`h()` 工具統一建構 DOM。
- [x] `innerHTML` 僅存在於 `h()` 的 `html:` 分支，**全程式碼無任何呼叫方傳入 `html:`**（grep 證實），且其本機只可能接靜態骨架字串。
- [x] `app.name` / `audit.target` / `audit.actor` / `audit.ip` 等不可信欄位全部走 textContent。
- [x] `app_secret` 僅在建立/輪換成功後的模態中一次性顯示，列表與詳情均不回傳 secret。
- [x] 無 `eval`、無 `new Function`、無字串版 `setTimeout`。
- [x] 無任何外部 URL（grep 證實：唯一外部參照是同目錄 `style.css`）。
- [x] 無 localStorage、無 cookie；token 僅 sessionStorage。
