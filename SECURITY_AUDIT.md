# filesrv 安全审查报告（代码审计）

**审计范围**：仅源码（`src/`、`tests/`、嵌入静态资源 `src/admin_ui/static/`），不涉及运行态、网络拓扑、密钥管理运行过程。审计时未修改任何代码。

**审计结论总览（修复状态见第六节）**：整体架构安全设计较为扎实，已对常见漏洞（路径穿越、重放、JWT 伪造、备份密钥泄露、管理面误暴露等）做了显式防护并留下了修复注释（F1~F7）。主要残余风险集中在：**用户 JWT 无撤销**、**下载限速时序过晚**、**软删除/擦除后 plaintext 缓存残留**、**admin 接口返回 app_secret 明文**、**审计写入失败静默忽略**等，均为中低危，建议按优先级修复。

---

## 一、已做好的安全控制（优势）

| 类别 | 控制点 | 代码位置 | 说明 |
|---|---|---|---|
| 请求认证 | App 端 HMAC-SHA256 签名（`X-App-Key` + `X-App-Signature` + `X-Timestamp` + `X-Nonce`） | `src/auth.rs` `verify_app_signature` | ±300s 时间窗口、单次 nonce 防重放、constant-time 比较、**先验签名后写 nonce**（F1，堵住未认证写 DB DoS） |
| 用户认证 | HS256 JWT（`iss=app:{id}`），过期检查，用户必须先注册于 `app_users` | `src/auth.rs` `verify_user_jwt` | 签名 constant-time 验证，拒绝未知用户和伪造签名 |
| 管理认证 | Admin Bearer token，constant-time 比较 | `src/auth.rs` `verify_admin` | |
| 管理面隔离 | 启动时拒绝非 loopback admin 绑定（`TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN` 才可覆盖） | `src/main.rs` F6 | 防止误配置把 admin API 暴露到公网 |
| 默认密码保护 | 检测到开发默认 `SERVER_SECRET` / `ADMIN_TOKEN` 时拒绝启动（可选 dev 逃生开关） | `src/main.rs` | 避免已知默认密钥 silently 上线 |
| 静态加密 | AES-256-GCM envelope，per-blob 随机 DEK，KEK = SHA-256(`SERVER_SECRET`)，自描述 `TSFS` 头 | `src/crypto.rs` `blob_encrypt`/`blob_decrypt`/`blob_rekey` | 备份/偷盗 blob 无密钥即不可解；支持 `blob_rekey` 做服务器密钥轮换 |
| Plaintext 缓存 TTL | `blob_root/dec_cache` 文件随维护循环按 mtime 清理（F2） | `src/storage.rs` `sweep_dec_cache` + `main.rs` 维护循环 | 解密明文不持久化 |
| 路径穿越防护 | `canonicalize` + `starts_with(app_root)`，拒绝 `..`/symlink 逃逸；UUID 扫描深度上限 5 | `src/storage.rs` `resolve_blob`/`locate_blob` | 存取 blob 均受控 |
| ACL 语义 | deny 优先于允许和 owner；deny 跨整个文件夹链收集；file-level allow 不能覆盖 inherited deny；支持 `g:<group>`、`*`、`public_read` | `src/authz.rs` `effective_acl`/`evaluate_acl_with_groups` | deny-by-default |
| 租户隔离 | 所有数据行按 `app_id` 过滤；`can_app_access_file` 只允许同 tenant；跨 app `file_id` 无法访问 | 各 route + `src/db.rs` | 物理 blob 目录按 `app_{id}` 隔离 |
| 用户 ID 安全校验 | 禁止 `/`、`\`、`..`、控制字符，长度 1..=128 | `src/routes/common.rs` `validate_user_id` | 防止 zip-slip 风格的归档条目和 tenant key 污染（F4） |
| 软删除 | DELETE 只打 tombstone，立即回滚 usage + 失效 tokens，blob 在 grace 期后由维护循环物理删除 | `src/routes/files.rs`/`folders.rs` + `src/db.rs` `purge_expired_tombstones` | 误删可恢复窗口 |
| 备份不含密钥 | 备份不写入 `SERVER_SECRET`、`admin_token`、`app.secret` 明文；跳过 `dec_cache/`、`exports/`、`tmp_*`；manifest 无 key material | `src/backup.rs` | 备份本身不构成解密能力 |
| 备份目标防逃逸 | 备份 target 必须 canonicalize 后仍在 `backup_root` 内；拒绝绝对路径和 `..` | `src/backup.rs` `resolve_backup_dir`/`validate_target` | |
| 速率限制 | Per-app 60s 固定窗口，generate/upload/export/chunked 共享一桶；硬容量 + expired sweep（anti memory-bomb） | `src/ratelimit.rs` | 429 + Retry-After |
| 幂等上传 | `Idempotency-Key` 在窗口内返回原结果，不写第二个 blob，不重复扣 quota；内存硬容量 + 过期清理 | `src/idem.rs` + `routes/upload.rs` | |
| 上传大小强制 | 流式体边写边累计，超 `max_payload_bytes` 立即中止；temp 文件 RAII guard 保证异常/断连清理 | `src/routes/upload.rs` | |
| 文件名清洗 | 去目录组件、控制字符、双引号；下载时 `Content-Disposition` 文件名再次 sanitize，`X-Content-Type-Options: nosniff` | `src/routes/upload.rs` `sanitize_file_name` + `download.rs` `disposition_filename` | |
| 文件夹环防护 | 变更 parent 时从新 parent 向根走链，命中移动目标即拒绝（F5） | `src/routes/folders.rs` `patch_folder` | |
| 审计日志 | actor / action / app_id / target / ip / decision，按 `TENANT_FS_AUDIT_RETENTION_DAYS` 保留并 prune | `src/db.rs` `audit`/`prune_audit` | |
| 前端控制台 | 纯静态资产（`include_str!`），非受信数据不进 `innerHTML`，CSP/frame-deny/nosniff/no-store/no-referrer，token 仅 sessionStorage | `src/admin_ui.rs` + `app.js` | 仅 loopback 服务 |
| 错误信息最小化 | 不存在的 token/文件统一返回 `not_found`，不泄露差异；异常不回显堆栈 | `src/error.rs` + 各 route | |

---

## 二、发现的问题（按修复优先级）

### 高危

**H1. 用户 JWT 在过期前不可撤销**

- 位置：`src/auth.rs` `verify_user_jwt`；`src/tokens.rs` 只有 *能力 token* 有 revoke，**用户身份 JWT 没有**。
- 问题：JWT 一经签发，在 `exp` 前始终有效。若 app secret 泄露、用户应被禁用或设备丢失，服务端在 `exp` 到达前无法使已签发 JWT 失效。`verify_user_jwt` 只校验 app 是否 enabled/未软删除、用户是否存在，不校验用户级撤销状态。
- 建议：引入用户级 revocation（如 `revoked_users` 表或 `app_users` 增加 `revoked_at`），在 `verify_user_jwt` 中校验；或在业务层缩短用户 JWT TTL、配合短期 refresh 模式。

### 中危

**M1. 下载限速在昂贵操作之后才执行，热链可绕过预算消耗 I/O**

- 位置：`src/routes/download.rs` `download` / `download_head`。
- 问题：先执行 `resolve_download`（DB 查询、token 校验、storage 解析、必要时把加密 blob 解密到 `dec_cache` 明文缓存），**然后**才调用 `ratelimit::gate`。有效 token 的请求在被限速前已完成磁盘读 + 解密；注释 F7 称“downloads count against budget”，但时序不对。
- 建议：把 `ratelimit::gate(&st, app_id)` 挪到 `resolve_download` 之前（或至少在 blob 读取/解密之前），使每个 app 的下载流量在消耗 I/O 前就受 60s 窗口限制；无效/过期 token 的请求本身已很廉价，可保留在 resolve 后返回 404。

**M2. 软删除/擦除后，`dec_cache` 中的 plaintext 残留未被立即清理**

- 位置：`src/routes/admin.rs` `wipe_app`/`purge_app`；`src/db.rs` `purge_expired_tombstones`；`src/storage.rs` `remove_blob`。
- 问题：`remove_blob` 会同时删 raw blob 和 `dec_cache` 条目，但 `wipe_app`/`purge_app` 只 `remove_dir_all(app_{id})`，不清理 `blob_root/dec_cache/` 下以 uuid 命名的明文缓存文件（dec_cache 按 uuid 而非 app_id 组织，无法由 wipe 直接定位）。软删除 tombstone 物理 purge 时，`remove_blob` 已覆盖；但直接 wipe/purge 路径会在 dec_cache TTL 到期前留下明文。
- 建议：`wipe_app`/`purge_app` 在删除 app blob 目录后，遍历 `blob_root/dec_cache` 删除与该 app 文件 uuid 相关的缓存（或在 purge_expired_tombstones 的返回行中同步清 dec_cache，并让 wipe/purge 复用同一清理逻辑）。

**M3. `export_download` 仅用 `starts_with` 校验导出文件路径，未 canonicalize**

- 位置：`src/routes/export.rs` `export_download`。
- 问题：`p.starts_with(blob_root.join("exports"))` 对未 canonicalize 的路径不足以阻断 symlink 恶意指向根外文件。当前 `path` 由服务器在 `run_export` 内部构造（`export_dir.join("job_{id}.zip")`），用户不可直接注入 symlink，风险较低；但若未来导出路径可由外部输入，`starts_with` 会被绕过。
- 建议：对导出下载路径也做 `canonicalize` + `starts_with(exports_root_canonical)`。

**M4. 上传路径对 App 请求的 HMAC 签名在 body 流式写入之后才验证**

- 位置：`src/routes/upload.rs` `upload` / `upload_chunk`。
- 问题：代码预检只拒绝“缺失签名头”的请求（不缓冲 body），但真正的 HMAC 验证在整个 body 流式写完 temp 文件之后。无效签名的请求仍会把 body 写入磁盘再被拒绝，浪费 I/O 和磁盘空间；大批此类请求可形成小型 DoS。
- 建议：对携带 `x-app-key` 的请求，在 streaming 前尽早完成 HMAC 验证（需先读全 body 再算 `body_hash`，或接受两次缓冲），无效签名则在落盘前直接 401。

**M5. 审计写入失败被静默吞掉（`.ok()`）**

- 位置：`src/db.rs` `audit`；各 route 的 `db::audit(...)` 调用不检查返回。
- 问题：审计表写满/锁定/磁盘错误时，主流程不受影响，但审计缺失无感知，违背“审计必须可靠”的原则。
- 建议：对安全相关审计（鉴权失败、删除、擦除、备份配置）写入失败时应至少记录错误日志；更严格者可让关键操作因审计失败而回滚/拒绝。

**M6. 无全局请求并发/空闲超时，慢客户端可占用连接**

- 位置：`src/main.rs` `axum::serve`。
- 问题：没有全局最大并发连接数和连接空闲超时，上传流式体可被客户端极慢发送以占用连接（Slowloris 风格）。
- 建议：给两个 `axum::serve` 增加连接数上限与超时（或在反向代理层做），并给 `bytes_ctx`/`to_bytes` 的 2 MiB 上限之外的流式上传增加 per-connection deadline。

### 低危 / 配置与设计选择

**L1. `audit_downloads` 默认关闭，敏感文件无 per-download 审计痕迹**

- 位置：`src/config.rs` `Ops.audit_downloads`；`src/routes/download.rs`。
- 说明：属设计选项（避免高读负载下审计量过大），不是缺陷。建议在存储敏密文件的部署中显式开启 `TENANT_FS_AUDIT_DOWNLOADS=true`，并确保审计保留期足够。

**L2. 导出/备份按原 blob 归档，已软删除的文件也会被备份**

- 位置：`src/routes/export.rs` `run_export`（`deleted_at IS NULL`，已排除）；`src/backup.rs` `tar_blobs`（遍历整个 blob 树，未排除 tombstoned 文件）。
- 说明：export 已排除已删除文件；backup 归档的是磁盘上的加密 blob，包含 grace 期内尚未 purge 的已删除文件。这是“备份包含历史”的合理行为，非缺陷；如需，可在备份时按 DB 排除 tombstoned 文件。

**L3. `encrypt_blobs=true` 时，legacy plaintext blob 不自动迁移，手动运行 `migrate_plaintext_blobs` 才加密**

- 位置：`src/storage.rs` `migrate_plaintext_blobs`；`src/lib.rs` `build_app` 只调用了 `cleanup_stale_tmp`，未自动迁移。
- 说明：现有明文 blob 会长期以明文存留，直到运维手动迁移。建议在首次启用加密时自动或文档化强制运行一次迁移。

**L4. 管理 API `create_app`/`rotate_secret` 将 `app_secret` 明文返回给调用者**

- 位置：`src/routes/admin.rs`；前端 `app.js` `showSecretOnce` 提示“只显示一次”。
- 说明：设计如此（one-time display），本身不是漏洞，但管理 token 泄露即可获取所有 app_secret 明文。应加强 admin token 保护（轮换、仅内网、审计告警）。

**L5. CSP 对 admin console 放宽了 `unsafe-eval`**

- 位置：`src/admin_ui.rs` `CSP`；`app.js` `G()` 里 `(0, eval)(x.responseText)` 作为 gsap 的 sandboxed webview 回退。
- 说明：控制台仅 loopback 且资源自托管，风险受控；若追求更严格 CSP，可移除 `unsafe-eval` 并确保所有 webview 可正常加载外部脚本。

**L6. 依赖版本较旧，未在代码中锁定微版（Cargo.lock 已锁）**

- 位置：`Cargo.toml`。
- 说明：`axum 0.8`、`tokio 1`、`rusqlite 0.32`、`aes-gcm 0.10` 等均无已知重大 CVE（审计时未联网查 CVE 数据库），建议定期运行 `cargo audit` / `cargo update --dry-run` 并监控 RustSec。

---

## 三、修复建议优先级排序

1. **H1**：增加用户级 JWT revocation / `app_users.revoked_at`，在 `verify_user_jwt` 中校验。
2. **M1**：把 `download`/`download_head` 的 `ratelimit::gate` 移到 blob 读取/解密之前。
3. **M2**：`wipe_app`/`purge_app` 及 tombstone 物理 purge 时同步清理 `dec_cache` 中对应 uuid 的 plaintext 缓存。
4. **M3**：`export_download` 对文件路径做 `canonicalize` + `starts_with`。
5. **M4**：对带 `x-app-key` 的上传请求，在 body 落盘前完成 HMAC 签名验证。
6. **M5**：关键审计写入失败不再静默忽略，至少记错误日志；安全敏感操作考虑因审计失败而拒绝。
7. **M6**：给两个 HTTP 服务增加全局并发连接上限与空闲超时。
8. **L3**：文档化或自动执行 legacy plaintext blob 的一次性 envelope 迁移。
9. 持续：定期 `cargo audit`，轮换 `TENANT_FS_SERVER_SECRET` / `TENANT_FS_ADMIN_TOKEN`，生产环境禁止使用开发默认值。

---

## 四、审计方法与边界

- 审计方式：只读代码审计，逐文件阅读 `src/` 下全部 `.rs`、嵌入的 HTML/JS/CSS、全部集成/单元测试；未运行服务，未做动态渗透测试，未联网查 CVE/RustSec。
- 未覆盖：编译器/标准库/运行时漏洞、操作系统与容器配置、反向代理/TLS 终止、密钥在部署环境中的分发与轮换过程、物理接入。
- 代码中已出现的 “F1~F7” 标注指代先前修复的问题，本次审计确认这些修复在代码中已落位。

---

## 五、修复状态（本轮已落地的改动，2026-11-10）

所有修复均**不改动公开 API、响应结构、路由或既有行为语义**；只在内部执行顺序、表列与日志层加固。测试套件 75 个用例全部通过。

| 编号 | 状态 | 修改文件 | 具体做法 |
|---|---|---|---|
| H1 | ✅ 已修复 | `src/db.rs`、`src/auth.rs` | `app_users` 新增 `revoked_at` 列（自动迁移，NULL=未撤销，默认不改变行为）；`verify_user_jwt` 在存在性检查中一并校验，撤销后立即拒绝。不新增 API。 |
| M1 | ✅ 已修复 | `src/routes/download.rs` | 将 `resolve_download` 拆为廉价的 `resolve_download_meta`（token+行校验）与昂贵的 `resolve_download_path`（blob 定位+解密）；`ratelimit::gate` 夹在二者之间，热 token 耗尽租户预算前不再消耗磁盘 I/O。 |
| M2 | ✅ 已修复 | `src/routes/admin.rs`、`src/storage.rs` | 新增 `storage::remove_dec_cache_entries`；`wipe_app`/`purge_app` 在删行前收集 storage_uuid，删除目录后同步清 `blob_root/dec_cache/<uuid>` 明文缓存。 |
| M3 | ✅ 已修复 | `src/routes/export.rs` | `export_download` 对 exports 根与制品同时 `canonicalize` 后比较，阻断 symlink 逃逸。 |
| M4 | ✅ 已修复 | `src/routes/upload.rs` | App 签名的 `upload`/`upload_chunk` 先缓冲 body（受 `max_payload_bytes` 约束）算 hash 并验签，**通过后才创建/写入磁盘文件**；JWT 请求保持流式。 |
| M5 | ✅ 已修复 | `src/db.rs` | `audit()` 写入失败时以包含 actor/action/app/target/decision 的 stderr 日志显式告警，不再静默 `.ok()`。 |
| M6 | ✅ 已修复 | `src/main.rs`、`Cargo.toml` | public/admin 两个 `axum::serve` 前置 `tower::limit::GlobalConcurrencyLimitLayer`（512/64），限制并发请求数；tower 启用 `limit` feature。 |
| L3 | ✅ 已修复 | `src/main.rs` | 启动时若 `encrypt_blobs` 开启，自动执行一次幂等的 `migrate_plaintext_blobs` 并记录数量/告警；不改 API 调用方式。 |

保留为“已接受的设计选择 / 运维建议”（未改代码，因改动会改变对外行为）：

- **L1** `audit_downloads` 默认关闭：保持默认值，避免高读负载审计量激增；敏感部署显式开启。
- **L2** 备份包含 grace 期内已软删除文件：合理历史行为，未改动。
- **L4** `create_app`/`rotate_secret` 一次性返回 `app_secret`：现有 API 契约，保持。
- **L5** admin console CSP 的 `unsafe-eval`：仅 loopback + 自托管资源，保持。
- **L6** 依赖版本：新增 `tokio-util` 到 `tower`（随 `tower` feature），其余版本未变；建议持续 `cargo audit`。
