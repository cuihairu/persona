# Persona 威胁模型与周期性安全审查

本文档定义 Persona 当前主线产品的安全边界、主要威胁、已落地控制和复审机制。范围以根目录 `BOUNDARY.md` 为准：Persona 是本地优先、零知识的身份材料管理器，主要保护同一用户在不同身份上下文中的密码、API Key、TOTP、SSH Key、浏览器填充数据和相关元数据。

## 目标与非目标

目标：

- 保护本地工作区中的身份材料，避免未授权读取、填充、导出和签名。
- 将凭据、SSH Key、TOTP 等敏感材料限制在明确的身份上下文和来源上下文内使用。
- 在 CLI、桌面端、浏览器扩展和 SSH Agent 之间保持一致的加密、审计和策略边界。
- 在发生误用、异常填充、异常签名或配置变更时留下足够的本地审计证据。

非目标：

- 不防御已经完全控制当前用户会话的恶意内核、调试器或系统级恶意软件。
- 不承诺在未解锁且主密码丢失时恢复明文数据。
- 不把 Server/Sync 作为强依赖；可选服务端不得接触明文身份材料（加密备份恢复点除外——见"备份保管端点"，服务端持密文不持密钥）。
- 不把钱包能力作为当前安全主线，钱包相关能力仍按实验性范围处理。

## 资产

| 资产                  | 示例                                          | 主要风险                          |
| --------------------- | --------------------------------------------- | --------------------------------- |
| 主密码与派生主密钥    | `PERSONA_MASTER_PASSWORD`、内存中的解锁密钥   | 泄露后可解密本地工作区            |
| 单项凭据密钥          | `wrapped_item_key` 解封后的 item key          | 单项明文泄露或横向扩大            |
| 凭据明文              | 密码、API Key、TOTP secret、SSH 私钥 seed     | 数据外泄、未授权填充、未授权签名  |
| 工作区数据库          | SQLite、迁移、用户认证记录、元数据            | 离线暴力破解、篡改、回滚          |
| 浏览器桥接会话        | 配对密钥、短期 session、Native Messaging 消息 | 恶意扩展请求填充或复制            |
| SSH Agent socket/pipe | `SSH_AUTH_SOCK`、Windows Named Pipe           | 未授权签名、agent 转发滥用        |
| 审计日志              | 登录、解锁、凭据解密、SSH 签名摘要            | 篡改、删除、敏感字段误写入        |
| 备份/导入导出文件     | JSON/YAML/CSV、加密备份                       | 备份泄露、格式注入、弱 passphrase |
| OS 钥匙串托管条目     | keyring 中的主密码（biometric unlock 用）     | 同用户恶意进程读取、陈旧条目      |

## 信任边界

1. **本地用户边界**：当前 OS 用户账户是主要安全边界。Persona 不应把明文写入 world-readable 路径，也不应依赖云端保密。
2. **进程内解锁边界**：解锁后的主密钥和部分明文只应存在于短期内存路径，锁定后必须清理服务状态。
3. **工作区边界**：SQLite、附件和配置文件属于同一个本地工作区；迁移必须保持向后兼容和最小权限。
4. **浏览器桥接边界**：浏览器扩展通过 Native Messaging 调用 `persona bridge`，敏感操作必须经过配对、HMAC、短期 session、origin binding 和 user gesture。
5. **SSH Agent 边界**：OpenSSH 客户端通过 socket/pipe 请求签名；agent 只暴露公钥列表和签名能力，不导出私钥。
6. **可选服务端边界**：server/sync 只能处理事件摘要、密文或同步元数据，不得成为明文解密方。已落地的 events API 仅接收审计事件摘要（action、资源类型、可选 ID、时间戳、成功标记与受限 metadata），以 Bearer 令牌认证（多设备令牌或 legacy 单令牌），未配置令牌即整体禁用（fail-closed）。备份保管端点（2026-09）只存储客户端加密的 PERSENC1 密文与元数据，恢复需备份口令 + 主密码双要素，详见"备份保管端点"一节。
7. **自动化边界**：非交互模式允许用环境变量注入主密码，适合 CI，但环境变量由调用方负责隔离和清理。

## 主要威胁与控制

| STRIDE                 | 威胁                                             | 已有控制                                                                                           | 仍需关注                                                |
| ---------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Spoofing               | 恶意浏览器扩展伪装成已配对客户端                 | 配对码、`client_instance_id`、短期 session、HMAC-SHA256 请求认证                                   | 配对状态文件权限和撤销 UX 需要持续检查                  |
| Spoofing               | SSH 连接目标主机被冒充                           | known_hosts 强制模式、未知主机确认、每主机策略                                                     | known_hosts 解析仍需随 OpenSSH 格式演进复测             |
| Tampering              | 本地 SQLite 或配置被离线篡改                     | AES-GCM 认证加密保护凭据密文，迁移测试覆盖 schema                                                  | 明文元数据和审计日志仍可能被本地攻击者修改              |
| Tampering              | 导入文件或 Native Messaging 消息被构造为恶意输入 | JSON 解析、长度前缀协议、格式解析测试与 fuzz 路径                                                  | 需把新增解析器纳入 fuzz 清单                            |
| Repudiation            | 用户否认敏感操作                                 | 审计记录身份 CRUD、凭据解密、导出、SSH 签名摘要                                                    | 审计日志当前不是防篡改账本                              |
| Repudiation            | 客户端向 server 伪造/重放上报审计事件            | server 明确不宣称防抵赖；events API 仅作聚合观测（单 Bearer 令牌门禁、`client_event_id` 幂等去重） | per-client 设备身份与防抵赖（SRP/事件签名）留待同步轨道 |
| Information Disclosure | 工作区文件被复制并离线攻击                       | Argon2id/PBKDF2 派生、AES-256-GCM、单项 item key 包裹                                              | 主密码强度仍是核心风险；KDF 参数需周期性复审            |
| Information Disclosure | 浏览器后台页面悄悄读取密码/TOTP                  | user gesture、origin binding、活动身份过滤、只返回匹配凭据                                         | 没有 URL 的凭据无法绑定来源，应在 UI/CLI 中提示风险     |
| Information Disclosure | 日志泄露 secret、token、验证码                   | 日志脱敏策略和单元测试覆盖常见 secret/key/value 形式                                               | 新增日志字段必须先确认不含明文                          |
| Denial of Service      | Agent 被频繁请求签名或耗尽资源                   | 全局最小间隔、每小时/每日限制、每密钥/每主机策略                                                   | 长期运行 agent 需要实机压力测试                         |
| Elevation of Privilege | 被低信任自动化脚本借用解锁态执行敏感操作         | 自动锁、敏感操作再认证、非交互模式显式环境开关                                                     | 解锁态是高风险窗口，桌面端接线时要避免隐式授权          |

## 已落地安全控制

- **本地加密**：凭据明文使用 AES-256-GCM 加密；新写入凭据使用随机 item key，并由主密钥包裹。附件（attachments）复用所属凭据的 item key 封存——主密码轮换只重包 wrapped key、item key 不变，附件无需重写即跨轮换可解密；legacy 凭据（无 wrapped key）首次挂加密附件时原地升级为 item key 包裹，凭据删除级联清理附件 blob（孤儿 blob 持有的 item key 已不可恢复）。
- **密钥派生**：密码导出与部分数据加密使用 Argon2id；核心主密钥服务当前仍包含 PBKDF2 路径，需在安全复审中跟踪参数和迁移策略。
- **会话与锁定**：服务层支持自动锁、敏感操作再认证、生物识别 Provider 抽象和远程认证抽象。
- **浏览器桥接**：Native Messaging 协议包含配对、HMAC 请求认证、短期 session、重放窗口、origin binding 和 user gesture 要求。
- **SSH Agent 策略**：支持 deny-all、速率限制、known_hosts、每密钥/每主机 allow/deny、确认和生物识别优先级。
- **审计**：身份、凭据、解锁、导出、SSH 签名等敏感事件写入本地审计日志，SSH 签名只记录待签名数据 digest。
- **供应链检查**：`deny.toml`、cargo-deny、cargo-audit、npm audit/pnpm audit 和许可证策略已有文档化流程。
- **解析器测试**：TOTP、钱包导入导出、SSH 协议编码、浏览器桥协议具备单元/集成测试路径，部分 parser 已列入 fuzz 方向。

## 当前接受的限制

- 本地管理员、内核级恶意软件、调试器和内存转储仍可攻击解锁后的明文。
- 当前审计日志强调可追踪性，不提供加密签名链或远端不可抵赖性。
- `PERSONA_MASTER_PASSWORD` 适合自动化，但会暴露给同一执行环境中的进程/日志风险；CI 必须使用 secret store 并禁用命令回显。
- 没有 URL 的浏览器凭据无法做严格 origin binding；高价值凭据必须绑定 URL。
- 可选 Server/Sync 仍不是信任根：加密备份让服务端可作为密文快照的恢复点，但恢复能力以本地持有备份口令与主密码为前提，服务端不可用不应导致数据不可恢复（本地库是第一事实源）。
- persona-server 的 events API 是令牌门禁的观测面：接受客户端自报的事件摘要（`client_timestamp` 不可信，排序只用 server 的 `received_at`），无保留策略（事件库无界增长），不构成防篡改审计账本。
- 钱包能力仍是实验性，不能用当前主线安全承诺覆盖生产级资金安全。

## 安全复审节奏

每个版本发布前必须完成：

- 运行 `cargo test --workspace`，并运行对应前端/扩展测试。
- 运行 `cargo deny check` 和 JS 依赖审计。
- 检查新增日志、错误消息和审计 metadata，确认不包含明文 secret。
- 检查新增 CLI/bridge/agent 参数是否绕过 user gesture、origin binding、确认或自动锁。
- 检查新增迁移是否保护历史密文和 `wrapped_item_key`。

每月必须完成：

- 复查 RustSec、npm/pnpm audit 和过期依赖。
- 抽查 `PERSONA_*` 环境变量文档，确认没有新增高风险默认值。
- 抽查浏览器桥配对状态、session 过期和 nonce/HMAC 逻辑。
- 抽查 SSH Agent 策略默认值，确认默认不扩大签名权限。

每季度必须完成：

- 重新评估 KDF 参数、主密钥迁移和备份加密参数。
- 复审本威胁模型和 `BOUNDARY.md`，确认新功能仍在产品边界内。
- 对浏览器填充、SSH 签名、导入导出、备份恢复执行一次手工安全场景演练。
- 清理或解释 `deny.toml`、审计忽略项和未修复安全 TODO。

## 变更门槛

以下改动必须在 PR 中显式更新本威胁模型或说明不更新的理由：

- 新增明文 secret 类型、导出格式、同步路径或长期后台进程。
- 改变主密钥、item key、KDF、nonce、备份加密或签名算法。
- 改变浏览器桥接、Native Messaging、SSH Agent、自动化环境变量的认证/授权规则。
- 改变审计日志结构、脱敏策略、敏感 metadata 或日志保留策略。
- 引入新的生产网络 API、生产遥测或云端存储路径。

## 可选同步服务器（persona-server）

Events API（`POST/GET /api/v1/events`）与 `/metrics` 是 persona-server 的第一批生产网络端点，按"变更门槛"在此登记：

- **数据处理范围**：仅接收与存储审计事件摘要与元数据——action、resource_type、可选的 user/identity/credential/session ID、时间戳、成功标记、受限 metadata（≤32 条、键值长度有界）。协议上不承载明文 secret 或密钥材料；请求体双层限长——`Content-Length` 预检线上字节 ≤1 MiB（含 gzip 压缩传输）、解压后明文 ≤10 MiB（防解压炸弹，兼兜底无 Content-Length 的 chunked）、单批 ≤500 条。
- **认证**：共享 Bearer 令牌（legacy 单令牌 `PERSONA_SERVER_TOKEN` 或多设备令牌 `PERSONA_SERVER_TOKENS`），对全部条目常量时间比较；未配置即 503 整体禁用（fail-closed）。`/`、`/health`、`/metrics` 免认证。
- **明确不宣称**：该存储不是防篡改账本，不提供防抵赖保证——持有令牌的客户端可上报任意内容，`client_timestamp` 不可信；审计语义以各端本地审计日志为准，server 侧只作聚合观测。
- **指标面**：`/metrics` 输出请求计数（方法 + 路由模板 + 状态码）与事件接入计数，标签基数有界，不含用户数据或路径参数。
- **已知限制**：无保留策略（事件库无界增长）；无速率限制与配额；`ip_address`/`user_agent` 为客户端自报字段；permissive CORS（当前客户端非浏览器）；单令牌无 per-client 身份。

客户端上报器（`core::events::Emitter` + `ServerEventSink`，把本地审计事件尽力复制到上述 Events API）：

- **数据范围**：与 server 存储范围一致——本地审计摘要与受限元数据，不承载明文 secret 或密钥材料；wire 层逐条按 server 上限做字节级预校验，毒丸事件在客户端丢弃（server 是全有或全无校验，不让单条拖垮整批）。
- **令牌**：Bearer token 由宿主注入（`ServerEventSink::new(base_url, token)`），core 不读环境变量、不落盘；上报仅发往显式配置的 base_url。
- **非持久**：内存队列尽力而为复制——进程崩溃丢未 flush 批，无持久 outbox、不回补；本地 sqlite 审计库仍是唯一存证源（延续"不宣称防篡改/防抵赖"）。
- **背压**：上报绝不阻塞审计写入——队满丢最旧并计数；发送失败整批按原序回队，1s→5min 指数退避；`stop()` 的最终 flush 尽力而为，abort 丢失窗口上限 = 一个 batch_size。
- **传输压缩**（缺口已闭合）：明文 body >1 KiB 的批以 gzip（flate2 默认等级）发送并声明 `Content-Encoding: gzip`，server 侧 `RequestDecompressionLayer` 解压（tower-http 0.6）；小批明文直发。纯传输层压缩，协议形状、认证、审计存证语义不变；压缩封装在 `ServerEventSink` 内部，宿主零改动。解压面已限长（线上 1 MiB / 明文 10 MiB），损坏 gzip 流返回 4xx。
- **AutoLock 事件**（缺口已闭合）：`PersonaService::set_event_emitter` 同步传播给 `AutoLockManager`，其 SessionLocked/Unlocked 审计写库后走同一上报链；后台监控超时落锁的审计行同批补齐 session_id/user_id/details。`LockPending`/`Activity` 是 UI 事件不是审计动作，不写审计也不上报（维持现状）。

宿主接线（desktop / CLI / mobile 构造 Emitter 并注入 `PersonaService` 的端点）：

- **desktop（Tauri）**：`settings.sync` 段存 vault 的 `workspaces.settings` JSON 列，但 `server_token` **恒写空串占位**——token 真值存 OS keyring（keyring 4：Linux secret-service / macOS Keychain / Windows Credential Manager；service `"persona-sync"`、键为 vault db_path，字段级加密缺口已闭合）。keyring 批次之前的 legacy 明文在运行时一次性迁移进 keyring、DB 清空；迁移前 keyring 不可用时**保留明文不销毁数据**（上报禁用，下次 attach 重试）。`get_workspace_settings` 免解锁（解锁屏裁剪 UI 需要）返回的 sync 段因此不再含 token，锁定状态下 IPC 不暴露令牌；新增免解锁 `sync_token_present` 布尔查询（仅泄露"是否配置过"一位元数据），前端 placeholder 由它驱动、token 不回填。fail-closed 语义：提交非空 token 时 keyring 写失败拒绝保存；挂上报器要求 enabled + url 非空 + keyring 有 token 三者齐备；禁用即清 keyring（失败仅 warn，残留令牌在同一 OS 用户信任域内）；vault 文件拷到他机 → keyring 无对应条目 → 上报不启用，需重输入。配置保存即重挂上报器（停旧换新）；进程退出经 `RunEvent::Exit` 尽力最终 flush。
- **CLI**：env-only（`PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN` 都非空才启用，空白视同未设置），**不落盘**——配置文件通道故意不提供；`main` 尾部 `stop()` 尽力 flush，release `panic = "abort"` 的崩溃路径不经 flush（丢失窗口与上面内存队列限制一致）。
- **mobile（persona-mobile，Rust FFI 层）**：手写 extern "C" 宿主接线——`persona_service_init`（建户/认证序列对齐 desktop）、`persona_service_unlock/lock/is_unlocked`、`persona_configure_sync`（url+token trim 后都非空才启用、任一空白即摘除，fail-closed 对齐 CLI；URL 不做格式预校验，与 desktop attach 一致，格式错误在发送期暴露并退避）、`persona_shutdown`（落锁清密钥 + 尽力最终 flush + 清槽位）。**Rust 侧不落盘、不读环境变量**：url/token 由宿主（Dart 层）经 FFI 参数注入，服务状态留 Rust 侧全局槽位、密钥材料不跨 FFI 边界。如实标注未完成面：Flutter 工程本身（android/ios 目录、gradle）、Dart FFI 绑定层与 flutter_secure_storage 的 token 存储接线均未落地（本机无 Flutter SDK），当前安全结论只覆盖 Rust FFI 层；杀进程丢未 flush 批为已知限制（与 CLI/desktop 同）。手工验收（cargo-ndk 交叉编译、真 server 上报）转交有设备环境时执行。
- **上报面不变**：三宿主沿用同一 `ServerEventSink`（Bearer + POST /api/v1/events），仅发往用户显式配置的 base_url；desktop 侧新增的外联面即该配置指向的服务器。

## 备份保管端点（`/api/v1/backups`，2026-09）

同步第一阶段：整库加密备份的保管。客户端把 VACUUM INTO 物理快照 gzip 后按 PERSENC1（Argon2id + AES-256-GCM，与 CLI `--encrypt` 导出同一格式）加密上传，服务器只见密文。

- **数据处理范围**：仅存储密文文件（`{backup_dir}/{uuid}.persenc`）与元数据（设备名、字节数、sha256、时间戳）。服务器无备份口令与主密码，密文不可解；设备名由命中的设备令牌推导，客户端不可自报。
- **认证**：与 events 同一 Bearer 门禁——多设备令牌 `PERSONA_SERVER_TOKENS`（`"laptop:tok1,phone:tok2"`，对全部条目无早退常量时间比较）或 legacy 单令牌（"default" 设备）；非法格式启动即错（fail-closed）。上传上限 256 MiB（Content-Length 预检 + 流式计数双保险，超限删半成品）；子路由无解压层（密文不可压，少一个解压炸弹面）。
- **明确不宣称**：不防服务器操作者**扣留、删除或回滚**备份——无哈希链、无签名、无版本不可抵赖证明，持有令牌或主机控制权的一方可将库回退到旧版本（客户端恢复时无新鲜度校验）。phase 2 可加哈希链/签名；当前接受此风险并以"本地库是第一事实源"对冲。
- **恢复双要素**：恢复 = 下载密文 + 备份口令解密 + 主密码解锁库。备份口令丢失 = 备份不可恢复（无托管、无重置）；主密码丢失同理。
- **保留与去重**：同设备与最新版本 sha256 相同则去重（幂等重传）；`PERSONA_SERVER_BACKUP_MAX_VERSIONS`（默认 0 不限）全局删最旧（文件与行同删）。
- **已知限制**：附件 blob 不在 v1 备份内（恢复后附件元数据在、文件体缺失，客户端 UI/CLI 明示）；备份内容为新版本创建时的完整快照，不含后续增量。

## SRP 设备认证端点（`/api/v1/auth/*`，2026-09，E2EE 同步轨道阶段 1）

SRP-6a（RFC 5054 4096-bit group + SHA-256）设备登录：客户端本地以 Argon2id
预 hash 主密码派生 SRP 私钥，服务器只存 verifier（`auth_devices` 表：设备名、
salt、verifier，密码与 Argon2 派生值永不出机）。设计见
`docs/E2EE_SYNC_DESIGN.md` DR-2。

- **数据处理范围**：落盘仅设备名 + salt + verifier（注册时经既有 Bearer 上传——引导链）；未决握手（session_id、服务器临时私钥、客户端公开值，TTL 120s）、已签发短期令牌（TTL 15 分钟）、失败计数**全部内存态、有意不持久化**——服务器重启即全部失效（fail-closed，重新登录）。
- **认证**：`/register` 需既有 Bearer（静态令牌或已登录 SRP 令牌）；`/challenge` 与 `/verify` 免 Bearer（它们就是换取令牌的登录步骤），凭 SRP 证明放行；签发令牌为随机 ≥256-bit base64url，`require_bearer` 静态令牌优先、miss 后查 SRP 令牌表——**TOKENS Bearer 路径保留共存，备份链不打断**。认证体系未配置（无 TOKENS）时三端点整体 503（与 events/backups 同 fail-closed）。
- **爆破与滥用缓解**：Argon2id 预 hash（v19，m=19 MiB、t=2、p=1，与本地库解锁同参数、域分隔盐 `persona-srp-v1`）使 verifier 泄露后的离线猜解成本 ≈ Argon2 成本；连续 5 次验证失败锁 15 分钟（对齐本机 user_auth 语义，返回 423）；challenge 一次性（verify 即从缓存取走）+ 120s TTL；设备名不存在与任何握手失败同形 401（不暴露注册状态）；M1/M2 双向证明核验（客户端核验 M2 防恶意服务器/中间人降级）。`/auth` 子路由整体 64 KiB body 上限，base64 字段解码有逐字段字节上限。
- **明确不宣称**：不防服务器操作者对 `auth_devices` 表**离线爆破 verifier**（verifier 在服务器手里，成本 = Argon2 + 主密码强度——与本地库被拖库同级，主密码强度仍是核心风险）；不防**未认证 challenge 刷量**（内存会话缓存无速率限制，已知 DoS 面，部署侧反代缓解）；不防服务器**拒绝服务/删除注册记录**（设备无第二副本，重新注册即可，但属可用性损失）；SRP 数学依赖 RustCrypto `srp` crate（低维护，见设计稿 crate 调研）——由 RFC 5054 官方向量回归测试锁定实现，seam 隔离可换。
- **已知限制**：设备吊销/移除已落地（2026-09 吊销闭环）：同步设备吊销（`DELETE /sync/devices/:id`）级联删除同名 `auth_devices` 行（SRP 登记以设备名为键），并即刻吊销其内存短期令牌与未决握手（`SrpAuthState::revoke_device`——被吊销设备的既有凭证不再能用，真 TCP 测试锁定）；但吊销粒度是**设备**——无独立的「只吊令牌不吊设备」操作，令牌离开设备吊销仍以 TTL（15 分钟）自然失效；无变更门槛外的审计——注册/登录仅服务器日志（`tracing`），不入事件库。

## E2EE 同步中继（`/api/v1/sync/*`，2026-09，E2EE 同步轨道阶段 2）

设备间端到端加密同步的密文中继：oplog（逐条 `SyncOp`：item UUID、kind、
`(lamport, device_id)` 排序键、密文载荷）按到达顺序追加、按游标转发；
group key 以「设备信封」形态保管（X25519 静态公钥密封 + AES-256-GCM，
`persona-dev-env-1`）。服务器是**纯中继**：盲存、追加、转发，不做任何
胜负判定或合并。设计见 `docs/E2EE_SYNC_DESIGN.md`（DR-1/3/4），服务端
可见面清单见其 §9。

- **信任根**：主密码（仅本地，从不外发）+ 每设备 X25519 私钥（DR-1，持久化由宿主负责——OS keyring / 0600 文件，core 不依赖 keyring）。服务器没有任何解密路径：不见 group key 明文、不见 per-item key，只有密文与元数据（集成测试 `server_stores_only_ciphertext` 锁定）。
- **数据处理范围**：oplog 行（op_id/item_id/kind/op/lamport/device_id/timestamp + 密文两列，单批 ≤500 条、载荷 ≤512 KiB、body ≤1 MiB）、设备登记（设备名 + 32 字节 X25519 公钥，重名 409——公钥不可被静默替换）、信封（80 字节，**只能挂已登记设备**——信封不能挂幽灵设备，服务器侧 fail-closed 的一半）。**诚实登记的元数据侧信道**：服务器可观察条目数量、尺寸、到达时间与设备拓扑——不缓解（by design，密文长度不可避免）。
- **冲突由客户端裁决**（DR-4）：胜负以 `(lamport, device_id)` 全序由各客户端独立计算（同 item 同 lamport 异 device = 真冲突，保双版本等用户裁决）；服务器按到达顺序存储转发，`server_does_not_arbitrate_conflicts` 与双端收敛测试 `two_devices_converge_over_real_tcp_conflict_keeps_both_versions`（真 TCP，双端离线编辑真冲突 → 两端收敛同一主位 + 双版本密文都在）锁定该语义。
- **认证与授权**：整个子路由挂 `require_bearer`（静态令牌与 SRP 短期令牌共存，同 events/backups）。授权语义 = **「有信封 = 已授权」，由密码学而非服务器 ACL 承担**：未授权设备 GET 拿得到别人的信封，但无对应私钥则 GCM tag 校验必失败——拿不到 group key 也解不开任何条目（`group_key_envelope_round_trip_and_fail_closed` 锁定）。
- **明确不宣称**：不防服务器篡改/回滚/选择性扣留 oplog（「设备私钥签名 oplog」是设计稿 §11 开放问题 6，远期）；不防恶意服务器/客户端无限灌 oplog（批内上限只缓解量级，不根除）；**本阶段不校验 op.device_id 与认证身份的对应**（静态 token 与 SRP token 混用，无统一映射）——恶意客户端可向 oplog 写任意密文垃圾或伪造更高 lamport 的假版本，但解不开任何条目，也删不掉其他设备的本地库（本地优先：服务器永远不是事实源，伪造版本在正常设备上同样进 LWW、不覆盖其本地明文库）。设备被攻破的爆炸半径 = 该设备私钥 → group key → 全部同步数据，与「本机被攻破 = 本库全失」同级，不因同步而放大额外资产。
- **已知限制**：附件不经 oplog（512 KiB 载荷上限；v2 议题）；travel 激活期间 push/pull 双停是**客户端引擎闸**（`SyncEngine` 构造注入，服务器无感知）——闸失效的后果是 travel 语义被同步破坏，属阶段 3 接线时的走查项；group key 轮换已实现（2026-09 阶段 3d，桌面「轮换组密钥」）但**吊销 ≠ 轮换**：只吊销不轮换时历史密文仍可被被移除设备移除前的密钥解开（**无前向安全**，DR-3 诚实边界；轮换后新密文对该设备不可读，窗口内未推送的旧密文除外——用户文档与确认弹窗均如实提示）。**并发轮换以 epoch 乐观锁互斥**（2026-09-24，`rotate-begin` CAS）：只防诚实客户端的意外并发——后到者 409 中止、未写信封未重包；**不防恶意客户端**绕过 begin 直接写信封/重包 op（写入真实性属「设备私钥签名 oplog」远期边界，本阶段登记的「不校验 op.device_id 与认证身份」同族）。oplog 无限增长已由保留策略缓解（2026-09-24：客户端 GC + `PERSONA_SERVER_OPS_RETENTION_DAYS`，§11 开放问题 3 两端收口；默认 0 = 不清理，开窗即放弃向离线超窗设备补发历史的责任）。

## Travel Mode（travel.persenc sidecar，2026-09）

按 identity 粒度的"从本设备移除"：enter 把被标记身份的全部数据（含附件密文
文件字节）打包 gzip 后按 PERSENC1（独立 travel 口令，Argon2id 64 MiB 默认
参数）加密为 `<db dir>/travel.persenc`，再在单事务内从主库删除——主库零痕迹，
**主密码打不开 sidecar（by design，非缺陷）**；exit 输 travel 口令原样恢复。
该设计引入新的单点资产与新的丢失面：

- **口令强度自担**：sidecar 只有一个口令保护，强度完全由用户承担；口令丢失
  = 被移除身份永久不可恢复（无托管、无重置、无主密码回退）。UI/CLI 在
  enter 时明示"no master-password fallback"。
- **sidecar 删除 = 数据丢失**：travel 激活期间（`travel_mode=true`）手删或
  介质损坏丢失 sidecar 即数据永久丢失。status 命令与桌面设置页以
  `inconsistent` 红色警告诚实呈现（不假装可恢复），不做任何自动清理。
- **本机攻击者可删 sidecar（拒绝服务，接受）**：同 OS 用户进程对
  sidecar 文件有写权限即可销毁被移除身份的唯一副本。不宣称防本机攻击者
  破坏数据（与"恶意进程可读 keyring"同一信任边界）；恶意进程同样可删主库，
  travel mode 未新增该边界，只是把丢失面集中到一个文件。
- **加密面**：sidecar 密文对持有设备者、云同步目录、USB 拷贝均不泄露明文
  （与整库备份同一 PERSENC1 格式）；崩溃窗口语义——sidecar 写成功后才动库，
  4→5 之间崩 = sidecar 在但旗标 false（enter 拒绝，提示 exit 或删残留），
  5→6 之间崩 = exit 自愈覆写。
- **改密互斥**：travel 激活期间拒绝改主密码（sidecar 无主密码绑定，改密
  本身不破坏 sidecar，但为避免"激活期间密钥材料语义漂移"的全部组合证明，
  直接拒绝并返回 `TRAVEL_MODE_ACTIVE`，exit 后可改）。
- **运行态清理**：desktop enter 成功后停 SSH agent（agent 内存可能持有被
  移除身份的密钥）；audit_logs 只保留 id 引用（明文元数据随 change_history
  一并搬入 sidecar，主库不留可读残留）。

## Biometric Unlock（桌面指纹/生物识别解锁）

桌面端把主密码托管进 OS 钥匙串，用系统认证框（Linux polkit `auth_self` /
macOS LocalAuthentication `DeviceOwnerAuthentication` / Windows Hello）换取
免输主密码解锁。**该设计把"知道主密码"降级为"能通过 OS 用户认证"**，
新增资产与威胁面在此白纸黑字：

- **资产**：keyring（Linux secret-service `persona-biometric` service /
  macOS Keychain / Windows Credential Manager）中按 vault db_path 为键存的
  主密码明文。
- **固有暴露（接受）**：**同 OS 用户的任意进程可读 OS 钥匙串**——
  Linux secret-service 对同会话进程基本不设防；**Windows Credential
  Manager 无 per-entry ACL，同用户任意用户态进程可直接读取**。这是
  1Password 同款直存设计的固有代价：本机用户边界一旦被攻破（恶意软件
  以当前用户运行），托管的主密码即泄露。缓解只有"用户级前置防线"
  （OS 用户认证、应用来源管控）；对抗该场景需要专用硬件（TPM/SEP
  绑定 + ATTCK 级进程隔离），超出本设计范围。
- **生物路径爆破**：biometric_unlock 取回密码后走 `authenticate_user`
  本尊，**吃与密码路径共享的失败计数**（5 次锁户）。控制：条目不存在
  时干净报错不弹框；InvalidCredentials 当场自删条目并返回
  `BIOMETRIC_RESET`（防反复点指纹把账户锁死）。
- **陈旧条目**：桌面外改密（CLI）覆盖不到 keyring 联动——InvalidCredentials
  自删（上一条）即兜底；桌面内改密成功则同步更新条目，写失败即删
  （fail-closed：宁可让用户重输密码，不留打不开库的旧密码）。
- **系统弹窗仿冒**：任何进程都能请求 OS 认证框，用户无法从框本身分辨
  是谁发起。缓解：action id/message 固定为 Persona 专属
  （`com.persona.desktop.biometric-unlock`）；polkit subject 用
  system-bus-name（bus daemon 解析对端凭据，免疫 PID 复用类缺陷，
  规避 zbus_polkit <5.1.0 的 CVE-2026-78422）。
- **可用性 fail-closed**：无 fprintd/polkit agent、无 secret service、
  rpm/AppImage/dev 构建未装 action 文件 → availability 探测失败即整体
  降级为不可用（按钮不渲染），不做半开半关。
- **超时**：ceremony 专用线程 120s 超时 + macOS 内层 reply 等待 110s，
  弹框卡死不拖死 UI 线程。
- **enable 门禁**：先验主密码后弹 OS 认证框——绝不把未验证的密码写进
  keyring；enable 走解锁门禁（同 set_locale），disable 幂等删且不设门禁
  （收紧操作从宽）。
- **SSH agent 联动**：agent 的 require_biometric 策略默认拒绝 + 显式注入
  OS provider（消除内置 Mock 静默放行面）。
- **硬件绑定包裹层（2026-09-26，`docs/biometric-unlock-design.md`）**：
  门禁层之上的升级档——keyring 新增 `persona-biometric-wrap` service，
  存的是被平台硬件密钥包裹的**密文 blob**（BIOWRAP1 信封），与门禁层
  密码条目互斥。T1（同用户恶意进程读 keyring）在此档下只能拿到打不开
  的密文：解密必须过硬件认证（SE/TPM/Keystore），私钥永不导出。
  剩余威胁面：enrollment 漂移（换指纹）→ 解包失败即自动删 blob 回主密码
  （core 信封指纹二次比对纵深防御）；改密后旧 blob 包的是 stale key，
  桌面改密联动当场删除；`BIOMETRIC_CANCELLED` 不删 blob（取消≠失败）。
  Linux 定格门禁档（无硬件封装），macOS 硬件档待真机 spike 验证前默认
  不启用——未验证的路径不在生产 unlock 链上。

## Connect 本机自动化端点（`127.0.0.1` HTTP，2026-09，secrets automation）

桌面宿主进程内嵌 axum listener（DR-1），让本机脚本/工具按 token 范围只读
拉取凭据。**开关默认关闭**：不创建 listener 即无端口面；启用时 bind 硬编码
loopback、端口由 OS 分配（无配置面，不可被诱导监听 0.0.0.0）。新增威胁面：

- **信任根与可见面**：解锁态 + token 二元门禁（缺一即拒）。token 决定
  「哪个身份下的哪些类型」；scope 外条目 404 与 403 同形（对消费者不存在，
  防探测）。health 免认证但零信息（不报解锁态、不报库存在性）。
- **不宣称**：防本机恶意进程——token 交到它手里的那一刻（环境变量/参数/
  配置文件）就对它可见，与 1Password CLI 同边界；防宿主进程被攻破——
  automation 不扩大也不缩小该边界；多用户 OS 隔离（同既有口径）。
- **恶意网页三防线**（DR-4）：浏览器是 127.0.0.1 上唯一"陌生调用方"，
  三道独立防线各自 fail-closed——① Host 头白名单（仅
  `127.0.0.1`/`localhost`/`[::1]`），DNS rebinding 后 Host 是攻击域，
  421 拒绝；② 请求带 `Origin` 头（浏览器 fetch 的标记）即 403，CORS
  全关（不回 `Access-Control-Allow-*`，preflight 直接失败）；③ Bearer
  token 必需，缺失/未知/已吊销同形 401。恶意网页同时需要绕过全部三道
  才能触达数据，而 token 本身不在网页可及处。
- **已知残面（文档禁止此用法）**：若用户把明文 token 配置进**浏览器
  扩展可及的存储**（localStorage、扩展 settings），上述三防线对持有该
  token 的网页形同虚设——防线防的是"无 token 的网页"。设置页明文展示
  处的警示只说明一次性，不改变此边界。
- **token 泄露爆炸半径**：三维 scope 圈定的**只读**面（verbs 恒 read，
  无写路径 = 无篡改半径）+ 即时吊销（无缓存，下一请求即 401）+ audit
  可见（Used 走每 token 每分钟节流聚合）。token 只存 SHA-256 哈希，
  库/备份泄露不等于 token 泄露；明文 `pconn_` 前缀 + 32B 随机，离线
  不可爆破。passkey/wallet/ssh/custom 类型恒不可授权（词汇表层面不存在）。
- **管理面**：创建/吊销走 reauth 门禁（core `ensure_sensitive_operation_allowed`
  权威）；明文只在创建响应出现一次；锁定态管理动作先被敏感门禁拒绝。
- **DoS / 资源面**：每 token 每分钟 120 请求 429 上限（写死），保护宿主
  不被自动化消费者拖垮；锁定期间 503 `vault_locked` 且**不扣限额**；
  health 不占限额。listener 占用面极小（loopback 单口），仅解锁态返回
  数据，锁定 503。
- **吊销与审计**：吊销即时幂等；`ConnectTokenCreated/Revoked/Used` 三
  audit 动作入审计日志；创建/吊销记录 resource_id，不落 token 明文。
