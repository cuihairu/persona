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
- 不把 Server/Sync 作为强依赖；可选服务端不得接触明文身份材料。
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
| OS 钥匙串托管条目     | keyring 中的主密码（biometric unlock 用）      | 同用户恶意进程读取、陈旧条目       |

## 信任边界

1. **本地用户边界**：当前 OS 用户账户是主要安全边界。Persona 不应把明文写入 world-readable 路径，也不应依赖云端保密。
2. **进程内解锁边界**：解锁后的主密钥和部分明文只应存在于短期内存路径，锁定后必须清理服务状态。
3. **工作区边界**：SQLite、附件和配置文件属于同一个本地工作区；迁移必须保持向后兼容和最小权限。
4. **浏览器桥接边界**：浏览器扩展通过 Native Messaging 调用 `persona bridge`，敏感操作必须经过配对、HMAC、短期 session、origin binding 和 user gesture。
5. **SSH Agent 边界**：OpenSSH 客户端通过 socket/pipe 请求签名；agent 只暴露公钥列表和签名能力，不导出私钥。
6. **可选服务端边界**：server/sync 只能处理事件摘要、密文或同步元数据，不得成为明文解密方。已落地的 events API 仅接收审计事件摘要（action、资源类型、可选 ID、时间戳、成功标记与受限 metadata），以单 Bearer 令牌认证，未配置令牌即整体禁用（fail-closed）。
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
- 可选 Server/Sync 仍是后续方向；在 E2EE 同步完成前，不应把服务端当作恢复或信任根。
- persona-server 的 events API 是单令牌门禁的观测面：接受客户端自报的事件摘要（`client_timestamp` 不可信，排序只用 server 的 `received_at`），无保留策略（事件库无界增长），不构成防篡改审计账本。
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
- **认证**：单共享 Bearer 令牌（`PERSONA_SERVER_TOKEN`），常量时间比较；未配置即 503 整体禁用（fail-closed）。`/`、`/health`、`/metrics` 免认证。
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
