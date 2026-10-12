# 架构实现状态审计报告（2026-10-12）

> 依据 [2026-10-12-target-architecture-correction.md](./2026-10-12-target-architecture-correction.md) 第 8 节方法执行：
> 代码审查（Principal / Policy / authorize 真实存在性）→ 路径追踪（CLI / 桌面 / SSH Agent / Connect 四入口）→ 文档校正（Implemented / Partial / Planned / Unverified 标签）。
> 本轮只改文档，不改代码。审查范围：`core/`、`connect-server/`、`cli/`、`desktop/src-tauri/`、`agents/ssh-agent/`、`server/`。
> 标签口径：**Implemented** = 代码存在且可测试；**Partial** = 机制存在但未成为一级模型或仅部分入口使用；**Planned** = 设计方向，代码不存在；**Unverified** = 本轮无法给出结论。

---

## 1. 改过的文件

| 文件 | 改动 |
|------|------|
| `docs/src/overview/architecture.md` | 目标架构图标注规划组件；授权决策链/受控自动化契约逐条加状态标签；安全等级表标「纯标签」；组件职责与数据流修正失真描述 |
| `docs/src/design/architecture.md` | 分层表核心领域层路径修正；数据存储节 Vault 文件/审计日志两条与代码不符处修正；模块交互图与扩展点加注 |
| `docs/review/2026-10-12-audit-report.md` | 本报告（新增） |

---

## 2. 概念实现状态总表（代码依据）

| 概念 | 状态 | 代码依据 |
|------|------|---------|
| **Principal（主体）** | **Planned** | 全仓 `*.rs` 大小写不敏感 grep `principal` 零命中。调用方在代码里的词汇是 identity / credential_id / key_id / session / scope。与校正文档预审一致 |
| **Identity（分身）** | **Implemented** | `core/src/models/identity.rs`（`IdentityType` :55-62，`is_active` :44-45）；active 指针 `core/src/models/workspace.rs:17-18`；切换 `switch_identity`（workspace.rs:227-232，CLI `cli/src/commands/switch.rs:269-282`，桌面 `desktop/src-tauri/src/commands.rs:475-501`） |
| **Context（上下文）** | **Partial** | 无独立 Context 类型。上下文事实分散：SSH 主机名（`agents/ssh-agent/src/policy.rs:231` known_hosts 判定）、浏览器 origin binding（`validate_origin_binding`）、workspace active_identity_id。唯一的 `SecurityContext`（`core/src/auth/security_strategies.rs:774`）属于未接线的策略机（见 Policy 行） |
| **Material（材料）** | **Implemented** | `core/src/models/credential.rs`（`CredentialData` 枚举，`wrapped_item_key` :146-147）；per-item key 层次 `core/src/crypto/key_hierarchy.rs:12-44` |
| **Policy（策略）** | **Partial** | 无统一策略引擎，实际是散点硬门槛：SSH `SigningPolicy`/`PolicyEnforcer`（`agents/ssh-agent/src/policy.rs:19,142,225`）、`AutoLockPolicy`（`core/src/models/auto_lock_policy.rs:7`，锁定语义非授权）、敏感操作 reauth 闸门（`core/src/service.rs:431`）、Connect scope（`core/src/connect/token.rs:66-73`）。**已写好但未接线**：`SecurityStrategy`（时间/位置/设备/行为/网络五类条件，security_strategies.rs:7-519）与 `PermissionChecker`（`core/src/auth/permissions.rs:50`，零使用）——`auto_lock_dashboard.rs` 的求值入口无任何生产调用方 |
| **统一 authorize 入口** | **Planned** | 不存在共享 `authorize()`。四套机制各自为政：① core 服务层门禁 `ensure_sensitive_operation_allowed`（service.rs:431，解锁+reauth，10+ 调用方，是**最接近统一**的一个，但不含动词/资源裁决）；② Connect 数据面内联 scope 检查（service.rs:2292-2294 `connect_gate()` + `scope.allows_verb`）；③ SSH Agent `check_signature`（agents/ssh-agent/src/lib.rs:276）产出四态决策；④ CLI export 走 `ui.confirm`（`cli/src/commands/export.rs:73-95`）。`cli/src/commands/ssh.rs:1346` 的 `authorize` 是 authorized_keys 分发命令，与授权无关 |
| **Action（动作）** | **Partial** | `ConnectVerb` 只有 `Read` 且创建期强制恰为 `[read]`（token.rs:58-60,77-81）；SSH 只有 sign（approval.rs:19「currently always sign」）；read（Connect）/ use（agent sign）/ export（CLI confirm）三者授权语义彼此独立、无共享模型。校正文档第 5 节的 Action 粒度表整体为规划 |
| **Connect Token Scope** | **Partial** | 资源范围 **Implemented**：三维 scope（identities/item_types/verbs，token.rs:66-73），敏感类型（SSH/钱包/custom）排除法永不进 scope（token.rs:47-49），哈希落库、明文仅展示一次（service.rs:2154-2202），吊销即时生效每请求查表（service.rs:2258-2271，`connect-server/src/lib.rs:288-313`）。**缺口**：无 principal 字段（token.rs:106-117）；无过期机制（grep expires/ttl 零命中，`core/migrations/015_connect_tokens.sql:13-15` 仅 created/last_used/revoked）；scope 拒绝返回同形 404/空列表（防探测，lib.rs:455-476）但**不写审计**（service.rs:2288-2390 零 log_audit） |
| **Security Level** | **Partial（纯标签）** | `Critical/High/Medium/Low`（`core/src/models/credential.rs:83-92`）存在，但全仓无任何按凭据等级分支的强制行为——使用点全是存储映射（repository.rs:382-386）、导入默认值、统计计数（service.rs:1693-1710）、CLI/前端展示。CLI export 的两道确认（export.rs:77,83-95）与条目等级无关。校正文档预审的 L3「Partial」、L4「Unverified」本轮收敛为：**有等级字段，无独立密钥边界，无等级化授权** |
| **Unlock State（解锁状态）** | **Implemented** | 解锁态 = 内存 `master_encryption: Option<EncryptionService>`（service.rs:82-83,163-167）；锁定清密钥 `lock()`（service.rs:177-185）+ session `locked` 旗标（`core/src/auth/session.rs:29-30`）；AutoLockManager 后台巡检（`core/src/auth/auto_lock.rs:463-574`，默认空闲 300s service.rs:137）；桌面层补刀：Locked 事件独立任务 `service.lock()`（`desktop/src-tauri/src/commands.rs:163-201`）。StepUp 存在：敏感操作再认证（session.rs:105-113 `requires_sensitive_reauth`，`require_reauth_sensitive` 默认 false，敏感超时 300s，`force_lock_sensitive` 默认 true → `LockReason::SecurityViolation` 强锁）；钱包种子另有条目密码第二因子（credential.rs:305-308 `item_password_hash`）；账户 5 次失败锁 300s（`core/src/auth/authentication.rs:157-161`） |
| **密钥层次** | **Implemented（文档口径需修正）** | 实际三层：主密码 →**PBKDF2-HMAC-SHA256 100k**→ 主密钥（`core/src/auth/authentication.rs:203`，`core/src/crypto/keys.rs:105-107`；口令**验证**哈希另用 Argon2id PHC，hashing.rs:17 + authentication.rs:88-91）→ AES-GCM 包裹 → 每条 credential/passkey 独立 item key（key_hierarchy.rs:37-44，迁移 004/010）；同一 item key 再封附件（service.rs:2714-2755）、custom_fields blob（`core/src/custom_fields.rs:6-8`）、同步快照。主密钥不落盘、每次解锁现场派生（仅生物识别 `BIOWRAP1` 包裹是持久化例外，`core/src/auth/biometric_wrap.rs:21-25`）；改密只 rewrap item key 不动密文（key_hierarchy.rs:113-135）。同步 `GroupKey` 是独立平行链（`core/src/sync/keys.rs:2-4`，OS keyring `persona-sync-group`，仅同步 oplog/信封用）。备份/旅行 sidecar 是唯一 Argon2id(64MiB) 加密文件（`core/src/backup/file_crypto.rs:4-33`） |
| **审计** | **Implemented（文档口径需修正）** | 存 SQLite `audit_logs` 表（`core/src/storage/repository.rs:1158-1190`），14 字段（`core/src/models/audit_log.rs:9-51`），**不是** JSONL 文件。认证层 deny 写（未知/吊销 token，60s 节流，service.rs:2245-2270）；**scope 层 deny 不写**。先落本地库为存证源，再尽力异步复制远端（`core/src/events/emitter.rs:54-58`，service.rs:3421-3425，失败丢队列不回补）。 |

**Unverified 清零说明**：校正文档预审中标注 Unverified 的三项均已在代码中验证并收敛——Token 过期（不存在）、L4 独立密钥边界（不存在）、统一 authorize 入口（不存在）。

---

## 3. 发现的架构缺口

1. **Principal 缺失（高）**：调用方身份没有一级模型。Connect Token 无 principal 绑定，审计无法回答「哪个应用在何时读了什么」以外的问题（仅有 token 指纹间接关联）。
2. **授权入口分裂（高）**：四套机制（core 门禁 / Connect scope / SSH PolicyEnforcer / CLI confirm）无共享模型。「允许 sign ≠ 允许 export」目前只靠三个入口互不联通这一事实成立，不是被表达的规则。
3. **Action 语义不成体系（高）**：ConnectVerb 单变体且创建期写死 `[read]`，无法表达 use/fill；SSH 签名的四态决策（Allowed/RequireConfirm/RequireBiometric/Denied）是 agent 局部模型，不外溢。
4. **策略机死代码（中）**：`SecurityStrategy`（五类条件）+ `PermissionChecker` + `auto_lock_dashboard` 求值链完整，但零生产消费。要么接线要么登记移除，否则给人「策略引擎已存在」的错觉。
5. **Connect Token 无 TTL（中）**：永不过期、仅吊销；失窃 token 在 vault 解锁窗口内可无限期读密（限速 120 req/min 是唯一节流）。
6. **scope 拒绝无审计（中）**：有效 token 越权尝试（scope 外读取）返回同形 404 但不留痕，事后无法发现试探行为；`AuditAction::UnauthorizedAccess` 枚举存在却从未用于 Connect。
7. **SecurityLevel 纯标签（中）**：分级安全只有展示层；高等级条目与普通条目在同一把主密钥链下同等可解。
8. **Context 无一级类型（低）**：上下文事实散在各入口（hostname/origin/active_identity），策略判断无法统一引用。
9. **配置存而不读（低）**：`WorkspaceSettings.session_timeout_seconds`（models/workspace.rs:106,188）与 CLI `security.auto_lock_timeout`（cli/src/config/mod.rs:72）无消费者，实际生效的是 core 默认 300s。
10. **多 workspace 单 vault 假设（低）**：服务层处处取首行（service.rs:1835-1857）；overview 图的「多密码库/集合」出界判断（gap #1 未实现）与代码一致。

## 4. 目标架构 vs 当前实现的主要差异（图上已分开标注）

| 目标架构（图/文字） | 当前实现 |
|------|------|
| 统一授权层 `authorize(principal, resource, action, context)` | 不存在；core 门禁只做解锁+reauth，动词/资源裁决分散四入口 |
| Principal 子图作为架构顶梁柱 | 无 Principal 类型；入口直接持有 session/scope 调服务 |
| Server 子图含「事件 & 自动化 API (Connect)」 | Connect 是**本机**独立 crate `connect-server/`（127.0.0.1，桌面与 CLI 共用 re-export），不在 `server/`（可选云服务）里；`server/` 无 Connect 端点 |
| Connect Token 绑定 Principal + 分钟级短期 Token | Token 无 principal、永不过期（仅吊销） |
| 「每次访问记录完整授权决策链」 | 仅记录 token 维度审计（used/created/revoked + 认证失败节流）；scope 拒绝不落审计 |
| 解锁 = Argon2id 派生密钥解密 vault | 验证哈希是 Argon2id，**加密主密钥链是 PBKDF2-HMAC-SHA256 100k**；vault 不是加密容器，是 SQLite 密文列 + per-item key 包裹 |
| 审计日志 JSONL `audit.log` | SQLite `audit_logs` 表 |
| `core::services::{identity, credential, agent, wallet}` | `core/src/service.rs` 单体 `PersonaService`（8500+ 行）+ `core/src/models/` + `core/src/storage/` 各 repository；`core/src/services/` 目录不存在 |

## 5. 未解决的安全风险（实现缺口，非文档问题）

1. **Token 失窃窗口无界**：Connect token 永不过期；吊销是唯一终止手段，依赖人工察觉失窃。建议（下轮代码轮次）：TTL + last_used 告警。
2. **主 vault 解锁 = 全域解锁**：无 L4 独立密钥边界，Critical 级（钱包助记词）在普通解锁态下可被读出（仅 reauth/条目密码两道闸，均默认可关闭或可选）。建议：Critical 级独立密钥边界或默认强制 step-up。
3. **越权试探不可观测**：scope deny 不审计 + 404 同形，防御是隐式的、事后无证据。
4. **`PERSONA_NON_INTERACTIVE` / `PERSONA_MASTER_PASSWORD` 环境变量**：非交互模式下交互确认门全部失效、口令进进程环境（CI 场景便利与泄露面的权衡，需在威胁模型中显式登记）。
5. **审计远端复制尽力而为**：emitter 失败丢队列（本地 SQLite 仍在，但 server 侧审计视图可能缺页）。
6. **死策略机误导审计面**：SecurityStrategy/PermissionChecker 看似可用，实际无消费者——依赖它们做安全声明是错误的。

## 6. 验收标准对照（校正文档第 10 节）

- 「每个概念对应真实代码或标记 Planned/Unverified」：✅ 见第 2 节总表，Unverified 清零。
- 「所有敏感凭证访问路径都有明确的授权检查位置」：✅ 位置已全部定位（core 门禁 / scope / PolicyEnforcer / confirm），但「统一」未达成，属缺口 #2。
- 「自动化调用方不能仅凭凭证 ID 读取敏感数据」：✅ 基本成立——Connect 需 token + scope 双维匹配 + vault 解锁态，且敏感类型被排除法挡在 scope 外。
- 「SSH 私钥使用与导出有不同授权语义」：⚠️ 事实上分离（agent 只 sign、导出走 CLI confirm），但语义差异是结构性的而非被表达的规则（缺口 #3）。
