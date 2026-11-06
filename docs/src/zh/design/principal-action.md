# Principal 与 Action 授权体系设计

> English | **中文**

一句话定位：**principal 是"谁在发起动作"，action 是"想对这个资源做什么"**，所有敏感入口的判定收敛到
`core/src/authz.rs` 的单一裁决点 `authorize()`。本文只设计**补全**：动词词汇、主体绑定、裁决可观测性、
Agent 委托。

**边界（明确不做）**：不重做身份 CRUD。`PersonaService` 的身份/凭据创建、读取、删除、切换
（`core/src/service.rs` 中段数据面）保持不动；本文不新增身份模型、不迁移身份存储、不改动现有凭据加密与
解锁流程。

## 现状盘点：已有的部分

### 1. 统一裁决点 `core/src/authz.rs`

| 词汇   | 类型             | 取值                                                                                                                                                           |
| ------ | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 动作   | `AuthzAction`    | `Read` 读元数据/数据 · `Use` 库内使用（解密展示、签名断言） · `Export` 秘密本体离开库边界 · `Sign` 用密钥对外签名                                              |
| 主体   | `AuthzPrincipal` | `LocalSession` 本机已认证会话 · `ConnectToken { scope }` 浏览器自动化 token · `AgentKey { credential_id, identity_id }` SSH agent 持有的签名密钥               |
| 资源   | `AuthzResource`  | `Vault` vault 级 · `Identity { id }` 身份本体 · `Credential { identity_id, credential_type }` 某身份下的凭据 · `SshKey { credential_id }` agent 持有的签名密钥 |
| 上下文 | `AuthzContext`   | `origin` ∈ `local` / `connect` / `ssh-agent`，`interactive: bool`                                                                                              |
| 裁决   | `AuthzDecision`  | `Allowed` · `InteractionRequired { reason }` 策略允许但需调用边履约 · `Denied { reason }`                                                                      |

裁决语义（`core/src/authz.rs:143`）：

- **交互折叠 fail-closed**：`interactive == false` 时任何 `InteractionRequired` 直接折成拒绝，不产生
  "等一个永远不来的确认"。
- **分层不放松**：本模块只回答"该主体能否对该资源做该动作"；会话锁、自动锁、敏感重认证仍在
  `ensure_sensitive_operation_allowed`（`core/src/service.rs:432`）把守，token 吊销与逐请求查表仍在
  service 层，主机规则/频率/确认计数仍在 agent 的 `PolicyEnforcer`
  （`agents/ssh-agent/src/policy.rs:142`）。
- **动词折算**：`read`/`use` 可授予 Connect token；`export`/`sign` 不是 Connect 动词，对 token 一律拒绝
  （不是"忘了写"，是有意隔离）；agent 密钥唯一能力是签名自己的密钥；本地会话的导出永远要求显式确认。

### 2. 已收敛到 `authorize()` 的四个调用点

| 调用点                                         | principal                | 上下文    | 用途                   |
| ---------------------------------------------- | ------------------------ | --------- | ---------------------- |
| `core/src/service.rs:449` `ensure_authorized`  | `LocalSession`           | `LOCAL`   | 本地会话数据面统一门禁 |
| `core/src/service.rs:2463` `token_allows_read` | `ConnectToken { scope }` | `CONNECT` | Connect 端点资源过滤   |
| `cli/src/commands/export.rs:80` / `:106`       | `LocalSession`           | `LOCAL`   | 导出/敏感操作确认      |
| `agents/ssh-agent/src/lib.rs:291`              | `AgentKey { .. }`        | `AGENT`   | 签名授权               |

### 3. 机制层仍在裁决之外（有意保留）

- `core/src/auth/auto_lock_cached.rs` 的 `CachedAutoLockManager` 支持 `AutoLockPolicy`
  （`with_policy_repository`），策略表也已建（`core/src/storage/auto_lock_policy_repository.rs`）——但
  `PersonaService` 没有接它。
- `agents/ssh-agent/src/policy.rs:570` `SignatureDecision` 经 `to_authz`（`:588`）桥回 `AuthzDecision`，
  agent 的 TOML 策略与统一词汇之间已经有翻译层。

## 缺口

| #   | 缺口                                                                                                                                                                                                | 证据                                                |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| G1  | **写动词未拍板**。`AuthzAction` 只有读/用/导出/签名，没有 create/update/delete；模块注释明示"写路径未拍板"，管理面操作沿用敏感门禁而非数据面动词                                                    | `core/src/authz.rs` 模块注释；`service.rs:459` 注释 |
| G2  | **`ConnectTokenRow.principal` 是不透明字符串，`authorize` 从不消费**。字段建表即写（`connect_repository.rs:28,50,62,127`），取值是 `"browser-extension"` / `"cockpit"` 之类字面量，裁决只吃 `scope` | 迁移 015/019                                        |
| G3  | **32 处 `ensure_unlocked()` 只验证解锁，不表达资源与动作**。它们证明"有密钥"，但不进入统一裁决，也没有裁决记录                                                                                      | `grep ensure_unlocked()` 计数                       |
| G4  | **裁决不接审计**。`AuditAction` 34 个变体与 `AuthzAction` 4 个动词无映射；除 Connect scope 拒绝补了审计（`service.rs:2476` `audit_scope_denied`）外，放行类裁决零记录                               | —                                                   |
| G5  | **`ensure_authorized` 硬编码 `LocalSession` + `LOCAL`**。主体与上下文是参数位，但当前只有一个取值；三种 principal 的路径各自另写入口                                                                | `service.rs:449`                                    |
| G6  | **资源覆盖不全**。`AuthzResource` 没有 Attachment / Backup / Workspace / ConnectToken / Sync 等对象                                                                                                 | `core/src/authz.rs:75`                              |
| G7  | **`AutoLockPolicy` 表已建但管理器等未接线**。`PersonaService::new` 用 `AutoLockConfig::default()`（900s/3600s）硬编码，`WorkspaceSettings.session_timeout_seconds` 存了不读                         | `core/src/service.rs:124-126`                       |
| G8  | **死代码**：`core/src/auth/permissions.rs`（179 行）只在 `auth/mod.rs` 里被 `pub use`，全仓无调用方                                                                                                 | —                                                   |
| G9  | **术语冲突**：vault 里的 `Identity` 是**凭据分组**（资源），不是授权主体。文档与代码里两者都叫 identity/principal，容易把"分组切换"误读成"授权切换"                                                 | —                                                   |

## 设计原则

1. **单点裁决、机制分层**：策略判定只在 `authorize()`；状态性门禁（锁、重认证）与条件策略（主机规则、
   频率）留在各自机制层。不把它们塞进纯函数。
2. **可解释**：每次裁决都能回答"哪个 principal、对哪个资源、做了什么动作、为什么"，并能落到审计。
3. **fail-closed**：非交互上下文不接受"等确认"；任何异常路径折成拒绝而不是放行。
4. **principal 是一等公民**：AI Agent 不拿完整凭据，只拿有限动作。授权决策必须能按主体区分。
5. **词汇先于机制**：先补齐动词与资源词汇，再收敛调用点。不要给不存在的路径建模。

## 分阶段方案

### P0 清账（无行为变更）

1. 删除 `core/src/auth/permissions.rs` 及 `auth/mod.rs` 的重导出——全仓无调用方。
2. 把 `AutoLockPolicy` 接线进 `PersonaService`：`new` 时从 workspace 设置读
   `session_timeout_seconds` 构造 `AutoLockConfig`，而不是硬编码 default；同时决定 `is_unlocked()`
   的内存短窗与 `AutoLockManager` 的绝对上限如何分工（见
   [跨进程会话与授权中心](./session-center.md)）。
3. 审计增列 `principal_kind` + `decision_reason`，`ensure_authorized` 落裁决记录——让放行类动作也带
   裁决上下文，而不仅是 scope 拒绝。
4. 纠偏过时文档：`docs/src/concepts/principal.md` 仍声称"代码中没有 principals 表、没有按主体区分的
   授权规则"，与 `core/src/authz.rs` 现状不符。

**验收**：`cargo clippy --workspace --all-targets --all-features -- -D warnings` 与全量 `cargo test`
通过；新增一条断言"管理面动作带 principal_kind 审计记录"的回归测试。

### P1 动词与资源补全（写路径拍板）

1. `AuthzAction` 增 `Create` / `Update` / `Delete` 三个写动词（与 CRUD 一一对应，不用一个含糊的
   `Write`）。
2. **Connect token 仍只授予 read/use**：写动词对 token 一律拒绝，沿用 `connect_verb() -> None` 的现有
   模式。管理面动词只给 `LocalSession`。
3. `AuthzResource` 按需扩展 Attachment / Backup / Workspace / ConnectToken / Sync——**只加已存在门禁点
   的对象**，避免为不存在的路径建模。
4. `authorize_local` 补写动词：本地会话 create/update/delete 放行，状态门禁照旧由
   `ensure_sensitive_operation_allowed` 把守；管理面维持现状注释。

**验收**：新增裁决单测覆盖 `AuthzAction × AuthzPrincipal × AuthzResource` 的矩阵（含 token 拒绝写、
agent 拒绝非绑定密钥、非交互导出折叠为拒绝）；现有 4 个调用点行为不变。

### P2 本地会话收敛 + principal 绑定激活

1. **32 处 `ensure_unlocked()` 分批迁移到 `ensure_authorized(resource, action)`**：读路径 → 写路径 →
   管理面。本地会话全权，行为不变，但进入统一裁决与审计。
2. **激活 `ConnectTokenRow.principal`**：最小步是让该字段进入审计记录与 Connect API 展示（谁在用这个
   token），再决定是否升为裁决输入。建议存 machine-readable 标签而非自由文本。
3. **泛化 `ensure_authorized` 签名**：接收 `(principal, ctx)` 而非硬编码 `LocalSession`，使 token 与
   agent 路径共用同一入口。

**验收**：审计表可回答"某次签名由哪个 token/agent key 触发、裁决理由是什么"；无 `ensure_unlocked()`
裸调用残留在数据面。

### P3 Agent 委托（AI 不发完整 key）

1. `AgentKey` 已有 `credential_id` + `identity_id` 绑定，扩为带 **per-action 白名单**的
   `AgentGrant`，复用 `agents/ssh-agent/src/policy.rs` 的 TOML 形态（不引入策略 DSL）。
2. `InteractionRequired` 的履约接口统一（见
   [跨进程会话与授权中心](./session-center.md) 的确认原语合并）。
3. **验收场景**：AI agent 持受限 grant 能完成 `git fetch` / `git commit` / `git push`（签名放行），
   被拒：读其他 identity 的凭据、导出任何秘密、签非绑定密钥；非交互上下文下越权请求直接失败而不挂起。

## 非目标

- 不重做身份 CRUD，不新增身份模型，不迁移身份存储。
- 不引入策略 DSL / CEL；TOML 够用。
- 不改 SQLite 事务与并发模型。
- 不在 P1 给 Connect token 任何写能力。
- 不追求"策略覆盖所有对象"——只覆盖有真实门禁点的路径。

## 术语

- **principal（授权主体）** ≠ **Identity（凭据分组）**。后者是 vault 里的资源、被授权的对象；前者是
  发起动作的主体。切换身份是切资源，不是切主体。
- **动词**：`read` / `use` / `export` / `sign`（现状）+ `create` / `update` / `delete`（P1）。
- **`InteractionRequired`**：策略允许但需调用边履约（确认框、生物识别）；履约完成前视同未授权，
  非交互上下文直接折成拒绝。

## 关联

- [跨进程会话与授权中心](./session-center.md)：解锁状态共享、活动身份广播、确认原语合并与 Agent 受限
  RPC，是 P2/P3 的履约基础设施。
- [安全设计](./security.md)：分层边界与敏感操作授权约束。
- [原型外部审查与核验记录](https://github.com/cuihairu/persona/blob/main/docs/review/2026-10-24-persona-external-architecture-review.md)：R-P3 的来源与核验落档。
