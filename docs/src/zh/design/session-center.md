# 跨进程会话与授权中心

> English | **中文**

一句话定位：Persona 的**解锁状态、活动身份、权限撤销、用户确认**四件事目前没有任何跨进程协调机制
——每个进程各自持一份 `PersonaService`，靠同一个 SQLite 文件"碰巧一致"。本文先给现状调研，再给
分阶段方案。

**边界（明确不做）**：不引入新的网络监听面；不改 SQLite 的事务与并发模型；不把架构改成
C/S。桌面已内嵌 Connect 监听（`127.0.0.1`）的事实不动。

## 现状调研

### 1. 解锁状态：每进程内存字段，没有共享存放处

"已解锁"的真值就是 `PersonaService` 上的三个内存字段，判定是一个纯内存谓词
（`core/src/service.rs:187`）：

```rust
pub fn is_unlocked(&self) -> bool {
    if let (Some(_), Some(last)) = (&self.master_encryption, *self.last_activity.lock().unwrap()) {
        return last.elapsed() < self.auto_lock_timeout;
    }
    false
}
```

注意它同时是自动锁判定——空闲超过 `auto_lock_timeout`（默认 300s，`core/src/service.rs:138`）
就返回 `false`。

- **没有持久化解锁标记**：全仓没有"已解锁"的 SQLite 行、设置键或文件；`user_auth` 表只存密码哈希、
  salt 与失败计数。
- **没有 watcher**：`core/src/storage/database.rs` 没有 `busy_timeout` / `WAL` / 任何 PRAGMA；
  `core/` 与 `cli/` 里没有 `notify` / `inotify` / 文件监听（唯一的 `Notify` 是 `tokio::sync::Notify`，
  在审计 Emitter 内部）。
- **每个进程各自解锁**：桌面（`desktop/src-tauri/src/lib.rs` 的 `AppState.service` 槽位）、
  CLI（`PERSONA_MASTER_PASSWORD`）、Bridge NMH（`cli/src/commands/bridge.rs` 显式建模为
  "没有注入环境变量就是锁定态"）、内嵌 SSH agent（`agents/ssh-agent/src/lib.rs` 自己 new 一份
  `PersonaService` 并自己 authenticate）、独立 `persona connect serve`——五处入口，五份解锁态，
  互不可见。

### 2. 自动锁跑了两遍，互不相识

| 机制                       | 位置                               | 默认值                                       |
| -------------------------- | ---------------------------------- | -------------------------------------------- |
| `is_unlocked()` 的内存短窗 | `core/src/service.rs:138,187`      | 300s 空闲                                    |
| `AutoLockManager`          | `core/src/auth/session.rs:186-196` | 非活跃 900s / 绝对上限 3600s / 敏感操作 300s |

`PersonaService::new` 无条件用 `AutoLockConfig::default()` 构造管理器
（`core/src/service.rs:119`），而 `WorkspaceSettings.session_timeout_seconds`
（`core/src/models/workspace.rs:106`，默认 3600）存了却不喂进去。两套计时器各自只观察自己进程里的
用户/会话集合——一个进程自动锁不会锁另一个进程。

`lock()` 本身也不完整（`core/src/service.rs:176-184`）：清了 `master_encryption`、`last_activity`、
`current_user`，但清 `current_session_id` 的那行被注释掉（注释写的是"这需要 async"），也没有停掉
自动锁监控；桌面包了一层才补上同步捕获的 detach。

### 3. 活动身份：唯一的持久层，但零广播

持久化只有一处：`workspaces.active_identity_id`
（`core/src/models/workspace.rs:18`；读写 `core/src/storage/repository.rs:585` 起的 `workspaces`
表 SQL）。它是 **per-workspace**（按 vault 文件路径分），没有全局活动身份概念。

- **写入方只有桌面**：`set_active_identity` / `clear_active_identity`
  （`desktop/src-tauri/src/commands.rs`）先查 `service.is_unlocked()`，然后**完全绕过
  `PersonaService`**，自己开 DB、构造 `WorkspaceRepository`、调 `repo.update()`。于是审计、
  同步捕获（`attach_sync_capture`）、敏感操作门禁全部被跳过。
- **不广播**：全仓 `emit_all` 零命中，所有 Tauri 事件都是桌面窗口作用域；没有任何
  unlock / lock / identity switch / settings change 事件被发出。
- **Connect 数据面从不读活动身份**：`connect-server/src/lib.rs` 里 `active_identity` 零命中，
  身份列表按 token scope 过滤，不按活动身份。所以桌面切身份对自动化消费者毫无影响。
- CLI 从不设置活动身份，只在删除身份时防御性清除。

### 4. 现有跨进程通道盘点

| 通道                                | 方向                         | 内容                                                                       | 备注                                                |
| ----------------------------------- | ---------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------- |
| Tauri 事件 ×5                       | 桌面进程 → 前端窗口          | `persona://auto-lock`、`ssh-approval`、`passkey-approval`、quick-access ×2 | 窗口作用域，无 `emit_all`                           |
| Unix socket `ssh-agent.sock`        | OpenSSH → agent              | OpenSSH agent 协议                                                         | 已有                                                |
| Unix socket `passkey-approval.sock` | Bridge CLI → 桌面            | 一行 JSON 请求 / 一行应答，`0o600`                                         | **唯一真正跨进程的请求-应答通道**                   |
| Connect HTTP `127.0.0.1`            | 浏览器/自动化 → 桌面内嵌监听 | 5 个 REST 路由                                                             | 无 SSE / 无 WebSocket / 无推送                      |
| Native Messaging（stdin/stdout）    | 浏览器扩展 → 本地 CLI        | Chrome 4 字节长度前缀 + UTF-8 JSON                                         | 配对会话持久化在 `~/.persona/bridge`                |
| `POST /api/v1/events`               | 客户端 → 远端 server         | 审计批次，**单向**                                                         | 无任何回程通道；`server/` 与 `core/` 里零 WebSocket |
| SQLite 文件                         | 所有进程                     | 事务级一致性                                                               | **事实上的唯一跨进程总线，但没有任何人监听它**      |

关键性质：唯一能靠 SQLite 达成跨进程一致的只有 Connect token 鉴权——因为
`connect_authenticate` 每请求查表、无缓存窗口，撤销写入后立即对所有进程生效。解锁态与活动身份
是**每进程内存缓存**，不重读就不一致。

### 5. 权限撤销：只覆盖一类凭据

`revoke_connect_token`（`core/src/service.rs:2374`）是唯一的撤销 API：锁门禁 +
`connect_gate`，即**要求本进程处于解锁态**才能撤销。它每请求查表，所以跨进程即时生效。

其余全部没有撤销也没有续期（全仓无 `renew` API，命中的都是词表文件里的单词）：Bridge 配对会话、
NMH session id、账号 bearer token、同步设备身份、SSH key 策略、passkey。

### 6. 用户确认：两套重复的 oneshot 注册表

`state.ssh_approvals` 与 `state.passkey_approvals`
（`desktop/src-tauri/src/types.rs`）是两个结构相同的
`Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>`，各自复制一遍同一套模式：

1. 铸造 `request_id`（`ssh-{n}` / `passkey-{n}`）→ 插入 map；
2. emit 到前端（emit 失败则删条目并拒绝，不静默放行）；
3. 带 120s 超时 await 接收端（`desktop/src-tauri/src/approval.rs` 的 `APPROVAL_TIMEOUT`）；
4. 超时 / 应答端被 drop / 未知 id → 一律拒签；`resolve_from_map` 先删后发，保证 exactly-once。

**关键限制**：应答只能来自桌面 webview（两个 Tauri 命令 `ssh_approval_respond` /
`passkey_approval_respond`）。没有 socket、没有 HTTP 路由、没有文件应答路径。而且 SSH agent 的
`ApprovalHandler` 只有桌面 GUI、`TtyApprovalHandler`、`DenyAllApprovalHandler` 三种实现——
由 CLI 启动的 agent 收到签名请求时只能弹终端提示或拒签，**永远到不了桌面 GUI**（passkey 之所以能到
桌面，只是因为它恰好用了桌面自己拥有的 socket）。

## 核心问题

15 条细节收敛成 5 个：

| #   | 问题                        | 后果                                                                                              |
| --- | --------------------------- | ------------------------------------------------------------------------------------------------- |
| C1  | 解锁状态没有共享存放处      | 两个 host 对同一个 vault 可各自解锁、互不知情；CLI 侧的"注入环境变量才解锁"是把架构限制伪装成配置 |
| C2  | 锁定不完整 + 自动锁两套计时 | `lock()` 漏清 session id 与监控；同一行为在不同进程有不同超时                                     |
| C3  | 变更零广播                  | 活动身份/锁状态对其他进程零可见性；Connect 数据面连活动身份都不读                                 |
| C4  | 写路径绕过服务层            | 切身份跳过审计、同步捕获、敏感门禁——而这正是身份上下文可信性的一部分                              |
| C5  | 确认与撤销面窄              | 确认只能回桌面 webview；撤销仅一类凭据，且要求本地已解锁（锁着的时候撤不了）                      |

## 方案取向：先无 daemon

`docs/LOCAL_SERVICE.md` 记录过历史决定：不设本地守护进程，CLI 直接链接 core 库、Bridge 进程内接入。
本方案沿用该取向——**不新增进程**，把状态外置到已有的 SQLite，并复用现有的"每请求重读"模式
（Connect token 已经证明这条路径在工作）。只有当 Phase 1 证明不够时，才进入 Phase 2 讨论 hub 模式。

## Phase 1：无新进程，状态外置

1. **会话表 + 版本列**。新增 `sessions` 表（`session_id`、`host`、`identity_id`、`unlock_epoch`、
   `updated_at`）。解锁/锁定/切身份都写一行并推进 `unlock_epoch`；所有需要跨进程一致的读路径
   **每次按版本重读**，不缓存。这一步复用 Connect token 的"无缓存窗口"模式，风险最低。
2. **补全 `lock()`**。清 `current_session_id`、停自动锁监控、detach 同步捕获都收进
   `PersonaService::lock()`，不再靠桌面包装层补偿。
3. **自动锁统一**。`PersonaService::new` 从 `WorkspaceSettings.session_timeout_seconds` 构造
   `AutoLockConfig`；同时明确分工：`is_unlocked()` 的内存短窗负责本进程快速判定，
   `AutoLockManager` 的绝对上限负责跨进程会话有效性。与
   [Principal 与 Action 授权体系设计](./principal-action.md) 的 P0 第 2 条是同一件事。
4. **活动身份收回服务层**。`switch_identity` / `clear_active_identity` 改由 `PersonaService` 提供
   （走审计 + 同步捕获 + 敏感门禁），桌面 handler 只调 service，不再自己开 DB 写表。同时决定
   Connect 数据面是否跟随活动身份——目前它明确不跟随，如果保持现状需要写进设计而非靠"忘了读"。
5. **确认原语合并**。两个 map 合成一个 `ApprovalRegistry` + 请求类型枚举，保留现有的
   exactly-once 与 fail-closed 语义；并把 passkey 的 socket 模式推广给 SSH agent——新增一个
   socket handler，让非桌面启动的 agent 也能把签名请求弹到桌面，而不是只能 TTY 或拒签。

**验收**：见下一节 A1–A5。

## Phase 2（可选）：桌面作为 hub 的受限 RPC

如果 Phase 1 跑稳后出现"多个客户端同时需要密钥材料"的真实需求，再评估：桌面进程持有密钥，
CLI / Bridge 通过已有的 Unix socket 模式向桌面请求**受限动作**（read / use / sign 带 grant），
密钥材料不复制到第二份解锁态。这条路径与
[Principal 与 Action 授权体系设计](./principal-action.md) 的 P3（Agent 委托）汇合：socket 请求携带
grant，由 `authz::authorize` 裁决。

**前提条件**：Phase 1 的版本重读跑稳；且确认"多客户端同时要密钥材料"不是假需求。

## 明确不做

- 不引入新 daemon 进程（Phase 2 仍只是复用桌面进程 + 已有 socket 模式，不是新进程）。
- 不新增网络监听面（除已有的 Connect `127.0.0.1`）。
- 不改 SQLite 并发模型、不引入 C/S 架构。
- 不让 CLI / Bridge 持有第二份密钥材料——避免出现第二套解锁态。
- 不用 SQLite 文件监听替代重读：文件监听不可靠（通知丢失、跨文件系统行为不一致），每请求重读
  已经足够便宜。

## 验收场景

| #   | 场景                                          | 层       | 当前       | 验收条款                                                                                            |
| --- | --------------------------------------------- | -------- | ---------- | --------------------------------------------------------------------------------------------------- |
| A1  | 桌面解锁后，CLI 立即感知解锁态                | 模拟测试 | 不可达     | 桌面解锁推进 `unlock_epoch` 后，CLI 的下一个请求成功，无需重新输入主密码                            |
| A2  | 桌面锁后，CLI / agent / Bridge 下一个请求失败 | 模拟测试 | 不可达     | 锁后所有非桌面进程返回 `vault_locked`，桌面内 connect 监听继续返回 503（已有）                      |
| A3  | 桌面切身份后，Connect 端行为明确              | 模拟测试 | 未定义     | 要么返回新活动身份，要么文档化"Connect 不跟随活动身份"——不允许无声不一致                            |
| A4  | 撤销 Connect token 跨进程即时生效             | 模拟测试 | **已覆盖** | 保留为回归项；新增"锁定时不能撤销"的行为显式化或修正                                                |
| A5  | CLI 启动的 SSH agent 能弹到桌面确认           | 真实交互 | 不可达     | 由 `persona ssh agent` 启动、桌面解锁、签名请求弹出桌面审批框并可用 Allow/Deny 应答；超时 120s 拒绝 |

这些场景与 [验收场景清单与跨平台能力矩阵](/development/acceptance-matrix) 对齐编号。

## 关联

- [Principal 与 Action 授权体系设计](./principal-action.md)：动词词汇、裁决可观测性、Agent 委托；
  本文件是它的履约基础设施。
- [安全设计](./security.md)
- [跨进程能力现状](https://github.com/cuihairu/persona/blob/main/docs/review/2026-10-24-persona-external-architecture-review.md)：R-P4 的来源与核验记录。
