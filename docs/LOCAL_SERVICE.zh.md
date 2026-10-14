> [English](LOCAL_SERVICE.md) | **中文**

# Persona 客户端通信与存储模式

> **状态：目标架构（设计），而非当前现状。** 今天没有本地服务守护进程，
> 也没有 IPC 层：CLI 直接链接 core 库并直接打开 SQLite，桌面应用在进程内
> 持有 `Arc<Mutex<Option<PersonaService>>>`（Tauri invoke），浏览器桥在
> native-messaging host 进程里操作同一个库，移动端通过 `mobile/rust` 桥
> 进程内通信。确实存在两个专用 Unix socket（SSH agent、passkey 审批），
> 加上 `connect-server` 跑在 `127.0.0.1`。下面的目标/架构描述的是前进
> 方向；同一 caveat 在协议层面见 `CLIENT_COMMUNICATION_ARCHITECTURE.md`，
> 存储/同步的实际现状见 `STORAGE_AND_SYNC.md`。

本文档说明 Persona 的客户端（CLI、桌面/Tauri 应用、浏览器扩展、SSH agent，
以及未来的移动应用）如何与核心 vault 通信，以及用户如何在纯本地、自托管
或 Persona 托管的存储/同步选项之间选择。

## 目标

1. **单一事实源** —— 所有客户端经由同一个共享的 Rust core 库访问同一个
   本地 workspace（加密 SQLite + blob 存储）。
2. **一致的 IPC 边界** —— 通过一个轻量本地服务暴露 core，让每个客户端
   复用同一套 API 面。
3. **传输层同构** —— 每个桌面平台（含 Windows 10+）都使用 Unix Domain
   Socket，仅在必要时回退到命名管道。
4. **用户可控的同步** —— 本地 vault 在没有任何服务器的情况下保持可用，
   同时允许可选的同步适配器（自托管云或 Persona 服务器）。

## 架构概览

```
             +------------------------------+
             | Persona Local Service (Rust) |
             | - Unlock/session state       |
             | - Workspace DB + blobs       |
             | - Audit/log pipeline         |
             +---------------+--------------+
                             ^
          Unix socket / pipe | RPC (Protobuf/JSON-RPC/etc.)
                             |
  +-----------+   +----------+----------+   +-------------------+
  | CLI       |   | Desktop / Tauri    |   | SSH Agent process  |
  +-----------+   +--------------------+   +-------------------+
         ^                    ^                         ^
         | Native messaging   | WebExtension bridge     |
  +------+---------+          |                         |
  | Browser add-on |----------+-------------------------+
  +----------------+
```

- **本地服务**内嵌 Rust core crate，并暴露 RPC 命令（identity CRUD、
  credential 操作、SSH 签名、policy 查询等）。
- **CLI** 链接一个最薄 client SDK，每条命令都通过 Unix socket 连接（避免
  直接访问数据库）。
- **桌面应用**要么经 Tauri 命令链接 core，更推荐的做法是复用同一个 IPC
  client，以保证能力对齐。
- **SSH agent** 是同一服务的薄封装：它在一个 socket 上接收 SSH 协议请求，
  并通过 RPC 通道转发签名请求。
- **浏览器扩展**经由 Native Messaging host 通信，host 把请求代理到本地
  服务，因此机密不会落在浏览器存储里。

## IPC 传输策略

- **主传输：Unix Domain Socket**
  - macOS/Linux：标准路径在 `~/Library/Application Support/Persona/run/`
    或 `/run/user/<uid>/persona/` 下。
  - Windows 10 build 17063+：Windows 现已支持 `AF_UNIX`；我们使用
    `\\?\pipe\persona-<uid>.sock` 风格路径以保持语义一致。
- **回退：命名管道（Windows）**
  - 仅在旧版 Windows（17063 之前）或禁止 `AF_UNIX` 的企业环境需要。
  - 同一套协议消息原样跑在管道上，无需改动。
- **安全**
  - socket 目录权限锁定到当前用户。
  - 高风险 RPC（例如揭示凭据、SSH 签名）即使在 socket 连接建立之后仍
    可触发生物识别或系统密码提示。
  - 客户端可出示由服务签发的短期访问令牌，防止不受信任的本地进程静默
    调用 RPC。

## 存储与同步模式

| 模式                          | 说明                                                                                                                                                                | 备注                                             |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| 纯本地（Local-only）          | 所有数据都落在 `~/.persona` 下（或平台对应路径）。无任何网络调用。                                                                                                  | 最适合物理隔离场景。备份由手动或 OS 级快照处理。 |
| 自托管云（Self-hosted cloud） | **已规划，未实现。** 同步适配器将把加密 blob 推/拉到 iCloud Drive、Dropbox、WebDAV 或 S3；今天只能通过自行导出并上传密文获得云端备份托管（`STORAGE_AND_SYNC.md`）。 | 云侧只见密文；加密密钥永不离开设备。             |
| Persona 服务器（可选）        | 连接到 Persona 托管或自托管服务器，用于同步、审批与自动化工作流。同步目前是手动触发（「立即同步」执行 pull → apply → push），非实时。                               | 仍是零知识：载荷在上传前于本地完成信封加密。     |

### 同步适配器设计

- 本地服务把变更事件（例如条目创建、附件更新）放入队列。
- 同步 worker（插件）订阅事件，并按所选模式处理上传/下载。
- 切换模式只替换适配器；其余技术栈（CLI/桌面/浏览器）保持不变。
- 冲突解决在 core 库内进行：多版本并发控制加上业务特定的合并规则。

## 实现路线图

1. **抽出服务 crate** —— 把 `core` 包装成暴露 RPC handler 的守护进程。
2. **Client SDK** —— 提供一个薄 Rust crate（以及 Native Messaging host），
   供 CLI/桌面/浏览器/agent 调用服务。
3. **协议规范** —— 文档化消息 schema、版本协商与安全要求。
4. **传输层铺开** —— 为 macOS/Linux/Windows 交付 Unix socket 支持，并附
   可选的命名管道回退。
5. **同步适配器** —— 实现 `local`、`filesystem-cloud`（例如 iCloud）与
   `persona-server` 适配器，各使用同一套加密载荷格式。
6. **文档与示例** —— 更新 README/docs，让贡献者据此架构接入，便于新增
   客户端或自动化。

## 参考

- [`TODO.md`](../TODO.md) – 本文档及相关实现的跟踪任务。
- [`docs/MONOREPO.md`](./MONOREPO.md) – 该服务将落位的整体仓库布局（可能在
  `core` + 一个新的 `service` crate 下）。
- [`docs/REMOTE_AUTH.md`](./REMOTE_AUTH.md) – 架在该通信模型之上的远程认证
  流的补充细节。
