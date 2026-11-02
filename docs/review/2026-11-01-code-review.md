# 代码深审报告（2026-11-01）

> **审计日期**: 2026-11-01（实际执行 2026-11-02 凌晨—上午，跨会话）
> **仓库**: cuihairu/persona @ main（基线 a8f0d37，本轮前）
> **范围**: 全仓 —— Rust 167,495 行（core/cli/server/connect-server/agents/ssh-agent/desktop/src-tauri/mobile/rust）+ TS/TSX 53,575 行（desktop/browser/website/mobile/harmony）
> **方法**: ① 安全静态扫描（硬编码密钥/SQL 注入/shell 注入/eval/反序列化/路径穿越/非对称加密误用）；② 隐藏 bug 猎捕（错误处理/竞态/越界/资源泄漏/off-by-one/并发）；③ 质量门（lint/类型检查/测试基线）；④ 发现按严重度排序，每条带 file:line 证据。
> **分级**: P0 = 可利用安全漏洞或数据丢失；P1 = 确定性 bug 或高危隐患；P2 = 需特定条件/防御纵深缺口；P3 = 质量/卫生。

---

## 一、质量门（维度③）—— 全绿

| 门                                              | 命令（CI 口径）                                                                                         | 结果                                          |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| Rust clippy（root workspace）                   | `cargo clippy --workspace --all-targets --all-features -- -D warnings`                                  | ✅ 绿（1m11s）                                |
| Rust clippy（desktop/src-tauri 独立 workspace） | `cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets --all-features -- -D warnings` | ✅ 绿（3m34s）                                |
| Rust fmt（root）                                | `cargo fmt --all -- --check`                                                                            | ✅ 绿                                         |
| Rust fmt（src-tauri）                           | `cargo fmt --manifest-path desktop/src-tauri/Cargo.toml -- --check`                                     | ✅ 绿                                         |
| Desktop 类型检查                                | `tsc --noEmit`                                                                                          | ✅ 绿                                         |
| Desktop lint                                    | `eslint . --max-warnings 0`                                                                             | ✅ 绿                                         |
| Browser 扩展 typecheck                          | `tsc --noEmit --project tsconfig.json`                                                                  | ✅ 绿                                         |
| Core 测试基线                                   | `cargo test -p persona-core --lib`                                                                      | ✅ 1168 passed / 0 failed（417s，系统高负载） |
| Desktop 测试基线                                | `jest --silent`                                                                                         | ✅ 56 suites / 737 passed / 0 failed          |

**说明**: 测试基线对比 acceptance-matrix 计数快照（2026-10-24，core 1198 / desktop 726）为正常代码增长（core --lib 口径 1168 与 1198 差 30 为 `tests/` 集成 + feature 门控差异）；无回归。

### 质量门异常（P3，非阻塞）

| ID    | 位置                                | 发现                                                                                                                                                                                                                                                                                                                                             |
| ----- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| M-005 | `website/package.json`（lint 脚本） | **死脚本**：`lint` 引用 `eslint`，但 (a) `devDependencies` 无 eslint；(b) 仓库无 `.eslintrc*` / `eslint.config.*`；(c) CI 从不跑它（`ci.yml:201` 仅 desktop lint；`conventional-commits.yml:8` 是 commit-lint）。`npx eslint` 会拉最新 ESLint 10（flat-config only）并报 "couldn't find eslint.config.\*"。误导维护者以为 website 有 lint 门禁。 |

---

## 二、安全静态扫描 + 隐藏 bug 猎捕发现（按严重度排序）

### Rust 面（core / cli / server / connect-server / agents / desktop/src-tauri / mobile）

**BUG-1/SEC-2（P1，可用性）— SSH agent 无界帧长度分配崩溃**

- `agents/ssh-agent/src/lib.rs:43-48`（修复后 :47-52 含上限检查）
- 证据（修复前）: `let pkt_len = BigEndian::read_u32(&len_buf) as usize; let mut pkt = vec![0u8; pkt_len];`
- 触发：任何能连上 agent socket 的对端发送 4 字节 `0xFF 0xFF 0xFF 0xFF`，`pkt_len = 4,294,967,295`，`vec![0u8; pkt_len]` 在 `read_exact` 之前即触发 ~4 GB 分配 → Rust 分配失败 abort，凭据代理崩溃（丢已载密钥、中断在途签名）。
- 暴露：socket 经 `UnixListener::bind`（transport.rs:89）**无 `chmod 0600`**，模式纯由 umask 决定（默认 022 → 0755 同用户可连；umask 000 → 跨用户）。`read_ssh_string`（lib.rs:484-493）有界检查，此顶层长度却无上限——违反代码库自身约定。
- **修复**：加 `MAX_AGENT_PKT_LEN = 16 MiB`，超限断开连接。**已修 + 回归测试**（`test_agent_drops_oversized_frame`，提交 cbdd24f）。

**SEC-1/BUG-5（P2，安全/防御纵深）— blob 附件 `storage_path` 路径穿越（读取/删除）**

- `core/src/storage/blob.rs:199,214`（retrieve_file）、`:251,265`（delete_file）
- 证据：`let file_path = self.storage_root.join(&attachment.storage_path);` 无包含性/canonicalize 检查。
- 触发：`Attachment` 派生 `Serialize/Deserialize`（attachment.rs:278 从 DB 行载入 `storage_path`）；经备份恢复/篡改 DB 注入 `storage_path = "../../.ssh/id_rsa"` 或绝对路径，`join` 逃逸 `storage_root` → 任意文件读/删。**当前全部写入方安全**（`store_file` 用 `file_name()`，travel.rs:539/555/904/936 已做同类逃逸检查）——故为防御纵深缺口，非现行可利用。
- **修复方向**：`retrieve_file`/`delete_file` 加与 travel.rs 一致的逃逸检查（`storage_path` 含 `..`/绝对路径则拒绝）。

**SEC-3（P2，可用性）— CLI 读 agent socket 无界长度分配**

- `cli/src/commands/ssh.rs:785`（镜像 :824）
- 证据：`let resp_len = BigEndian::read_u32(&len_buf) as usize; let mut resp = vec![0u8; resp_len];`
- 触发：恶意/损坏 agent 对端迫使 CLI 大分配（`:791` 的 `resp.len() < 5` 检查在分配之后）。影响短生命周期 CLI 进程崩溃，非常驻代理。
- **修复方向**：与 BUG-1 同法，加长度上限。

**BUG-2（P2，竞态）— agent socket bind TOCTOU + 无条件删除**

- `agents/ssh-agent/src/transport.rs:82-90`（`passkey_bridge.rs:177` 同模式，内网桥较低危）
- 证据：`if path.exists() { let _ = std::fs::remove_file(path); } let listener = tokio::net::UnixListener::bind(path)?;`
- 触发：(a) 无验证删除路径上现有文件——若为并发实例的活动 socket 或无关节点的文件，被静默摧毁；(b) `exists()` 与 `bind()` 之间可被抢占，bind 仍失败。daemon 失败路径亦从不清理 socket/pid 文件。
- **修复方向**：bind 失败而非先删（或先验证为陈旧 socket 再删）；daemon 退出清理。

**BUG-3（P3，健壮性）— PERSENC1 头部长度溢出**

- `core/src/backup/file_crypto.rs:113-116`
- 证据：`let enc_len = u64::from_le_bytes(...) as usize; ... data.get(cursor..cursor + enc_len)`；`cursor + enc_len` 在 64 位近 `u64::MAX` 溢出。
- 触发：构造 PERSENC1 备份头的 `enc_len` 近 `u64::MAX` → debug panic / release `cursor+len` 回绕为 `start > end`（`.get` 返回 None，安全报错）。`as usize` 截断 32 位。
- **修复方向**：改用 `checked_add` / `enc_len` 先对剩余长度界检查。

**BUG-4（P3，健壮性）— Web3 keystore scrypt 参数溢出**

- `core/src/crypto/wallet_encryption.rs:306`
- 证据：`let mem = 128u64 * u64::from(*r) * u64::from(*n);`——`r`/`n` 为不受信 keystore 字段（读为 u32，`n` 仅在 :306 之后校验为 2 的幂）。
- 触发：大 `n`/`r` 使 `128*r*n` 溢出 u64 → debug panic / release 回绕小值绕过 `SCRYPT_IMPORT_MAX_MEM`（256 MiB）上限（scrypt::Params 随后拒绝超大 r，release 端为报错非 DoS，但上限被绕过）。
- **修复方向**：`checked_mul` 链 + 先校验参数再算 mem。

**BUG-6（P3，健壮性）— stop_agent 陈旧 pidfile 误杀**

- `cli/src/commands/ssh.rs:1508-1512`
- 证据：`let pid_str = std::fs::read_to_string(&pid_file).unwrap_or_default(); ... stop_agent_pid(pid)?;`——`kill` 目标 PID 无 `/proc/<pid>/cmdline` 验证。
- 触发：陈旧 pidfile 的 PID 被无关进程复用 → `stop_agent` 向无辜进程发 SIGTERM。标准 pidfile 隐患；daemon 从不清理 pid/socket 文件致陈旧 pidfile 为常态。
- **修复方向**：kill 前验证 `/proc/<pid>/cmdline` 含 persona 标识（或按 socket 存活判断）。

### JS/TS 面（desktop / browser / website / mobile）

**JS-1（P2，安全）— 扩展 passkey 桥未绑定 `origin` 到页面真实源**

- `browser/chromium-extension/src/content.ts:1685-1695,1740-1790`
- 证据：`handlePasskeyPageMessage` 仅检查 `event.source === window` 与公开常量 `data.source === PAGE_MESSAGE_SOURCE`，随后把页面自带的 `payload.origin` **原样** 转发到 `persona_passkey_create` / `_list` / `_assert`（content.ts:1747/1767/1786）并直接显示在确认 dialog（`Origin: ${payload.origin}`）。
- 影响：恶意页面可 `postMessage` 伪造 origin（如 `https://bank.com`），令用户看到「bank.com」的 passkey 授权框，原生门控（`validate_origin_matches_rp_id`，cli/src/commands/bridge.rs:1338）校验的是**同一伪造源**，故扩展层 origin 绑定是缺失环节。缓解（保留 P2）：需页面内点击（user_gesture）+ 原生确认门控。同缺口在 Safari 共享 `webauthnHook.ts`/`content.ts`。
- **修复方向**：在 `handlePasskeyPageMessage` 内校验 `payload.origin === location.origin`（或解析后比对 hostname），不匹配则丢弃。

**JS-2（P2，安全）— NMH 配对 HMAC 密钥持久化到 `chrome.storage.local`**

- `browser/chromium-extension/src/nativeBridge.ts:576`（经 `storageSet` → `storage.local.set`，:376）
- 证据：`pairingKeyB64`（长期 HMAC 承载秘密，经 `buildAuth` nativeBridge.ts:442-456 认证每个桥接请求）与 `sessionId` 写入 `chrome.storage.local`（持久未加密落盘）。
- 影响：违反项目自身纪律（「token 与 group key 只进 chrome.storage.session」，cloudSync.ts:16）；具备文件读取能力的攻击者可用它冒充扩展调用原生桥。
- **修复方向**：pairing key 移入 `chrome.storage.session`（或经 `setAccessLevel` 限制），仅在会话有效。

**JS-3（P2，健壮性）— sync pull 成功路径 JSON 解析无 try/catch**

- `browser/chromium-extension/src/cloudSync.ts:396`
- 证据：`const body = (await resp.json()) as PullResponse;` 未包 try/catch（错误体 :389 有），恶意/故障 sync 服务器返回 200+非 JSON 时抛出。
- 影响：调用方（popup.ts:433）catch 后回退离线缓存，故当前影响有限；但 untrusted 输入路径解析纪律不一致，为后续调用者埋雷。
- **修复方向**：与 :389 对齐包 try/catch。

**JS-4（P2，显示竞态）— QuickSearch / QuickAccessPanel 防抖竞态**

- `desktop/src/components/QuickSearch.tsx:66-69`、`QuickAccessPanel.tsx:176-179`
- 证据：`clearTimeout(timer)` 无法取消已在途 `await`，查询变更时旧响应可能后到并覆盖新结果——浮层显示（Enter 可选中）已被取代的查询串匹配项。
- 影响：显示/选择竞态，无注入（渲染为 JSX 文本节点）。
- **修复方向**：请求序号（requestId）守卫，过期响应丢弃。

**JS-5（P2，功能竞态）— 身份快速切换凭据串号**

- `desktop/src/hooks/usePersonaService.ts:340-341,359`
- 证据：`setActiveIdentity` → `loadCredentialsForIdentity` 无请求序列化/取消；A 慢响应后到会 `setCredentials(response.data)` 无条件覆盖 B 的凭据。
- 影响：密码管理器在活动身份 B 下显示身份 A 的凭据列表——用户可能复制错误身份的密钥。
- **修复方向**：切换请求加序号守卫，或 AbortController 取消旧请求。

### 安全类零发现（已排除）

- **XSS/注入**：`dangerouslySetInnerHTML` 全仓 0 处；`innerHTML` 命中均为静态串或经 `escapeHtml()`（content.ts:1653-1657，`textContent`→`innerHTML` 正确转义）；`eval`/`new Function`/字符串 `setTimeout`/`document.write` 0 处。`a.href = URL.createObjectURL` 非攻击可控。
- **硬编码密钥**：源码无真实密钥；唯一 secret 形字面量 `--secret JBSWY3DPEHPK3PXP`（website/src/pages/docs.tsx:328）为 RFC-6238 文档测试向量。全仓无 `.env` 文件被跟踪。
- **消息来源校验**：无 `onMessageExternal`/`externally_connectable`，外部页面无法注入 SW；自动填充/TOTP 路径均绑定 `location.origin`（content.ts:984,1007,1043,2059,2078）；pending-save 仅 session 存储 + 2min TTL + 读一次。
- **Tauri/localStorage**：desktop 无 innerHTML；localStorage 仅存主题偏好与更新检查标记（updateCheck.ts:73-97），主密码/token/解密凭据从不落 localStorage。
- **WebCrypto 误用**：IV 取自密文前缀（12B，与 Rust nonce‖ct 一致），无静态 IV；桥接鉴权 HMAC-SHA256 规范输入；请求 ID 用 `crypto.randomUUID`/`getRandomValues`；`btoa` 仅作 base64 编解码。

---

## 三、自主发现（本轮主会话，非 agent）

| ID    | 位置                   | 发现                                                                                                                                                                                | 严重度 |
| ----- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| M-004 | `server-18996.log`     | 运行时启动日志（persona_server 启动 WARN/INFO，监听 0.0.0.0:3000）**被 git 跟踪**且未被 .gitignore 排除（`*.log` 无规则）——应为本地运行产物，不入仓。内容无敏感数据（仅启动横幅）。 | P3     |
| M-005 | `website/package.json` | 见上「质量门异常」：lint 死脚本。                                                                                                                                                   | P3     |
| M-006 | `Makefile` release-\*  | 已于 R3 删除（悬空目标调用不存在 `scripts/release.sh`）——本轮复验无残留引用（CI/docs/脚本均无 `release-*`），`scripts/release.sh` 不存在。                                          | 已修   |

---

## 四、汇总与待办

## 四、汇总与待办

### 发现计数（按严重度）

| 严重度   | 数量   | 已修             | 剩余                                       |
| -------- | ------ | ---------------- | ------------------------------------------ |
| P0       | 0      | —                | —                                          |
| P1       | 1      | 1（BUG-1/SEC-2） | 0                                          |
| P2       | 8      | 0                | 8（JS-1..JS-5、SEC-1/BUG-5、SEC-3、BUG-2） |
| P3       | 5      | 0                | 5（BUG-3、BUG-4、BUG-6、M-004、M-005）     |
| **合计** | **14** | **1**            | **13**                                     |

> 注：BUG-1 与 SEC-2 同源（ssh-agent 无界分配，双 agent 分别定 P1/P2，主会话复核定 **P1** 并当场修）；SEC-1 与 BUG-5 同源（blob.rs 路径穿越），合并计数。JS 面 5 项 + Rust 面 9 项（含同源合并）= 14 唯一发现。

### Commit 清单（本轮修复）

| Commit    | 内容                                                                                 |
| --------- | ------------------------------------------------------------------------------------ |
| `f7757c8` | docs: fix round 3 doc-consistency drift（审计前置任务，含 Makefile release-\* 删除） |
| `cbdd24f` | fix(ssh-agent): cap frame length to prevent OOM crash（BUG-1/P1 + 回归测试）         |

### 剩余待办（P2/P3，记入 todo.md）

- **P2**：JS-1（passkey origin 绑定）、JS-2（NMH pairing key 落盘）、JS-3（cloudSync 解析容错）、JS-4（QuickSearch 防抖竞态）、JS-5（身份切换凭据串号）、SEC-1/BUG-5（blob 路径穿越防御）、SEC-3（CLI resp_len 上限）、BUG-2（socket bind TOCTOU）。
- **P3**：BUG-3（PERSENC1 溢出）、BUG-4（scrypt 溢出）、BUG-6（pidfile 误杀）、M-004（server-18996.log 出仓）、M-005（website lint 死脚本）。
- 修复建议见各条 file:line 证据；全部为源码级，未动文档（source-wins）。

### 质量门结论

- 9/9 门禁通过（clippy 双 workspace `-D warnings`、fmt 双 workspace、desktop tsc/lint、ext typecheck、core 测试 1168、desktop jest 737）；唯一异常为 website `lint` 死脚本（M-005，P3）。
- 本报告落库后、推送前需复跑 `cargo test -p persona-ssh-agent`（已绿 9 passed）+ 报告相关 docs 无构建依赖（review 非 VitePress 页面）。
- 无版本/tag 发布；无 force push。

---

## 附：审计元数据

- 扫描方式：3 个并行 Explore agent（Rust 安全 / Rust 隐藏 bug / JS 前端）+ 主会话自主验证 + 质量门命令。
- 并发说明：审计期间本机 53 个并发 Claude/agent 会话共享 14 核，系统 swap 满载；clippy 全量通过，core 测试基线单包跑（逐包策略，规避全 workspace swap 挤死 exit 144）。
- 历史密钥扫描：`git log --all -S 'AKIA'` 命中均为测试 fixture（`AKIA-example`/`AKIA-leak`，1c85352），无真实密钥入史。
- 无版本/tag 发布，无 force push；本报告落库前不发布任何二进制。
