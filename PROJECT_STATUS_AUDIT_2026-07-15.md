# Persona 项目状态审计（2026-07-15）

## 结论摘要

当前工作树不是一个可继续正常开发的主线基线。

- 当前 `HEAD` 为 `11a792a2712faac9fc27197ed54c5abc99365a82`
- 其父提交为 `ffc5cd2584a933ec41f623a6538bc54dbfeaca3e`
- 本次 `HEAD` 相对父提交的差异为：`5864 files changed, 157 insertions(+), 761646 deletions(-)`
- 提交标题是 `Fix CLI SSH agent status and config serialization`
- 但实际效果是删除了几乎整个 monorepo，仅保留：
  - `cli/src/commands/init.rs`
  - `cli/src/commands/ssh.rs`
  - `.spec-workflow/` 模板目录

这说明当前仓库状态与提交说明严重不一致。若直接基于当前工作树继续推进，会导致对项目进度、功能现状、测试状态的判断全部失真。

## 真实项目基线

基于父提交 `ffc5cd2584a933ec41f623a6538bc54dbfeaca3e`，项目真实基线是完整 monorepo，而不是当前残片。

父提交包含以下主要模块：

- `core/` Rust 核心库
- `cli/` 命令行工具
- `agents/ssh-agent/` SSH Agent
- `desktop/` Tauri + React 桌面端
- `browser/` 浏览器扩展与 wasm 组件
- `server/` 可选服务端
- `docs/` 文档体系
- `website/` 官网
- 根级 `Cargo.toml`、`Cargo.lock`、`README.md`、`TODO.md`

因此，项目“整体进度”应以父提交为准，而不是以当前 `HEAD` 文件数量为准。

## 进度基线

基于父提交中的 [`TODO.md`](./TODO.md) 内容统计：

- 已完成：52 项
- 未完成：21 项
- 总计：73 项
- 按条目计的表面完成度约为 `71.2%`

按模块拆分：

| 模块 | 已完成 | 未完成 | 总计 | 观察 |
| --- | ---: | ---: | ---: | --- |
| Now (current sprint) | 7 | 0 | 7 | 当前冲刺项已完成 |
| Monorepo & Tooling | 7 | 0 | 7 | 基础工程完成 |
| Security & Auth | 5 | 0 | 5 | 当前列出的安全认证项已完成 |
| Storage & Data | 4 | 0 | 4 | 该阶段目标已完成 |
| CLI | 8 | 0 | 8 | CLI 主流程已完成 |
| SSH Agent (developer focus) | 15 | 2 | 17 | 最成熟的子系统之一，剩余主要是实机验证 |
| Browser & Autofill (future) | 4 | 1 | 5 | 骨架和主要流程已落地 |
| Quality & Security | 2 | 2 | 4 | 仍缺威胁建模与可重现构建 |
| Server & Sync (optional) | 0 | 5 | 5 | 基本未启动 |
| Wallet Material (deferred / experimental) | 0 | 11 | 11 | 明确延后 |

## 产品边界与优先级判断

根据父提交中的产品边界文档，主线目标很清晰：

- 本地优先的 identity-material manager
- 核心围绕身份切换、凭据管理、浏览器辅助、CLI、SSH 工作流
- 钱包能力概念上在边界内，但路线优先级被明确延后
- Server/Sync 是可选项，不是当前主线完成度的核心判据

这意味着项目主线并不是“从零开始”，而是已经完成了相当多的核心能力，尤其是：

- CLI 主工作流
- 工作区与迁移
- 导入导出
- 审计日志
- SSH Agent 主链路
- 浏览器扩展骨架与桥接协议

## 当前 HEAD 的已确认问题

以下问题基于当前工作树中的残留源码确认，不是推测。

### 1. 仓库被异常裁剪

当前 `HEAD` 删除了根级构建与文档文件以及几乎所有源码，导致：

- 无法从当前工作树判断真实完成度
- 无法在当前工作树正常构建 workspace
- 无法验证之前已完成的跨模块能力
- 当前分支对外表现为“项目几乎不存在”

这是当前最严重的问题。

### 2. `ssh generate` 生成逻辑发生功能回退

在 [cli/src/commands/ssh.rs](/home/cui/workspaces/persona/cli/src/commands/ssh.rs:191)：

```rust
let signing_key = SigningKey::from_bytes(&[0u8; 32]);
```

这意味着当前代码使用固定全零种子生成 ed25519 私钥，不是随机密钥。

影响：

- 每次生成结果相同
- SSH 私钥完全可预测
- 功能错误且存在严重安全风险

这不是未完成占位那么简单，而是不可接受的错误实现。

### 3. `ssh list-all` 行为已损坏

在 [cli/src/commands/ssh.rs](/home/cui/workspaces/persona/cli/src/commands/ssh.rs:130)：

```rust
SshSubcommand::ListAll => list_keys("", config).await,
```

而 `list_keys` 会通过身份名解析身份：

- [cli/src/commands/ssh.rs](/home/cui/workspaces/persona/cli/src/commands/ssh.rs:165)
- [cli/src/commands/ssh.rs](/home/cui/workspaces/persona/cli/src/commands/ssh.rs:230)

空字符串不会对应有效身份，因此这里等价于把原本的跨身份枚举能力回退成失效实现。

### 4. 非交互模式支持被回退

在 [cli/src/commands/ssh.rs](/home/cui/workspaces/persona/cli/src/commands/ssh.rs:153)：

当前 `ensure_service` 强制走交互式密码输入，不再读取 `PERSONA_MASTER_PASSWORD`。

影响：

- 破坏原有 CI/自动化场景
- 与项目已有 “Non-interactive CI mode” 方向冲突

### 5. Agent 启动链路被简化并丢失健壮性

在 [cli/src/commands/ssh.rs](/home/cui/workspaces/persona/cli/src/commands/ssh.rs:289) 之后可以看到：

- 不再解析 agent 二进制路径
- 不再创建和管理专用 state/socket 路径
- 不再处理 agent 提前退出的详细错误
- 不再支持更完整的 socket 导出格式

这属于可用性和可诊断性回退。

### 6. `stop-agent` 平台兼容性回退

在 [cli/src/commands/ssh.rs](/home/cui/workspaces/persona/cli/src/commands/ssh.rs:556)：

当前直接调用 `kill`，丢失了之前的 Windows 停止逻辑。

影响：

- 与父提交中“Windows named pipe support / cross-platform transport”能力不一致
- 当前文件虽然仍含 `#[cfg(windows)]` 的状态查询逻辑，但停止逻辑已退化为 Unix-only 假设

### 7. `init` 配置序列化修复是本次提交里少数真实有效的改动

在 [cli/src/commands/init.rs](/home/cui/workspaces/persona/cli/src/commands/init.rs:180)：

- 当前版本改为通过 `CliConfig::default()` 生成配置并用 `toml::to_string_pretty` 序列化

这部分符合提交标题中的 “config serialization”，是合理修复。

但它不能抵消整个提交删除仓库与回退 `ssh` 行为的问题。

## 对“当前进度”的准确判断

如果以父提交为基线，项目状态应判断为：

- 主线产品方向明确
- 核心架构完整
- CLI 和 SSH 相关能力完成度高
- 浏览器端已有骨架与桥接
- 桌面端存在原型但未进入完善阶段
- Server/Sync 与 Wallet 仍属后续工作

如果以当前 `HEAD` 为基线，项目状态则会被误判成：

- 几乎没有可构建系统
- 只剩两个 CLI 命令文件
- 无法证明任何已完成功能仍然存在

因此，当前最优先任务不是继续在这个 `HEAD` 上“追加功能”，而是先恢复正确开发基线。

## 建议的推进顺序

### P0：恢复正确仓库基线

首选目标：

- 以 `ffc5cd2584a933ec41f623a6538bc54dbfeaca3e` 作为开发基线
- 重新审视 `11a792a2` 中真正需要保留的最小修复

最可能值得保留的内容只有：

- `init.rs` 中的配置序列化修复
- `ssh.rs` 中极少数与 agent status 解析相关的局部修复

但这些修复必须在完整 monorepo 上重新摘取，而不是继续依附当前异常提交。

### P1：在完整基线上重做 `ssh.rs` 差异审查

重点检查：

- 保留哪些是真修复
- 去掉哪些是功能回退

当前已确认必须回滚或重做的点：

- 固定零种子密钥生成
- `list-all` 退化实现
- 非交互模式移除
- 启动和停止 agent 的跨平台退化

### P2：恢复构建与验证链

在完整基线上应优先恢复并执行：

- `cargo build --workspace`
- `cargo test --workspace`
- SSH agent 相关测试
- CLI 关键命令的最小回归验证

### P3：再继续主线开发

恢复后建议优先推进仍未完成但最接近主线价值的项：

1. SSH agent 实机 E2E 验证
2. Windows 专项测试与收尾
3. Desktop 数据接线
4. Threat model / security review
5. Reproducible builds

这符合 KISS/YAGNI：

- 先修正基线，不做额外重构
- 先补真实缺口，不扩新范围
- 避免在错误快照上继续叠加复杂度

## 本次审计结论

项目并没有“停在很早期”。

真实情况是：

- 上一完整提交已经是一个完成度较高的 monorepo
- 当前 `HEAD` 是一次异常的大规模删除提交
- 该提交还夹带了 `ssh` 子系统的若干明确功能回退

所以“继续推进”的正确含义不是继续在当前残片上写功能，而是：

- 先恢复完整基线
- 再按主线优先级继续开发

否则后续所有开发、测试和进度判断都会建立在错误事实之上。
