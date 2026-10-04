# Context-Aware Identity Suggestion — Design

状态：设计（阶段 0）。关联：[核心概念：上下文](src/concepts/context.md)、
[ROADMAP M7](ROADMAP.md#milestone-7--identity-runtime-positioning--concepts-feature-track-follows)、
`cli/src/commands/ssh.rs` 的 `--identity`（reserved for future use）。

## 1. 目标与定位

自动填充的下一步是**分身建议**：当用户进入一个目录、打开一个仓库、连上一台
主机时，Persona 应该知道「现在最可能是哪个分身」并把它排到最前——而不是让
用户在 6 个分身里手选。

铁律（与 `concepts/context.md` 一致）：

> **Context 只建议，不授权。** 建议结果永远不会绕过策略放行动作；未被确认的
> 建议不改变 `active_identity_id`，只改变「默认/首个候选」。

## 2. 概念落点

```
信号采集（客户端可观察的事实）
      │
      ▼
core: ContextService（纯函数，可单测）
      │  输入：Context { cwd, host, remote, origin, ... } + 映射表
      │  输出：候选分身份列表（identity, score, reason）— 排序、阈值、fallback
      ▼
消费方（CLI 提示 / 桥协议建议 / 桌面端 UI）
      │
      ▼
用户确认 → persona switch（唯一的身份变更路径，落审计）
```

- 决策必须在 **core**（ContextService），所有客户端共享同一套打分；
- 客户端只负责**采集信号**（cwd、host、origin），不自带推理；
- 身份变更仍走 `persona switch` 与 `active_identity_id` 指针——建议只是
  把「默认选哪个」这块替换掉。

## 3. 上下文信号清单

| 维度 | 信号 | 来源 | 可靠性 | v1 纳入? |
| --- | --- | --- | --- | --- |
| 终端 | `cwd` | `std::env::current_dir` | 脚本可伪造，但建议不授权所以无害 | ✅ |
| Git | `cwd` 上溯到 `.git`，读 `remote origin` → forge 与 owner/repo | shell 调用 git 或 `git2` | 高 | ✅ |
| 终端 | `hostname` | `gethostname` / `PERSONA_HOST` 覆盖 | 高（可通过环境变量改，见下） | ✅ |
| 终端 | 父进程链（shell 是否交互） | `/proc/<ppid>/comm` 启发式 | 中；交互 TTY 才提示，脚本不打扰 | ⚠️ 阶段 2 |
| SSH | Agent 请求的 host / key | 已有 agent 策略输入 | 高 | ⚠️ 阶段 3 |
| 浏览器 | page origin / 每站点默认 | 已有 autofillDefaults | 高 | ⚠️ 阶段 4 |
| 桌面 | 当前窗口/项目 | Tauri 侧 | 中 | ⚠️ 阶段 4 |
| 设备 | 机器角色（dev-pc / laptop / server） | 主机名约定或 `~/.persona/machine-profile` | 用户自声明 | ✅（可选） |

隐私边界：信号全部本地计算，永不外发；建议历史不进同步、不进服务器；
审计只记「用户确认了哪个建议」（复用已有 switch 审计），不记信号本身。

## 4. 建议算法 v1（确定性打分）

纯函数 `score(ctx) -> Vec<(identity, score, reason)>`，禁止随机/ML：

```
score = Σ (signal_match × signal_weight)
阈值：score ≥ MIN_SUGGEST (如 0.6) 的才进候选；候选中取第一
平局：活跃最近使用优先（SQLite 记录每次 switch 的 identity + ts）
无候选：fallback = 当前 active identity（行为与今日完全一致）
```

示例（静态映射表）：

```toml
# ~/.persona/context.toml（用户可维护；v1 也支持 persona context map 子命令）
[project "github.com/cuihairu/persona"]
identity = "OpenSource"

[host ".*-server$"]
identity = "Ops"
```

- `cwd=~/workspace/persona` → remote `github.com/cuihairu/persona` →
  命中 `[project ...]` → OpenSource（score 1.0，reason="仓库 github.com/cuihairu/persona"）；
- `cwd=~/workspace/client-a` → 无项目映射，host=`dev-pc` 无 `-server` 匹配，
  但最近 30 天在该目录 `persona switch` 过 41 次到 "Client-A" →
  学习候选 "Client-A"（score 0.7，reason="最近在此目录使用"）；
- 都不中 → active identity，行为不变。

### 4.1 历史学习（可选，默认关）

默认关；`persona context learn on` 后，每次 `persona switch` 把
`(identity, cwd_hash, host, ts)` 记入 SQLite 一张新表（本地，不进同步）。
建议时按「同组信号最近使用次数」产出一个学习候选。理由：
学习建立在用户已有行为上，且结果只影响默认值，风险低；但默认关
保持「不意外」原则。

## 5. 用户模型与数据

- 映射表：`~/.persona/context.toml`（全局）+ 可选 `$repo/.persona/context.toml`
  （仓库内，`.gitignore` 默认忽略——仓库共享的分身偏好属于团队决策，
  先不自动共享；仓库内**明文**映射只允许指向分身名，不涉及密钥材料）；
- 覆盖链（高优先在上）：环境变量 `PERSONA_CONTEXT_OVERRIDE=<identity>` >
  仓库内映射 > 全局映射 > 历史学习 > active identity；
- 身份名称引用与 `persona switch` 同源（同名校验失败则跳过该候选并告警）。

## 6. 集成点

- **CLI（v1 核心）**：`persona suggest`（人类可读）与 `persona suggest --json`
  （脚本友好）；`persona context map/get/unmap/learn on|off/status`；
- **交互提示（v1）**：`persona shell-hook` 生成 zsh/bash 片段，仅交互 TTY
  且 `PERSONA_NO_CONTEXT` 未设置时在 PS1 显示「⛵ OpenSource」候选，
  并提供 `persona use` 一键确认（= `persona switch` 的别名，落审计）
  ——注意 `persona switch` 语义不变，建议不自动执行；
- **桥协议（阶段 2）**：`get_suggestions` 请求可携带可选 `host`/`cwd` 字段；
  服务端（bridge、非 server）返回建议时合并 context 分身后排序
  ——向后兼容：缺省字段时行为与今日一致；
- **SSH（阶段 3）**：agent 策略已有的 host 维度接进 ContextService——
  访问 `*.company.com` 时建议 Work 分身；`--identity` 由 reserved 变为过滤器。

### 6.1 为什么不在桥协议首发

浏览器扩展是当前最高频入口但已有「每站点默认值 + active identity」的基础建议；
cwd/host 信号主要在终端场景价值最大。v1 锁 CLI，把 ContextService 在 core
测稳，再横向铺到浏览器/桌面。

## 7. 兼容性与安全

- 未配置任何映射、未开学习时，`suggest` 结果 ≡ 今日行为（active identity）；
- 建议**永不**独自触发 `switch`、永不改变任何策略评判（origin binding、
  user gesture、审批闸门全部不动）；
- 环境变量覆盖是「建议层」覆盖，不扩大任何授权（已有 `PERSONA_*` 首领一致）；
- 仓库内映射仅明文引用分身名，不写材料/密钥；同步不过（该表不进库）。

## 8. 阶段计划

| 阶段 | 交付 | 验收 |
| --- | --- | --- |
| 1 | core `ContextService` + `context.toml` 解析 + `persona suggest [--json]` + `context` 子命令 | 单测：映射命中/无命中/覆盖链/平局/伪造信号；无映射时输出=active |
| 2 | shell-hook、交互 TTY 提示、`persona use`、历史学习表（默认关） | 双 shell 冒烟；学习开关默认关；审计含 reason |
| 3 | SSH host 维度接入、`--identity` 生效 | `ssh -T git@github.com` 场景建议正确；host 策略联动不变 |
| 4 | 桥协议字段、桌面托盘候选、浏览器建议排序 | 全部入口一致候选；旧扩展（未知字段）不回归 |

## 9. 开放问题

1. 自动切换 opt-in：单候选且置信度高时是否允许直接切换？（倾向：v2 再议，
   v1 只提示）——review 的「一键切换」愿景我们拆成「建议 + 一键确认」落地；
2. 历史学习的表结构是否复用 sync 通道做跨设备一致？（倾向：tombstone 语义
   太重，v1 本地即可，跨设备用「每设备学习、全局映射表同步」方案后续评估）；
3. 建议结果是否进入桌面端「最近使用」排序？（不影响本设计，纯 UI 层）。

## 10. 失败模式与回退

- 映射表损坏 → 忽略该层并告警（不崩）；
- git 调取远程失败（离线/损坏仓库）→ 降级为无 Git 信号，其余信号照常；
- 打分全 0 → fallback active，行为不变——因此本特性的最坏情况是
  「与今天完全一样」，这是它敢进 CLI 默认路径的原因。