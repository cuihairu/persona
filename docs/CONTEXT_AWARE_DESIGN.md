# Context-Aware Identity Suggestion — Design

> [English](CONTEXT_AWARE_DESIGN.md) | [中文](CONTEXT_AWARE_DESIGN.zh.md)

Status: **Stages 1+2 implemented** (2026-10-12: core `ContextService` + `context.toml`
parsing + `persona suggest [--json]` + `persona context map/get/unmap/status`;
2026-10-13, stage 2: `persona shell-hook` (bash/zsh snippet, PS1 prefix ⛵ candidate) +
`persona use` (= an alias for switch; the audit entry carries the reason when the top suggestion is confirmed) + history learning
(migration 020 `context_learn`/`context_settings`, off by default,
`persona context learn on|off|status|clear`, suggestion weight 0.7, 30-day window);
2026-10-13, stage 3: `persona ssh run --host` prints a suggestion line using the target host as its only signal
(stderr; it suggests without authorizing), and `--identity` moves from reserved to an agent key filter
(the CLI first verifies the name exists, and the agent loads only
that identity's keys under `PERSONA_AGENT_IDENTITY`, failing closed);
2026-10-14, stage 4 bridge half: the bridge protocol's `get_suggestions` accepts optional `host`/`cwd` signals,
the response gains a `context` field and items gain an `identity` annotation, and the suggested identity's credentials merge into the candidate list ranked first
(shared with `persona suggest` through core `suggest()`; `PERSONA_NO_CONTEXT` switches the whole layer off;
corrupt mappings degrade silently); same day, browser half: the popup consumes `context`/`identity` — ordering
follows the bridge-side order (the suggested identity is already ranked first), each entry is labeled with its identity name, and one line at the top reads "Context suggests X"
(`autofillUx.ts` pure-function test, 5 cases). Remaining: the desktop tray candidate.
Related: [Core concept: context](src/concepts/context.md),
[ROADMAP M7](ROADMAP.md#milestone-7--identity-runtime-positioning--concepts-feature-track-follows).

## 1. Goals and positioning

The next step after autofill is **identity suggestion**: when the user enters a directory, opens a repository, or connects to a
host, Persona should know "which identity is most likely now" and rank it first — rather than leaving the
user to pick by hand among six identities.

Iron rule (consistent with `concepts/context.md`):

> **Context suggests; it never authorizes.** A suggestion never bypasses policy to allow an action; an unconfirmed
> suggestion does not change `active_identity_id` — it only changes the "default/first candidate".

## 2. Where the concepts land

```
Signal collection (facts observable by the client)
      │
      ▼
core: ContextService (pure function, unit-testable)
      │  Input: Context { cwd, host, remote, origin, ... } + mapping table
      │  Output: candidate identity list (identity, score, reason) — ranking, threshold, fallback
      ▼
Consumers (CLI prompt / bridge suggestions / desktop UI)
      │
      ▼
User confirms → persona switch (the only identity-change path, audited)
```

- Decisions must live in **core** (ContextService); all clients share one scoring implementation;
- Clients only **collect signals** (cwd, host, origin); they carry no reasoning of their own;
- Identity changes still go through `persona switch` and the `active_identity_id` pointer — a suggestion only
  replaces the "which one is the default" decision.

## 3. Context signal inventory

| Dimension | Signal                                                          | Source                                      | Reliability                           | In v1?       |
| --------- | --------------------------------------------------------------- | ------------------------------------------- | ------------------------------------- | ------------ |
| Terminal  | `cwd`                                                           | `std::env::current_dir`                     | Scripts can forge it, but suggestions do not authorize, so it is harmless | ✅           |
| Git       | Walk up from `cwd` to `.git`, read `remote origin` → forge and owner/repo | Shell call into git, or `git2`              | High                                | ✅           |
| Terminal  | `hostname`                                                      | `gethostname` / `PERSONA_HOST` override     | High (can be changed via env var; see below) | ✅           |
| Terminal  | Parent process chain (is the shell interactive)                 | `/proc/<ppid>/comm` heuristic               | Medium; only prompt on an interactive TTY, leave scripts alone | ⚠️ Stage 2    |
| SSH       | Host / key requested by the agent                               | Existing agent policy input                 | High                                | ✅ (stage 3) |
| Browser   | page origin / per-site default                                  | Existing autofillDefaults                   | High                                | ⚠️ Stage 4    |
| Desktop   | Current window/project                                          | Tauri side                                  | Medium                              | ⚠️ Stage 4    |
| Device    | Machine role (dev-pc / laptop / server)                         | Hostname convention, or `~/.persona/machine-profile` | User self-declared          | ✅ (optional) |

Privacy boundary: all signals are computed locally and never leave the machine; suggestion history never enters sync and never enters the server;
the audit log records only "which suggestion the user confirmed" (reusing the existing switch audit), never the signal itself.

## 4. Suggestion algorithm v1 (deterministic scoring)

Pure function `score(ctx) -> Vec<(identity, score, reason)>`; no randomness or ML allowed:

```
score = Σ (signal_match × signal_weight)
Threshold: only entries with score ≥ MIN_SUGGEST (e.g. 0.6) qualify as candidates; take the first
Tie: most recently used active entry wins (SQLite records the identity + ts of every switch)
No candidate: fallback = current active identity (behavior identical to today)
```

Example (static mapping table):

```toml
# ~/.persona/context.toml (user-maintained; v1 also supports the persona context map subcommand)
# Valid TOML syntax is dot-separated quoted keys (the whitespace form in the first design draft was git-config style and is invalid)
[project."github.com/cuihairu/persona"]
identity = "OpenSource"

[host.".*-server$"]
identity = "Ops"
```

- `cwd=~/workspace/persona` → remote `github.com/cuihairu/persona` →
  hits `[project ...]` → OpenSource (score 1.0, reason="repository github.com/cuihairu/persona");
- `cwd=~/workspace/client-a` → no project mapping, host=`dev-pc` matches no `-server` pattern,
  but `persona switch` was run 41 times in this directory within the last 30 days, to "Client-A" →
  learned candidate "Client-A" (score 0.7, reason="used in this directory recently");
- Nothing hits → active identity, behavior unchanged.

### 4.1 History learning (optional, off by default)

Off by default; once `persona context learn on` is set, every `persona switch` writes
`(identity, cwd_hash, host, ts)` into a new SQLite table (local, never synced).
When suggesting, one learned candidate is produced from "how recently the same signal group was used". Rationale:
learning builds on behavior the user already has, and the result only affects the default, so the risk is low; but keeping it off by default
preserves the "no surprises" principle.

## 5. User model and data

- Mapping table: `~/.persona/context.toml` (global) + optional `$repo/.persona/context.toml`
  (inside the repository; ignored by `.gitignore` by default — sharing identity preferences across a repository is a team decision,
  so nothing is auto-shared; an in-repo **plaintext** mapping may only reference identity names and never touches key material);
- Override chain (highest precedence first): environment variable `PERSONA_CONTEXT_OVERRIDE=<identity>` >
  in-repo mapping > global mapping > history learning > active identity;
- Identity name references share their source with `persona switch` (if the name check fails, skip that candidate and warn).

## 6. Integration points

- **CLI (v1 core)**: `persona suggest` (human-readable) and `persona suggest --json`
  (script-friendly); `persona context map/get/unmap/learn on|off/status`;
- **Interactive prompt (v1)**: `persona shell-hook` generates a zsh/bash snippet; on an interactive TTY only,
  and only when `PERSONA_NO_CONTEXT` is unset, it shows an "⛵ OpenSource" candidate in PS1,
  and offers `persona use` for one-keystroke confirmation (= an alias for `persona switch`, audited)
  — note that `persona switch` semantics are unchanged; a suggestion is never executed automatically;
- **Bridge protocol (stage 4, implemented 2026-10-14)**: a `get_suggestions` request may carry
  optional `host`/`cwd` fields; the serving side (the bridge, not the server) scores with the **same** core
  `suggest()`: the response gains `context` (identity/score/reason), items gain an
  `identity` annotation, and the suggested identity's credentials merge into the candidates ranked first (cards merge the same way) —
  backward compatible: with fields omitted / no mappings, behavior matches today (no `context` in the response,
  legacy extension shape unchanged); the extension side (`popup.ts`) consumes the same response: ordering follows the bridge-side order,
  each entry is labeled with its identity name, and one context hint line sits at the top (`autofillUx.ts` pure function;
  `nativeBridge.ts` types gain the optional `identity`/`context` fields);
- **SSH (stage 3)**: the host dimension already present in agent policy feeds into ContextService —
  when touching `*.company.com`, suggest the Work identity; `--identity` moves from reserved to a filter.

### 6.1 Why not debut in the bridge protocol

The browser extension is the highest-frequency entry point today, but it already has a baseline suggestion from "per-site default + active identity";
cwd/host signals are worth the most in terminal scenarios. v1 locks onto the CLI, gets ContextService
proven in core, and only then rolls out horizontally to the browser and desktop.

## 7. 兼容性与安全

- 未配置任何映射、未开学习时，`suggest` 结果 ≡ 今日行为（active identity）；
- 建议**永不**独自触发 `switch`、永不改变任何策略评判（origin binding、
  user gesture、审批闸门全部不动）；
- 环境变量覆盖是「建议层」覆盖，不扩大任何授权（已有 `PERSONA_*` 首领一致）；
- 仓库内映射仅明文引用分身名，不写材料/密钥；同步不过（该表不进库）。

## 8. 阶段计划

| 阶段 | 交付                                                                                        | 验收                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | core `ContextService` + `context.toml` 解析 + `persona suggest [--json]` + `context` 子命令 | 单测：映射命中/无命中/覆盖链/平局/伪造信号；无映射时输出=active **——已实现 2026-10-12（`core/src/context.rs` 30 例 + CLI 8 例；suggest/context 豁免 workspace 要求，可在任意项目目录运行；映射文件损坏按「忽略该层并告警」处理）**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 2    | shell-hook、交互 TTY 提示、`persona use`、历史学习表（默认关）                              | 双 shell 冒烟；学习开关默认关；审计含 reason **——已实现 2026-10-13（`persona shell-hook [bash\|zsh]` 生成片段经 `bash -n`/`zsh -n` 语法冒烟 + source 直调降级冒烟；`persona suggest --short` 供 PS1；`persona use` = switch 别名，确认首位建议时审计 details 记 "confirmed context suggestion: {reason}"；学习表 migration 020，开关默认关，`persona context learn on/off/status/clear`，记录只存 cwd SHA-256 + 分身名，不进同步；学习候选权重 0.7、30 天窗口，任何映射命中都在其上）**                                                                                                                                                                                                                                                                        |
| 3    | SSH host 维度接入、`--identity` 生效                                                        | `ssh -T git@github.com` 场景建议正确；host 策略联动不变 **——已实现 2026-10-13（`persona ssh run --host` 以目标主机为唯一信号走 ContextService：命中时 stderr 打一行建议（不改 agent 目标主机文件、不改策略评判），`PERSONA_NO_CONTEXT` 非空整层关闭，任何加载失败静默无建议；agent 策略链路未动。`ssh add-to-agent --identity <名>` 先验名存在再 spawn，agent 按 `PERSONA_AGENT_IDENTITY` 只加载该分身的 SSH 密钥、未知名不加载任何密钥（fail-closed）。suggest host 建议 7 例 + agent 过滤 2 例 + CLI 传参/早失败 2 例全绿；实机走查：scratch workspace 中 `--host git.company.com` 出建议行、未知主机静默、opt-out 静默、假 agent 收到过滤器 env、`--identity Ghost` 先失败不 spawn）**                                                                      |
| 4    | 桥协议字段、桌面托盘候选、浏览器建议排序                                                    | 全部入口一致候选；旧扩展（未知字段）不回归 **——桥半已实现 2026-10-14（桥协议可选 `host`/`cwd` 字段 + `context` 响应 + items `identity` 标注 + 建议分身并入排最前；8 例缝级测试（宿主映射命中与跨身份合并、无映射、损坏映射降级、env 覆盖压过映射、显式 host 字段压过 origin、cwd 仓库发现 + 仓库内映射压过全局、`PERSONA_NO_CONTEXT`、card 表单合并）+ 端到端兼容测试（信号被接受、无映射时 `context` 缺省、items 带 identity）；身份枚举/解析走既有 `Repository` trait（与全仓口径一致，未加 inherent 重复）。浏览器半同日已实现：popup 消费 `context`/`identity`（排序沿用桥端序，建议分身已排最前；逐条标分身名；顶部 "Context suggests X (score N.NN)" 提示；`autofillUx.ts` 新增 5 例纯函数测试，扩展 164 例 + tsc + build 全绿）。剩余：桌面托盘候选）** |

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
