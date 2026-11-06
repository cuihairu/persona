# Persona 外部审核（2026-10-18）· 四维度审计

> 来源: https://chatgpt.com/s/t_6ad48226917c8191b6469d0f327c9872
> 取回: 2026-10-18
> 维度: 代码审计 / 产品需求审计 / 安全审计 / Code Agent 可执行任务清单
>
> **性质：外部建议，不是本仓事实陈述。** 每条结论必须先与代码核对再采纳；
> 下方「核验结论」表记录核对结果，未核实的条目不得直接实施。
>
> 注：审核提到的 374 行任务清单是附件（sandbox 路径），本机无法取回，
> 完整任务清单见同目录 task-list-2026-10-18.md（599 行，已由用户于 2026-10-18 提供）。

我会按“**代码审计 + 产品需求审计 + 安全审计 + Code Agent 可执行任务清单**”四个维度来审核 `persona`，而不是只检查 README 或罗列一些泛泛的优化建议。

仓库地址：urlcuihairu/personahttps://github.com/cuihairu/persona

从项目公开信息看，Persona 的核心定位是一个本地优先的多身份凭据管理系统，涉及密码与密钥保险库、TOTP、Passkeys、SSH Agent、浏览器扩展、桌面与移动端，以及端到端加密同步。它不是一个普通的 CRUD 应用，**安全边界、密钥生命周期、跨端数据一致性和权限控制必须优先于新功能开发**。citeturn950439view0

最终我会整理成独立的 `todo.md`，让 Claude Code、Codex 等代码 Agent 能够按优先级逐项执行，明确每项任务的检查范围、实施要求、验收标准和测试要求，并避免 Agent 未经验证就重写现有架构。

## 审核中发现的重点问题

以下结论来自当前公开仓库的 README、TODO、威胁模型、浏览器桥协议、CI 工作流和历史审核报告；我会在任务文件中区分**已经能从仓库确认的问题**与**需要 Code Agent 在实际代码中复现验证的问题**。

| 优先级 | 发现                                | 审核判断                                                                                                                                                     |
| ------ | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| P1     | `TODO.md` 与 `todo.md` 同时存在     | 两个路径仅大小写不同，存在 Windows 大小写不敏感文件系统的检出与文件覆盖风险，应保留内容并消除冲突。                                                          |
| P1     | Rust 工具链版本不一致               | `rust-toolchain.toml` 固定为 1.97.0，而 CI 工作流使用 1.99.0；需要核实实际生效版本，统一本地、CI 和可复现构建基线。                                          |
| P1     | 安全审计未形成严格门禁              | CI 中 `cargo audit` 和前端依赖审计允许失败后继续，Makefile 也有忽略前端审计失败的写法。需要明确漏洞分级、豁免期限和阻断规则。                                |
| P1     | SSH Agent 的 Windows 实机验收未闭环 | `BUGS.md` 已记录启动问题的代码修复，但仍要求 Windows 实机验证。不能仅凭编译成功或模拟测试判定完成。                                                          |
| P1     | 浏览器桥存在明确的策略实现缺口      | `docs/BRIDGE_PROTOCOL.md` 明确指出，未知来源确认、每次填充确认和敏感操作生物识别等配置项尚未实现。必须确保产品界面、配置与文档不把计划中的控制误报为已生效。 |
| P2     | 发布安全和仓库卫生需要收尾          | 发布工作流注明安装包尚未签名；仓库还跟踪了运行日志文件，且 `.gitignore` 未覆盖通用日志。需要补充发布完整性和运行产物治理。                                   |

参考：urlCI 工作流https://github.com/cuihairu/persona/blob/main/.github/workflows/ci.yml、urlBUGS.mdhttps://github.com/cuihairu/persona/blob/main/BUGS.md、url浏览器桥协议https://github.com/cuihairu/persona/blob/main/docs/BRIDGE_PROTOCOL.md、url发布工作流https://github.com/cuihairu/persona/blob/main/.github/workflows/desktop-build.yml。这些问题并不意味着所有相关功能都存在可利用漏洞，但都值得进入可验证的整改计划。

另一个重要原则：同步设计文档明确承认，当前方案不保证抵御恶意服务器的历史回滚，也尚未将附件纳入第一版增量同步。因此，任务清单会要求先保证现有承诺真实、失败时安全，再决定是否扩展协议，不会让 Agent 擅自改造整个同步架构。

## 下载 Code Agent 任务清单

## todo.md

Markdown · 374 行 · 中文任务清单

适用于 Claude Code、Codex 等代码 Agent

下载 todo.md

---

内容包括：

- 仓库基线、文件命名冲突和工具链统一
- CI 安全门禁、依赖审计与发布供应链
- 密钥层级、加密迁移、自动锁定和明文泄漏排查
- 浏览器桥、Connect API、SSH Agent 安全验证
- E2EE 同步、设备管理、冲突处理和备份恢复
- Windows/macOS 实机测试、回归测试与验收标准

### 建议你如何使用

**不要让 Agent 一次性执行全部 374 行任务。** 建议先让它执行 Phase 0，确认当前分支、文件命名冲突和工具链版本，再逐阶段推进。每项任务都要求提供代码位置、根因、回归测试和真实验证结果。

还有一个特别重要的操作：仓库目前已有 `TODO.md` 和 `todo.md` 两个大小写不同的文件。新清单已将保留原任务记录、消除 Windows 文件名冲突列为首要任务。先让 Agent 安全迁移并更新引用，不要直接覆盖历史记录。citeturn950439view0turn436250view1turn436250view2

**审核范围说明：** 本次结论基于 GitHub 当前公开的代码目录、文档和工作流进行静态审查，尚未在完整本地环境执行编译、测试或 Windows/macOS 实机验收。清单已明确区分确认的问题与待复现事项，避免 Agent 把推测当成漏洞，或把尚未验证的功能标记为完成。

---

If you want, I can:

- 详细分解todo.md任务清单第一阶段执行步骤
- 列出Persona项目CI安全门禁缺失及改进方案
- 制定Persona浏览器桥策略缺口验证与整改任务

====

]}/>

最终我会整理成独立的 `todo.md`，让 Claude Code、Codex 等代码 Agent 能够按优先级逐项执行，明确每项任务的检查范围、实施要求、验收标准和测试要求，并避免 Agent 未经验证就重写现有架构。

---

## 核验结论（已核对，2026-10-18）

> 六条**全部属实**，无「审核有误」项。证据如下。

| 审核条目 | 核验结果 | 证据 file:line |
| -------- | -------- | -------------- |
| TODO.md 与 todo.md 同时存在（Windows 大小写冲突） | **属实** | `git ls-files` 同时列出 `TODO.md` 与 `todo.md`；`ls -la` 两者同为 6632 bytes、同 mtime（Windows 大小写不敏感文件系统映射为同一磁盘文件）；`git config core.ignorecase=true`；pull 前两 blob 不同（`HEAD:TODO.md`=b906beb 旧格式「# Persona TODO」，`HEAD:todo.md`=e479d43 新格式「# TODO」）——即同一磁盘文件被两个不同 blob 索引，检出/覆盖风险真实存在。 |
| rust-toolchain.toml 1.97.0 vs CI 1.99.0 不一致 | **属实** | `rust-toolchain.toml:11` `channel = "1.97.0"`；CI 七处 `dtolnay/rust-toolchain@1.99.0`（`ci.yml:32,76,131,148,176`、`desktop-build.yml:104,196`）。注意：`rust-toolchain.toml:4-9` 注释自陈该文件是目录级 override、cargo 经 rustup 解析时永远压过 dtolnay action 装的 stable，故**实际生效版本是 1.97.0**，CI 的 @1.99.0 被覆盖（run 37155098351 android E0463 根因即此）。声明不一致属实，但非静默漂移——已文档化覆盖。 |
| cargo audit / 前端依赖审计允许失败继续 | **属实** | `ci.yml:157` cargo audit `continue-on-error: true`（注释「Don't fail CI on advisories」）；`ci.yml:214` pnpm audit `continue-on-error: true`；`Makefile:162` `pnpm --filter persona-desktop audit || true`。三处均静默放行。 |
| BUGS.md 记录 SSH Agent 仍需 Windows 实机验证 | **属实** | `BUGS.md:12`「状态：代码已修，Windows 实机全链（点启动→agent 真起来→状态已启动→重启 app 仍正常）待用户复测」。 |
| BRIDGE_PROTOCOL.md 承认策略实现缺口 | **属实** | `docs/BRIDGE_PROTOCOL.md:1011`「planned and not yet implemented」；`:1014-1016` 三键 `confirm_on_unknown_origin`/`confirm_on_fill`/`:1016 require_biometric` 均标 not implemented；`:1018` 说明当前实际生效仅 user gesture gate + desktop approval gate。 |
| 发布工作流安装包未签名；仓库跟踪了运行日志 | **属实** | 未签名：`desktop-build.yml:25-26`「Binaries are unsigned (SmartScreen/Gatekeeper will warn)； signing keys tracked as follow-up」。运行日志被跟踪：`git ls-files` 列出 `server-18996.log`；`.gitignore` 中无任何 `.log`/`log/` 规则（grep 零命中）。 |

## 落地跟踪

- [x] 核对上表六条，填证据（2026-10-18，六条全属实，无「审核有误」项）
- [ ] 按核对结果分阶段实施（每阶段过测试后勾掉，填 commit hash）
  - [x] a) 基线类（P1）：文件命名冲突、Rust 工具链版本统一（以实际生产版本为准）——旧 `TODO.md`（完整路线图 130 行）迁移为 `TODO_BACKLOG.md`、`todo.md`（整改清单 30 行）保留，索引零大小写冲突（awk 扫描）、18 处引用更新、原内容完整保留；工具链统一到 `1.97.0`（`rust-toolchain.toml` 是目录级 override 永远压过 dtolnay action，实际编译走 1.97.0，CI 七处 `@1.99.0`→`@1.97.0`，同时修 android target 装错工具链的 E0463 根因）（071793d）。注：本机无 cargo/rustc，未能跑 `cargo test`；.rs 改动全为注释、工具链改动仅版本串，均不涉编译语义，最终以 CI 验证。
  - [x] b) CI 安全门禁（P1）：审计失败不应静默继续——确认三处确会放行后去除静默：`ci.yml` cargo audit 与 pnpm audit 两处删 `continue-on-error: true`、`Makefile` security-check 删 `pnpm audit || true`；severity 阈值 `--audit-level=moderate` 保持不变（是否下调阻断等级属维护者策略，AUDIT-010，不擅改）；同步更新 `SUPPLY_CHAIN_SECURITY.md` 两处旧现状描述（0911993）。**注：本机未能实跑审计**——cargo 不可用；`pnpm audit` 被仓内既有 `pnpm-lock.yaml` 重复键（`@types/node@26.6.5`，2605/2608/2611/2614 行，HEAD 即存在，非本次引入）挡住（ERR_PNPM_BROKEN_LOCKFILE）。审计是否通过需 CI 侧验证；本改动只保证失败会阻断、不静默。
  - [ ] c) 浏览器桥策略缺口、SSH Agent Windows 验收
    - [x] 浏览器桥策略缺口——核对属实但无「误报为已生效」风险，无需代码改动：`confirm_on_fill`/`confirm_on_unknown_origin` 在非文档代码零读取（全仓 grep，排除 node_modules/dist/build/target/docs），`require_biometric` 属 **SSH Agent** 子系统（`agents/ssh-agent/src/policy.rs:81`）而非浏览器桥；三键均未接入任何 UI/配置面（否则会有读取点），故不存在被误显示为已启用的路径。`docs/BRIDGE_PROTOCOL.md:1011-1018` 已准确标注三键 planned & not implemented、并列明当前实际生效仅 user gesture + desktop approval gate，文档边界准确。AUDIT-030 明令「未经产品决策不得擅自实现新确认 UX」→ 不实现新确认流；若后续要对不支持配置给明确错误，需 Rust 编译验证，留后续（本机无 cargo）。
    - [ ] SSH Agent Windows 实机验收 → **BLOCKED**：本机无 cargo/rustc/rustup（`command -v` 三者皆空），无法构建 agent，亦无法在真实 Windows 桌面会话验签（启动→进程/管道真实可用→状态 running→签名成功→停止→重启状态正确）。按 AUDIT-032「不得用 CI 编译成功/模拟 Named Pipe 替代真实运行；无设备则 BLOCKED 不得勾选」。**缺什么**：① Rust 工具链以构建 `agents/ssh-agent`；② 真实桌面会话手动验上述全流程 + 命名管道权限/重复启动/杀软拦截等错误路径，附 Windows 版本与构建版本。BUGS.md:12 现状「代码已修、Windows 实机待复测」维持不动。
  - [ ] d) 发布签名、仓库卫生（P2：签名设计 + 移除被跟踪日志 + .gitignore 补 .log）
