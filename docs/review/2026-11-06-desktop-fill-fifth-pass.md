# 桌面填充第五轮收尾：真实命令层取消时序测试 + 文档口径收紧 + openclaw 红绿双验（2026-11-06）

基线：`7b880d7`（上席已推命令层取消时序套件 + 宿主暂停钩子）。本席产出
`52beff2..3325d9e` 四笔（推送后 CI 追加格式修复 `8cb81c9`），另有真机红/绿
两轮原始日志入仓。

## 一、本地 3 笔 commit 的核验（先说结论：内容已在 main，唯一增量是运行脚本）

本地分支 `round5-red-old-impl`（基于 `a283573` 旧命令层）领先 3 笔未推 commit。
逐文件比对结果：

| 本地 commit                            | 内容                                                                                     | 与 origin/main 对应笔的比对                                                                                                                      |
| -------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `997cabc` 命令层取消时序套件（红叠加） | `fill-test/tests/desktop_fill_command_cancel.rs`、`fill-test/Cargo.toml`、`filltest.bat` | 套件与 Cargo.toml 与 `7b880d7` **逐字节相同**（`git diff` 为空）；唯一差异是 `filltest.bat` 缺 cmdcancel 腿                                      |
| `09e35c1` 长度前缀 READBACK 协议       | `fill-test/lib.rs`、`fill-test-host.rs`、跨进程套件                                      | `lib.rs` / `fill-test-host.rs` 与 `08c4944` **逐字节相同**；跨进程套件不同是因为本地分支仍是旧 `execute_fill` 签名（属分支基线差异，非新增内容） |
| `ab42d44` 确定性暂停钩子               | `fill-test-host.rs`                                                                      | 与 `7a4dbaf` **逐字节相同**                                                                                                                      |

因此**不重复推送同内容**：真正缺的是
① `filltest.bat` 的 cmdcancel 腿（否则真机任务永远不跑命令层套件）；
② 套件头注释引用的 `run7-red-cmdcancel-old-impl/` 目录**从未入仓**（红证据只在真机上）；
③ 文档过满表述残留。
另记一处本地分支自身的缺陷（未推送，仅记录）：`997cabc` 加了 4 个 dev-dependency
却没提交 `Cargo.lock`，该分支 `--locked` 构建会失败——origin 的 lock 已含同一 delta。

## 二、套件完整性核验（可独立触发 + 旧实现可复现取消路径）

`desktop/src-tauri/fill-test/tests/desktop_fill_command_cancel.rs`（575 行，5 例）：

- **端到端驱动真命令**：`desktop_fill_credential`（tauri mock runtime + 真服务解密 +
  真实跨进程靶窗 `fill-test-host`），不是引擎层 `execute_fill` 的直测——补的正是
  第四轮「命令层自建的 `slot_recheck_for` 闭包从未被真命令路径执行过」这个缺口；
- **取消时点确定性插桩**：注入线程阻塞在 username 的跨进程 `SendMessageW` 上，宿主在
  该消息处理内置 `HOOK_PAUSED`，测试在 `HOOK_PAUSED` 与放行命令之间改
  `AppState.fill_target`（清槽 / 换新 snapshot_id）——严格落在第一字段写入之后、
  密码写入之前，**不靠轮询碰运气**；
- **可独立触发**：
  `cargo test --features fill-test-host -p persona-fill-test --test desktop_fill_command_cancel`
  （Windows + 交互式桌面会话；缺 `fill-test-host` feature 时编译为 0 tests——文档已按此写全命令）。
  本机 Linux 上 `cargo test -p persona-fill-test --test desktop_fill_command_cancel`
  → `0 tests`（套件 `#![cfg(all(windows, feature = "fill-test-host"))]`，符合声明）；
  `cargo check -p persona-fill-test --features fill-test-host --tests --target x86_64-pc-windows-gnu`
  在旧命令层分支上 EXIT 0（套件对旧实现可编译）；
- **旧实现可复现取消路径（真机红，run7）**：openclaw，HEAD `ab42d44`（旧命令层：
  绑定比较在锁内、写入前无字段级重查），运行前核对该机 `git rev-parse HEAD` =
  `ab42d44`、任务用 `filltest.bat` SHA-256 `5CFCA21E…F926480A` 与仓内一致：
  - `lib_exit=0 frame_exit=0 xproc_exit=0`，**`cmdcancel_exit=101`**；
  - 命令层套件 5 例：3 过（确认门 / 缺 snapshot_id / 解密在途清槽拒绝），**2 红**，
    红的正是 `command_layer_mid_fill_slot_clear_aborts_remaining_write` 与
    `command_layer_mid_fill_target_swap_aborts_remaining_write`；
  - 失败点是 `assert!(!resp.success)`（断言文案 "…old implementation would report
    success here"）——即旧层在这两个时点**返回成功、未报告中止**（日志只到这一步：密码读回断言未执行，是否真的写完无从据此判断）。其后的密码
    读回断言因此没有执行，**日志本身不直接证明密码已落框**（本席据此把 README、
    两份设计文档与 todo 里的「照写密码并报成功」全部收窄为日志可证的口径）；
  - 原始日志 5 份 force-add 入仓
    `docs/review/evidence/openclaw-2026-11-06-desktop-fill/run7-red-cmdcancel-old-impl/`。

## 三、文档过满表述收紧（codex 三轮复审逐条点名，全部落地）

| 位置                                              | 改前（过满）                                                                                                                  | 改后（可证）                                                                                                                             |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `docs/src/design/desktop-fill.md` / `zh`          | 「nothing is ever redirected into a newly current target / 绝不把任何字段转投新目标」+ 把竞态窗口挂靠「同进程 HWND 复用限制」 | 「重查不把写入改投新目标（中止由下一次写入前的重查判定）」；重验证→写入非原子窗口与 HWND 值复用**拆成两件独立的事**分别说明              |
| 同上（就绪态）                                    | 「reflects the validated state / 验证后的真实状态」                                                                           | 「the slot as it was last validated / 最近一次验证时的槽位状态」                                                                         |
| `docs/FEATURE_GAP_ANALYSIS.md` / `.zh.md` #12     | 同上两句绝对口径                                                                                                              | 同步收窄（中止条件 + 独立竞态窗口 + 就绪态）                                                                                             |
| `todo.md` 首段                                    | 仍把**已移除**的「第二框」启发式、**未接线**的剪贴板备选写成现行设计；门禁数字无来源标注；xproc「4/4」                        | 启发式标注已移除、剪贴板标注「已建未接线、不提供保密」；门禁标注「2026-11-05 当时自报」；「当时 4/4，run3 起 5/5」；归档清单补 run4–run7 |
| 新增套件条目（两份设计文档 + 证据 README + todo） | —（无）                                                                                                                       | 写全带 `--features fill-test-host` 的命令、run7 实际证明到哪一步（`assert!(!resp.success)` 失败）、绿侧复验随后续提交归档                |

另修一处**本批次之外的既有破损**（声明项，codex 第三轮 PASS 后单独成笔）：
`docs/src/zh/design/desktop-fill.md` 把 `READBACK <unit-count>:<hex> …` 断在两行，
`<unit-count>` 落到行首被 Vue 当未闭合标签——**origin/main 的 docs 构建当时就是红的**
（在 `7b880d7` 干净 worktree 复现：`vitepress build` exit 1），docs 工作流因此连
prettier 自动修复都没跑到。合并为单行后 `npm run build` EXIT 0。

## 四、openclaw 真机重验（run8 绿，HEAD `8cb81c9`）

计划任务 `PersonaFillTest`（/IT）执行，任务用 `filltest.bat` 与仓内 SHA-256 一致；
该机 `git status` 无已跟踪改动，HEAD `8cb81c9`（= 当时 origin/main：4 笔本批次 +
CI prettier 自动修复）；`persona-desktop` 重编译 `Finished in 1m 56s`，确系新代码。

`filltest.done`：**`lib_exit=0 frame_exit=0 xproc_exit=0 cmdcancel_exit=0`**

| 套件                     | 结果                     | 覆盖                                          |
| ------------------------ | ------------------------ | --------------------------------------------- |
| lib `--lib desktop_fill` | **17 passed / 0 failed** | 取消时序 2 例 + 剪贴板 4 例 + 确认绑定 5 例等 |
| readback_frame           | **6 passed / 0 failed**  | 长度前缀 READBACK 协议                        |
| 跨进程 xproc             | **5 passed / 0 failed**  | 在途销毁重建竞态等                            |
| **命令层 cmdcancel**     | **5 passed / 0 failed**  | run7 上必红的两个 mid-fill 用例在此通过       |

原始日志（force-add 入仓）：
`docs/review/evidence/openclaw-2026-11-06-desktop-fill/run8-green-8cb81c9/`。

传输注记：该机 `git fetch origin` 两次超时（180s/600s，`ls-remote` 正常、无锁文件），
改用 `git bundle`（`main ^a283573`，96K，4 个前置 ref 均验证为 `ab42d44` 的祖先）
scp 后从 bundle 取对象；该机随后自行完成的 `origin/main` fetch 使其落在 `8cb81c9`，
即以该 SHA 跑绿。

## 五、本地门禁（Linux，rebase 到 `52beff2` 之后的终态）

- `cargo fmt --all -- --check`：EXIT 0；
- root workspace `cargo test --lib`：**1505 passed / 0 failed**（connect_server 37 /
  core 1228 / mobile 19 / server 139 / ssh_agent 82）；
- root workspace `cargo clippy --workspace --all-targets -- -D warnings`：0 告警；
- `desktop/src-tauri`（独立 workspace）：`cargo test --lib` **273 passed / 0 failed**、
  `cargo clippy --all-targets -- -D warnings` 0 告警；
- `npx tsc -p tsconfig.json`（desktop）：干净；
- `npx jest`：**56 套件 / 747 例全绿**；
- docs：`prettier@3.6.2 --check .` 对本批次 5 个文件全绿（4 个非本批次文件的既有
  漂移由 CI 在 `8cb81c9` 自动修复）；`npm run build`（vitepress，含死链渲染）EXIT 0。

提交门禁：四轮 codex `exec -p luna` 独立复审——前三轮针对四笔主体提交（首轮 FAIL
5 条 → 逐条修 → 第二轮 FAIL 1 条 → 修 → 第三轮 PASS，认可 stage list A/D/B/C 与四条
英文提交信息），第四轮对本报告 + run8 归档做 spot-check（数字与出处抽样全过；点名
run7 两处「未中止剩余写入」超出日志可证范围，已改为「未报告中止」）。

## 六、commit 清单（均已推 origin/main）

| commit    | 内容                                                                                                                                                              |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fc8e487` | `docs(review): archive the round-5 red command-layer run and wire it into filltest.bat`（run7 5 份日志 force-add + README 条目/表行 + filltest.bat cmdcancel 腿） |
| `b674f1d` | `fix(docs): keep the READBACK frame placeholder in one code span so vitepress builds`（只暂存那一处合并）                                                         |
| `f0cc27d` | `docs: scope the desktop-fill slot-recheck claims to the recheck logic`（设计中英 + gap 中英）                                                                    |
| `3325d9e` | `docs: record the round-5 command-layer cancellation closeout in todo.md`                                                                                         |
| `8cb81c9` | `docs: 自动修复 markdown 格式 [skip ci]`（CI 对 4 个非本批次文件的既有漂移）                                                                                      |
| 本报告    | `docs/review/2026-11-06-desktop-fill-fifth-pass.md` + run8 5 份日志 + README run8 条目                                                                            |

推送核验：`git rev-parse origin/main HEAD | uniq -c` 一行；`gh api` 读回
`run7-red-cmdcancel-old-impl/filltest.done` = `lib_exit=0 frame_exit=0 xproc_exit=0 cmdcancel_exit=101`。

## 七、剩余风险（如实）

- 本地 3 笔 `round5-red-old-impl` commit **未推送**（内容已由上席的 `7b880d7` /
  `08c4944` / `7a4dbaf` 落地，重复推送只会制造空提交或冲突）；该分支保留在本机与
  openclaw 上作为红证据的检出点，其 `Cargo.lock` 未随提交（见第一节）；
- run7 的两个红只证明「旧层返回成功、未报告中止」，密码是否真落框未被日志直接证明
  （密码读回断言未执行）——如需硬证据，可在旧实现上把读回断言提到 `!resp.success`
  之前再跑一轮；
- 命令层套件与其余套件一样依赖交互式桌面会话，`cfg(windows)` 使本地与 CI 天然
  照不到，只能靠真机任务兜底；
- docs 工作流对非本批次文件的格式修复是 CI 自动提交（`8cb81c9`），非人工审阅内容。
