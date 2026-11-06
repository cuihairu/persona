# 桌面填充第四轮收尾：`lib_exit=101` 诊断修复 + openclaw 全套重验至绿（2026-11-06）

基线：`4644114`（第四轮改动全部推送后、上席死于 glm 限额处）。本席产出
`2c05120..HEAD`：红证据先入仓 → 两笔测试修复 → 真机全套重验 → 本报告。

## 红：`lib_exit=101`（openclaw 真机）

上席最后状态 `filltest.done` = `lib_exit=101 frame_exit=0 xproc_exit=0`——
readback_frame 与跨进程套件已绿，只有 `cargo test --lib desktop_fill` 红。
原始日志归档于
`docs/review/evidence/openclaw-2026-11-06-desktop-fill/run5-red-4644114/`：
17 例中 15 通过、**2 失败，两个都是 Windows-only 剪贴板用例**（`win_tests`
是 `cfg(windows)`，Linux 侧本地门禁根本编译不到，所以带着病一路推到了
真机才暴露）：

1. **`clipboard_paste_warns_on_panic_path_when_restore_fails`**
   （`desktop_fill.rs:1451`，`closure panic must propagate after restore`）
   注入的写入函数 `|_| Err("injected clipboard writer failure")` **每次调用
   都失败**；实现里明文覆写是第一次调用——覆写先 Err，`paste` 闭包根本不会
   执行，`catch_unwind` 拿到 `Ok`，断言必红。测试声称覆盖的「panic + 恢复
   失败」组合从未被构造出来（`6418859` 引入时即带病）。
2. **`clipboard_paste_warns_when_non_text_content_is_cleared`**
   （`desktop_fill.rs:1404`，`left: "PREV-PANIC-53cf…" right: ""`）
   期望为空的读用了 `read_clipboard_text()`——retry-until-non-empty，最多
   给 rdpclip 等外部剪贴板同步进程 **1 秒**把上一条用例写过的
   `PREV-PANIC-*` 灌回来，于是「外部回灌的陈旧内容」被当成本函数的残留。
   同文件 1355-1358 与 1514-1519 的注释已白纸黑字写了这个坑，本用例没照做。

两处都是**测试侧缺陷**，产品代码无问题：实现分支（覆写失败上抛、panic 在
恢复后 `resume_unwind`、非文本覆写告警）在同套件另外 3 个剪贴板用例里均已
覆盖并通过。

## 修复（红先行，只改测试，产品代码零改动）

| commit   | 内容                                                                                 |
| -------- | ------------------------------------------------------------------------------------ |
| `2c05120` | 红证据先入仓：run5 真机四份原始日志（`lib_exit=101 …`）force-add 归档                  |
| `a68fd72` | 期望空的读改用 `read_clipboard_text_expect_maybe_empty()`（单次读，只在 OpenClipboard 瞬时失败时重试） |
| `a9d2eed` | panic 路径用例的注入写入函数改为「第 1 次（明文覆写）Ok、之后（写回备份）Err」，确定性构造 panic+恢复失败；用例收尾 `seed_clipboard("")` 清掉留在真剪贴板上的 `PANIC-SECRET` |

`a9d2eed` 另修一处隐患：恢复是注入失败的，明文 `PANIC-SECRET` 会留在真
剪贴板上留给后续用例和外部同步进程——测试自己清场。

## 真机重验（openclaw，计划任务 `PersonaFillTest` /IT，HEAD `a9d2eed`）

`filltest.bat` 与仓内此文件 SHA-256 逐字节一致（`AD11EA03…B492DD`）后触发；
日志显示 `Compiling persona-desktop … Finished in 46.34s`，确系新代码重编译
后运行。`filltest.done`：**`lib_exit=0 frame_exit=0 xproc_exit=0`**

| 套件            | 结果                                   | 覆盖第四轮新增用例                                                    |
| --------------- | -------------------------------------- | --------------------------------------------------------------------- |
| lib `--lib desktop_fill` | **17 passed / 0 failed**        | 取消时序 `slot_cleared/slot_replaced_after_first_write_aborts_remaining_write` 2 例 + 剪贴板 4 例 + 确认绑定 5 例 |
| readback_frame  | **6 passed / 0 failed**                | 长度前缀 READBACK 协议（空字段/单字段残留/utf16 hex）                  |
| 跨进程 xproc    | **5 passed / 0 failed**                | 在途销毁重建竞态 `cross_process_inflight_destroy_rebuild_rejected` 等  |

原始日志（force-add 入仓）：
`docs/review/evidence/openclaw-2026-11-06-desktop-fill/run6-green-a9d2eed/`
（`filltest-lib.log`、`filltest-frame.log`、`filltest-xproc.log`、`filltest.done`）。

## 本地门禁（Linux）

- root workspace `cargo test --lib`：**1503 passed / 0 failed**（connect_server 37 / core 1226 / mobile 19 / server 139 / ssh_agent 82）；
- root workspace `cargo clippy --workspace --all-targets`：0 告警；
- `desktop/src-tauri` 是**独立 workspace**（root 门禁覆盖不到，本席补跑）：
  `cargo test --lib` **273 passed / 0 failed**、`cargo clippy --all-targets` 0 告警；
- Windows 编译面：root 与 desktop 两侧
  `cargo check/clippy --all-targets --target x86_64-pc-windows-gnu` 均 0 告警
  （desktop 侧即被修的 `win_tests` 所在 crate）；
- `tsc -p tsconfig.json`（desktop）：干净；jest：**56 套件 / 747 例全绿**。

注：jest 首跑与本机并行的 clippy 及他仓构建（load average 一度 >150）撞车，
3 例 5s 超时；无并发负载复跑 747/747 全绿——负载抖动，非用例缺陷，如实记录。

## 剩余风险（如实）

- 剪贴板用例跑在真机共享剪贴板上：期望空的读已缩到单次读，但外部同步进程
  在**读之前**注入仍可能让断言红——窗口极小，非零；
- `win_tests` 只能靠真机套件兜底，本地与 CI 天然照不到（`cfg(windows)`）；
- panic 用例清场写 `seed_clipboard("")` 失败被忽略：极端情况下 `PANIC-SECRET`
  会留在真剪贴板上（清场失败本身不改变该用例的断言语义）。
