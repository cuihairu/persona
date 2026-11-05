# 桌面填充第三轮：P1 确认绑定 snapshot_id + 五项 P2 收口（2026-11-06）

基线：`20eb126`（第二轮审核收口后的 main）。本轮 `8a17cb1..4915a10` 五笔逻辑提交，
全量门禁 + openclaw 真机重验（lib 12/12、跨进程 5/5，真实原始日志入仓）。

## P1：确认绑定快照（在途请求不得转投新目标）

原缺陷：`confirmed` 只是布尔，`desktop_fill_credential` 在**异步解密完成后**才读
「当前槽位」（commands.rs 旧 ：1276）——确认 A 后浮窗重新捕获 B，在途请求会把
凭据注入 B；浮窗收起清槽同理会在途请求落空或误判。

修复（`8a17cb1`，红先行：先写 `confirm_binding_tests` 5 例平台无关纯函数测试，
编译失败即 RED，再实现转 GREEN）：

1. 捕获快照时生成 `snapshot_id`（UUID v4，`FillTarget.snapshot_id`）；
2. `fill_target_status` 随就绪态下发 id；前端确认面捕获并存储，注入请求
   原样带回（`desktopFillCredential(credentialId, confirmed, snapshotId)`）；
3. 后端在解密（在途窗口）完成后**持锁**按 id 绑定（`bind_confirmed_snapshot`
   纯函数）：槽位为空 → `FILL_TARGET_DISCARDED`（隐藏/清槽）；槽位已被新一轮
   捕获替换 → `FILL_TARGET_CHANGED`（确认 A 后捕获了 B）；请求缺 id →
   `FILL_TARGET_SNAPSHOT_REQUIRED`。在途请求绝不转投新目标——绑定成功返回
   的是被确认的那份快照的克隆，指纹重验证 + 逐控件重验证都锚定它；
4. 锁外注入（慢 FFI）成立的前提是注入目标已在锁内验证并克隆为确认快照；
   失效清槽（`CAPTURED_TARGET_INVALID`）只清本请求确认的那份快照——槽位若已
   换成别的新目标，不替用户清掉；
5. 前端如实消费：新增三个 typed 错误码 + en/zh-CN 提示（提示重新走确认流），
   就绪态但无 snapshot_id 视同无有效目标，不进确认面；jest 新增 2 例
   （`FILL_TARGET_CHANGED` 在途拒绝不收起浮窗、缺 id 本地拒绝）。

## P2 五项

1. **原始日志缺失**：README 声称的两份 .log 已从 openclaw 取回归档
   （`run1-d601c14/`，`d601c14` 当轮任务的真实输出）；并按纪律在本轮修复后
   于该机重跑整套件，run3（`a283573`）日志归档于顶层（lib 12/12 + xproc 5/5，
   `filltest.done lib_exit=0 xproc_exit=0`，计划任务 `PersonaFillTest` /IT）。
2. **竞态测试**：`fill-test-host` 新增 `arm-race-hook`（子类化 username 框，
   第一条 WM_SETTEXT 完成写入后在同一消息处理内同步销毁重建）——新的
   `cross_process_inflight_destroy_rebuild_rejected` 是**注入请求在途时**完成
   销毁重建的真竞态：断言注入整体拒绝（密码写入前的逐控件重验证失败）且重建
   窗口内密文零残留（跨进程读 + 宿主同进程读回双重确认）。旧「销毁重建」用例
   注明是注入前完成，并把「同进程同指纹 HWND 值复用平台无法区分」如实改写为
   剩余限制（不再声称该分支「拒绝」）。真机跑通过程：首轮 4/5——失败在测试
   脚手架 READBACK 帧解析（重建后两框为空是预期结局，`a283573` 放宽解析），
   复跑 5/5。
3. **恒空断言降级**：跨进程 WM_GETTEXT 读 ES_PASSWORD 的 `assert_eq!("")`
   通用断言移除，改为 eprintln 实测观察注记（Server 2022 实测空，不做通用
   断言）；成功判据不变：靶进程同进程读回逐字符一致。
4. **剪贴板告警**：非文本内容（文件/位图/自定义格式）被覆写清空时返回告警并
   落 `tracing::warn`（新增 `EnumClipboardFormats` 检测 + 非文本种子测试）；
   粘贴失败分支与闭包 panic 分支此前吞掉的恢复告警也补落日志。剪贴板用例以
   进程内互斥串行化（剪贴板是进程全局的，并行用例互相踩）。
5. **文档过满收口**（gap 中英 #12、`docs/src/design/desktop-fill.md`、todo.md
   #12）：「隐藏即丢弃」限定为浮窗 toggle/关闭路径清槽 + snapshot 绑定后在途
   确认如实拒绝；「无静默路径」限定为确认+绑定双门禁，且明确 Win32 校验非
   原子、重验证与写入之间的竞态窗口仍在；「竞态拒绝」限定为注入前销毁重建与
   在途钩子两类已证场景，同进程同指纹 HWND 值复用如实记为剩余限制；「Windows
   恒隐藏」降级为 Server 2022 实测观察（记录观察值，不做跨版本通用断言）。

## 门禁

- `cargo test --lib`（Linux）：272 passed / 0 failed；
- `cargo clippy --workspace --all-targets`（Linux）：0 告警；
- `cargo check --workspace --all-features --all-targets --target
x86_64-pc-windows-gnu` + 同参数 clippy：0 告警（Windows 侧编译面全干净）；
- tsc `-p tsconfig.json`：干净；jest：56 套件 747 例全绿（较上轮 +4：
  确认绑定 2 例 + mock 口径调整）；
- openclaw 真机（Windows Server 2022 交互式会话）：lib `cargo test --lib
desktop_fill` 12/12、跨进程 5/5，原始日志
  `docs/review/evidence/openclaw-2026-11-06-desktop-fill/{filltest-lib.log,
filltest-xproc.log,filltest.done,run1-d601c14/}`。

## 提交

| commit     | 内容                                                                          |
| ---------- | ----------------------------------------------------------------------------- |
| `8a17cb1`  | fix(desktop): bind fill confirmation to the captured snapshot via snapshot_id |
| `2b67a63`  | test(desktop): genuine in-flight destroy/rebuild race + observation notes     |
| `7d9519c`  | docs: scope desktop-fill claims to the implementation proof                   |
| `4915a10`  | test(desktop): accept empty READBACK frames                                   |
| （本轮末） | docs/review: run1 原始日志补归档 + run3 重验日志 + README/报告/todo           |

## 剩余风险（如实）

- Win32 校验与写入之间非原子竞态窗口仍在（平台固有）；同进程同指纹的 HWND
  值复用平台无法区分，由确认面（目标应用名展示）兜底；
- 跨进程 WM_GETTEXT 读 ES_PASSWORD 的系统行为只在一台 Server 2022 上实测，
  套件按观察记录，未做跨版本断言。
