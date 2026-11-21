# openclaw 真机证据：桌面填充（2026-11-06，run1、run3–run8 原始日志均已入仓）

- 环境：openclaw（Administrator@10.240.0.3，Windows Server 2022 x64，msvc +
  RUSTUP_TOOLCHAIN=stable，交互式控制台会话经计划任务 `PersonaFillTest`（/IT）执行；
  SSH 会话中 IsWindowVisible/GetForegroundWindow 失效，不可用于本套件）。
- 运行脚本：`filltest.bat`（与仓内此文件逐字节一致，任务执行前本地核对了哈希）。
- 代码：
  - **第一轮** HEAD `d601c14`（安全收紧定案：readback 定案 + 导入修复 + hex 解码
    与守卫断言）→ 原始日志在 `run1-d601c14/`（此前 README 声称的两份 .log 一直
    **不在仓内**，2026-11-06 第三轮已从该机取回归档——文件为当时任务的真实输出）；
  - **第三轮** HEAD `a283573`（P1 确认绑定 snapshot_id + 真竞态用例 + 告警补齐）
    → 顶层三份文件为本轮重跑的真实原始输出；
  - **第四轮红** HEAD `7e52d7b`（取消边界红测试 + READBACK 残留红测试，红先行）
    → `run4-red-7e52d7b/`，`lib_exit=101 frame_exit=101 xproc_exit=0`（预期红）；
  - **第四轮实现落地后** HEAD `4644114` → `run5-red-4644114/`，
    `lib_exit=101 frame_exit=0 xproc_exit=0`：实现侧绿、红在两个 Windows-only
    剪贴板用例（根因见第四轮报告）；
  - **剪贴板用例修复后复验** HEAD `a9d2eed` → `run6-green-a9d2eed/`，
    `lib_exit=0 frame_exit=0 xproc_exit=0`。
  - **第五轮红（旧命令层）** HEAD `ab42d44`（分支 `round5-red-old-impl`：命令层
    取消时序套件 + 长度前缀 READBACK + 宿主暂停钩子，叠在 `a283573` 的旧命令层
    上——绑定比较后锁释放、写入前无字段级重查）→ `run7-red-cmdcancel-old-impl/`，
    `lib_exit=0 frame_exit=0 xproc_exit=0 cmdcancel_exit=101`。命令层套件 5 例：
    3 过（确认门 / 缺 snapshot_id / 解密在途清槽拒绝），**2 红，红的正是两个
    mid-fill 用例**：失败断言为 `assert!(!resp.success)`——旧实现在这两个时点
    **返回成功**、未报告中止（其后的密码读回断言因此未执行，日志本身不
    直接证明密码落框），即「旧实现可复现取消路径」的红证据。运行前核对：该机 `git rev-parse HEAD` = `ab42d44`，
    任务执行用 `filltest.bat` 的 SHA-256 `5CFCA21E…F926480A` 与仓内此文件一致。
  - **第五轮绿（main，逐字段重查实现）** HEAD `8cb81c9`（= 当时 origin/main，
    含 4 笔本批次提交 + CI prettier 自动修复）→ `run8-green-8cb81c9/`，
    `lib_exit=0 frame_exit=0 xproc_exit=0 cmdcancel_exit=0`：命令层套件 **5/5 全绿**
    （run7 上必红的两个 mid-fill 用例在此通过），lib 17/17、readback_frame 6/6、
    跨进程 5/5。运行前核对该机 HEAD `8cb81c9`（`git status` 无已跟踪改动）、
    任务用 `filltest.bat` SHA-256 与仓内一致；`persona-desktop` 重编译
    `Finished in 1m 56s`，确系新代码。

## 结果

| 轮次 | 代码                  | lib 套件                               | 跨进程套件              | 退出码（filltest.done）                                                                       |
| ---- | --------------------- | -------------------------------------- | ----------------------- | --------------------------------------------------------------------------------------------- |
| run1 | `d601c14`             | 6 passed / 0 failed                    | 4 passed / 0 failed     | `lib_exit=0 xproc_exit=0`                                                                     |
| run3 | `a283573`             | 12 passed / 0 failed                   | 5 passed / 0 failed     | `lib_exit=0 xproc_exit=0`                                                                     |
| run4 | `7e52d7b`             | 12 passed / **3 failed**（红先行预期） | 5 passed / 0 failed     | `lib_exit=101 frame_exit=101 xproc_exit=0`                                                    |
| run5 | `4644114`             | 15 passed / **2 failed**（剪贴板用例） | 5 passed / 0 failed     | `lib_exit=101 frame_exit=0 xproc_exit=0`                                                      |
| run6 | `a9d2eed`             | **17 passed / 0 failed**               | **5 passed / 0 failed** | `lib_exit=0 frame_exit=0 xproc_exit=0`                                                        |
| run7 | `ab42d44`（旧命令层） | 12 passed / 0 failed                   | 5 passed / 0 failed     | `lib_exit=0 frame_exit=0 xproc_exit=0 cmdcancel_exit=101`（命令层套件 3 过 **2 红**，预期红） |
| run8 | `8cb81c9`（main）     | **17 passed / 0 failed**               | **5 passed / 0 failed** | `lib_exit=0 frame_exit=0 xproc_exit=0 cmdcancel_exit=0`（命令层套件 **5/5**）                 |

run3 相比 run1 新增：`confirm_binding_tests` 5 例（确认绑定快照纯函数：确认 A→
重捕获 B 拒绝、清槽后在途请求拒绝、缺 snapshot_id 拒绝等）、剪贴板非文本清空
告警 1 例、跨进程**在途**销毁重建竞态 1 例（`fill-test-host` 竞态钩子：第一条
WM_SETTEXT 写入完成后、密码写入前，宿主在同一消息处理内同步销毁重建——注入
整体拒绝，重建窗口内密文零残留，宿主同进程读回交叉确认）。

run6 相比 run5 只改测试（`a68fd72`、`a9d2eed` 两笔，产品代码零改动）：两个
Windows-only 剪贴板用例的根因与修复见第四轮报告——非文本清空用例用
retry-until-non-empty 去读**期望为空**的剪贴板，给了 rdpclip 把上一用例的
`PREV-PANIC-*` 灌回来的整整 1 秒窗口；panic 路径用例注入的写入函数每次都
返回 Err，明文覆写先失败、闭包根本不执行，`closure panic must propagate
after restore` 只能红。run6 全绿同时覆盖第四轮新增的取消时序两例
（`slot_cleared/slot_replaced_after_first_write_aborts_remaining_write`）、
READBACK 长度前缀协议 6 例与跨进程竞态 5 例。

run7 是第五轮的红先行证据：套件本身在旧命令层上**可独立触发**
（`cargo test --features fill-test-host -p persona-fill-test --test desktop_fill_command_cancel`，
5 例全部真实执行、0 ignored），3 个门禁类用例在旧实现上也过，只有两个
mid-fill 时序用例红——红点就是「绑定比较后锁释放、写入前无字段级重查」这条
旧路径：断言 `mid-fill … must abort the fill`（`assert!(!resp.success)`）失败，
即命令返回成功、未报告中止；其后的密码读回断言未执行，日志不直接证明
密码落框。实现侧（`8642e9b` 起的逐字段重查）在 main 上，绿侧复验将随第五轮
报告 `docs/review/2026-11-06-desktop-fill-fifth-pass.md` 在后续提交归档。

## 判断结论：跨进程 WM_GETTEXT 读 ES_PASSWORD 是实测观察到的系统限制，注入本身真实成功

证据链（run1 实机探针 + run3 套件）：

1. 跨进程 `WM_SETTEXT` 对 ES_PASSWORD 控件返回非零（execute_fill Ok，含逐控件
   revalidate）——写入成功；
2. 跨进程 `WM_GETTEXT` 读同一 ES_PASSWORD 控件在 Server 2022 上返回空串
   （`WM_GETTEXTLENGTH` 同理返回 0）——读被系统隐藏。**口径（2026-11-06 第三轮
   收口）**：这是 openclaw Server 2022 的实测观察，套件只记录观察值，不硬断言
   「Windows 恒隐藏」为通用不变量；
3. 同进程读回（靶进程 `fill-test-host` 的 `readback` 命令，WM_GETTEXTLENGTH +
   WM_GETTEXT）返回的 username/password 与注入值逐字符一致（含西里尔 + emoji）
   ——注入成功的判据始终是靶进程同进程读回，不依赖跨进程读密码框；
4. 交叉验证：同窗口的普通 Edit 跨进程 `WM_GETTEXT` 读回正常（返回注入的
   username）——排除"靶进程/枚举/注入链路"因素，限制只针对 ES_PASSWORD 的
   跨进程读。

结论：前席观察到的"WM_SETTEXT 成功、username 可回读、password 读回为空"是
Windows 对跨进程读密码框的系统级隐藏，不是注入失败。注入成功的验证策略为：
WM_SETTEXT 返回值 + ES_PASSWORD 样式/`EM_GETPASSWORDCHAR` 跨进程断言 +
靶进程内同进程读回（hex 编码经管道打回，断言与注入值逐字符一致）。

## 判定过程备注

- run1 判定运行序列：`52096bb`（第一轮：xproc 仍 1 failed，但失败点已从"跨进程
  读回为空"前移到同进程读回断言，且 eprintln 留痕跨进程读为空串 → 判定成立）；
  `74ac75b`（补 `SendMessageW` 导入，靶进程编译通过）；`d601c14`（修正 hex
  解码 4 位/单元 + 跨进程读空固化为硬断言）→ 4/4 全绿，即 `run1-d601c14/` 日志。
- run3 运行序列：`7d9519c`（snapshot_id 绑定 + 在途竞态用例 + 告警补齐）首轮
  xproc 4/5——新竞态用例失败点在测试脚手架的 READBACK 帧解析（宿主销毁重建后
  两框为空是预期结局，帧只有 1-2 段被误判协议错误）；`a283573` 放宽解析后
  5/5 全绿，即顶层日志。**在途竞态用例在真机上验证的行为**：execute_fill 在
  username 写入完成、密码写入前因逐控件重验证失败而整体拒绝，重建出的同标题
  新窗口内 username/password 均为空（跨进程读 + 宿主同进程读回双重确认）。
