# openclaw 真机证据：桌面填充跨进程套件 4/4 全绿（2026-11-06）

- 环境：openclaw（Administrator@10.240.0.3，Windows Server 2022 x64，msvc +
  RUSTUP_TOOLCHAIN=stable，交互式控制台会话经计划任务 `PersonaFillTest`（/IT）执行；
  SSH 会话中 IsWindowVisible/GetForegroundWindow 失效，不可用于本套件）。
- 代码：HEAD `d601c14`（跨进程读回断言定案三连：`52096bb` readback 定案 +
  `74ac75b` 导入修复 + `d601c14` hex 解码与守卫断言）。
- 结果：
  - lib 套件 `cargo test --lib desktop_fill`：**6 passed / 0 failed**（filltest-lib.log）；
  - 跨进程套件 `cargo test --features fill-test-host -p persona-fill-test
--test desktop_fill_cross_process`：**4 passed / 0 failed**（filltest-xproc.log）；
  - 退出码标记 filltest.done：`lib_exit=0 xproc_exit=0`。

## 判断结论：跨进程 WM_GETTEXT 读 ES_PASSWORD 是 Windows 系统限制，注入本身真实成功

证据链（本轮实机探针 + 修复后套件）：

1. 跨进程 `WM_SETTEXT` 对 ES_PASSWORD 控件返回非零（execute_fill Ok，含逐控件
   revalidate）——写入成功；
2. 跨进程 `WM_GETTEXT` 读同一 ES_PASSWORD 控件恒返回空串（`WM_GETTEXTLENGTH`
   同理返回 0）——读被系统隐藏（套件内已固化为硬断言）；
3. 同进程读回（靶进程 `fill-test-host` 的 `readback` 命令，WM_GETTEXTLENGTH +
   WM_GETTEXT）返回的 username/password 与注入值逐字符一致（含西里尔 + emoji）；
4. 交叉验证：同窗口的普通 Edit 跨进程 `WM_GETTEXT` 读回正常（返回注入的
   username）——排除"靶进程/枚举/注入链路"因素，限制只针对 ES_PASSWORD 的
   跨进程读。

结论：前席观察到的"WM_SETTEXT 成功、username 可回读、password 读回为空"是
Windows 对跨进程读密码框的系统级隐藏，不是注入失败。注入成功的验证策略改为：
WM_SETTEXT 返回值 + ES_PASSWORD 样式/`EM_GETPASSWORDCHAR` 跨进程断言 +
靶进程内同进程读回（hex 编码经管道打回，断言与注入值逐字符一致）。

## 判定过程备注

- 判定运行序列：`52096bb`（第一轮：xproc 仍 1 failed，但失败点已从"跨进程
  读回为空"前移到同进程读回断言，且 eprintln 留痕跨进程读为空串 → 判定成立）；
  `74ac75b`（补 `SendMessageW` 导入，靶进程编译通过）；`d601c14`（修正 hex
  解码 4 位/单元 + 跨进程读空固化为硬断言）→ 4/4 全绿，即本目录日志。
