# BUGS

用户实测报障登记。按优先级排列，修复后随行更新状态。

---

## P0-① SSH agent 点「启动」无法启动（用户复测仍失败）

- **现象**：Windows 下点击启动 SSH agent，报 `SSH agent failed to start: a global default trace dispatcher has already been set`；此前「点了没效果」疑似同族。
- **根因**：`agents/ssh-agent/src/daemon.rs` 的 `run_agent_with_hooks` 启动即 `RedactedLoggerBuilder…init()?`；desktop 壳（`desktop/src-tauri/src/lib.rs::init_desktop_logging`）在 setup 最前已装全局 subscriber，二次 `try_init` 返回 Err 被 `?` 当致命错误上抛 → `commands.rs` 的 startup_error 槽位 → UI 报启动失败。
- **修复方向**：① core `logging.rs::init` 幂等（占用 = 保持已装返回 Ok）；② daemon 启动链路日志初始化错误一律不当启动失败。
- **状态**：修复中。Windows 实机全链（点启动→agent 真起来→状态已启动→重启 app 仍正常）待用户复测；若 trace 修复后仍有第二层根因（进程/端口/权限/杀软），继续挖。

## P0-② 自动锁定后操作直接报「Authentication failed: Session is auto-locked」

- **现象**：密码箱自动锁定后做操作，报认证失败，用户被堵死。
- **正确行为**：引导解锁——弹解锁输入框，解锁成功后原操作继续/可重试。
- **范围**：全 app 排查同族路径（凡需解锁的操作统一处理）。
- **状态**：待修。

## P1-③ 库中的 SSH 密钥条目缺「删除」「编辑」操作

- **现象**：每条 SSH 密钥无删除/编辑入口。
- **要求**：删除需二次确认（不可恢复数据防误删）；编辑至少可改标签/注释等元数据，私钥本体不默认展示。
- **验收**：列表出现两操作 → 编辑改标签保存生效 → 删除确认后消失。
- **状态**：待修。

## P1-④ 生成 SSH 密钥弹框 comment/名称输入框看不清

- **现象**：输入框对比度不足（暗色主题下占位符灰字贴灰底/输入文字与背景同色）。
- **要求**：边框/背景/占位符/输入文字在亮暗两主题都清晰可辨；对照设置页正常输入框样式找漏配 token。
- **验收**：两主题截图确认。
- **状态**：待修。

## P2-⑤ 库中 SSH 密钥列表不显示密钥类型

- **现象**：无类型徽标（算法+位数/曲线，`ssh-keygen -l` 风格：ED25519 256 / RSA 4096 / ECDSA P-256）。
- **要求**：从公钥元数据解析；列表行或详情可见；导入与新建两路径都正确识别。
- **备注**：列表已有「类型 / 指纹」列（线格式算法名+SHA256 指纹），本项增量是位数/曲线徽标。
- **状态**：待修。

## P2-⑥ PEM 格式 SSH 密钥无法导入

- **现象**：PEM 系私钥（BEGIN RSA PRIVATE KEY / BEGIN EC PRIVATE KEY / BEGIN PRIVATE KEY）导入失败。
- **现状**：主体已闭环（PKCS#8/PKCS#1/SEC1 + PBES2 加密件 + PPK 明确拒绝，25 个 core 测试真实 openssl fixture 覆盖）。剩余核对：格式识别错误的提示要点名「哪个头不认识、期望什么格式」；导入+新建两路径的类型徽标识别随 P2-⑤ 一并验收。
- **状态**：核对中。
