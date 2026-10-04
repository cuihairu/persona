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
- **修复**：① 后端惰性锁定（操作时才查超时、无 locked 事件）撞 `SERVICE_LOCKED` → `utils/api` 统一 invoke 出口拦截该错误码（免解锁命令白名单除外），弹 `UnlockGateModal` 引导解锁，成功后原命令自动重试一次，取消按原错误返回——全 app 所有 invoke 路径统一生效，无需逐处适配。② 解锁弹期间全局 `isLoading` 会把主 UI 拆成全屏 spinner，重挂后 `CredentialList` 的「选中悬空即清」effect 连带清掉用户选中与详情面板——App 的 spinner 分支收窄为 `isLoading && !isUnlocked`（解锁态写操作不再拆主 UI，选中态保住）。
- **状态**：已修（walk 走查 15/15：撞锁→弹框→解锁→原操作自动重试→详情面板与选中保持；`revealed: 'reveal-pw-9'` 复现绿）。

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

## P1-⑦ SSH agent 启动按钮启动后仍可点（用户以为能重复启动）

- **现象**：启动成功后「启动」按钮不变灰，仍可点击，用户以为没启动成功反复点。
- **修复**：启动成功（running）后按钮禁用置灰；文案三态联动（启动中…→运行中→停止后恢复「启动」）；重复点击物理禁掉；服务状态与按钮状态严格联动（状态轮询/停止后自动恢复可点）。
- **状态**：已修（`disabled={isStarting || running}` + 三态文案；jest 断言 disabled/文案双态；走查截图三态×亮暗两主题：默认可点/启动中置灰「启动中…」/运行中禁用「运行中」+停止恢复可点）。

## P2-⑧ SSH agent 停止/刷新按钮不像按钮（无边框无底色）

- **现象**：停止/刷新按钮用 ghost 样式，外层无边框无底色，静态看不出是按钮，用户找不到。
- **修复**：区块级显性操作统一升 btn-secondary（含本面板生成/导入/重新加载与 Passkey 详情面板自检/导出/删除）；btn-secondary 样式系统补边框与按下态，三档按钮（primary/secondary/ghost）按下反馈统一；模态框取消键与行内小按钮保留 ghost。
- **验收**：三个按钮（启动/停止/刷新）默认/运行中/禁用三态截图；与启动按钮同一套样式系统。
- **状态**：已修（区块级显性操作统一 btn-secondary，含边框/底色/悬浮/按下态；同批升级 Passkey 详情三键与 Watchtower 重扫描；模态框取消键与行内复制小钮保留 ghost。走查截图三态×亮暗两主题确认样式统一）。
