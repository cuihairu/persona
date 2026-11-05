# 桌面应用内填充注入（Windows）

一句话：用户在 Quick Access 检索浮窗选中凭据后，Persona 把用户名/密码注入到
**浮窗唤起之前**持有前台的那个应用窗口——浏览器扩展填充的桌面应用兄弟篇
（FEATURE_GAP_ANALYSIS #12）。

## 范围（诚实边界）

- **填充归目标侧**：浏览器里的填充仍归浏览器扩展（Native Messaging 桥，
  #22）；本路径只服务原生桌面应用。自绘 UI 工具包（Electron、Qt、浏览器）
  不覆盖，见"注入选型"。
- **仅 Windows**。Linux/macOS 上命令如实报"未实现"，不假装
  （`fill_supported()`）。
- **仅 Password 类型凭据**（用户名 + 密码两个字段）。

## 注入选型

| 方案 | 结论 | 理由 |
| --- | --- | --- |
| **WM_SETTEXT 直写**（选定） | 首选 | 不依赖焦点、不模拟键击，同一桌面会话内跨进程可靠；可自动化验收。仅适用经典 Win32 EDIT 控件。 |
| 剪贴板中转（Ctrl+V） | 备选，已实现 | 兜底吃键盘事件校验的应用；粘贴前备份剪贴板、粘贴后立即恢复，密文暴露窗口只有粘贴闭包期。不做首选：跨进程聚焦受系统前台锁约束。 |
| UI Automation | 不做 | 可覆盖自绘控件，但引入 `Win32_UI_Accessibility` + COM 生命周期管理；作为后续扩展点记录，不留空壳桩。 |

## 字段选择

对目标顶层窗口 `EnumChildWindows`，只留类名 `Edit` 的子控件：

- 用户名 = 第一个非密码样式的框；
- 密码 = 第一个 `ES_PASSWORD` 样式的框；
- 没有密码样式框但 ≥2 个输入框 → "第二个框"启发式；
- 全部是密码样式框（改密对话框）→ 拒绝注入。

## 目标捕获与重验证

浮窗 show 路径在**拿焦点之前**捕获 `GetForegroundWindow`（pid 必须不同于
Persona 自己）。快照（hwnd + 标题 + pid）存 `AppState.fill_target`。注入时
重验证：`IsWindow`、pid 一致、当前标题仍是快照标题的前缀——防 HWND 复用。
失效目标即刻丢弃，用户拿到如实报错。

## 密文卫生

- 用户名/密码走与 `reveal_credential_secret` 相同的解密路径（审计 + re-auth
  门禁）；不新增明文缓存。
- 剪贴板中转备份并恢复原内容；失败如实作为警告上浮，绝不静默。
- WM_SETTEXT 是默认路径——完全不碰剪贴板。

## 代码位置

- `desktop/src-tauri/src/desktop_fill.rs` —— 注入引擎 + Windows 集成测试
  （真实窗口 + 真实 EDIT 控件，WM_GETTEXT 读回验证）。
- `desktop/src-tauri/src/quick_access.rs` —— 浮窗 toggle 路径里的目标捕获。
- `commands::fill_target_status` / `commands::desktop_fill_credential` ——
  命令层；浮窗绑定 ⌘F 填充（含 i18n 提示）。
