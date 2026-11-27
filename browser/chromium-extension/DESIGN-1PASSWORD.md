# 1Password 扩展逆向分析（persona 扩展对标基准）

来源：imac（Windows 顶配机）Edge 158 Default 配置里的已装扩展。
- 扩展 ID `dppgmdbiimibapkepcbdbmkaabgiofem`，版本 `8.12.46.29`（MV3）
- 原始包 43.1 MB / 1008 文件，快照归档：本机 `~/.cache/onepass-re/ext/8.12.46.29_0/`
- 分析日期：2026-11-28。用途：设计语言与功能面对标；实现全部原创，不搬运其代码/字体（Inter、iAWriterMono 为授权字体，不可分发）。

## 1. Popup 架构骨架

- `popup/index.html` 只是壳：`<div id="root">` + `<div id="portal">`，全部 UI 由 JS 渲染（defer module）。
- 尺寸由 `set-popup-width.js` 决定：`body[data-width]` 两档——**double-pane 600px**（列表+详情双栏）/ **single-pane 350px**（窄窗单栏）。
- 主题：`[data-theme=light|dark]` 手动属性（217 条规则），**不依赖** `prefers-color-scheme`（应用内主题偏好下发）；配套 `--color-shading-on-light/on-dark` 两套变量族。
- 字体：Inter variable（UI）+ iAWriterMono（密码/数值等宽显示）。preload woff2。
- 严格 CSP：`default-src 'none'`，脚本仅 self，样式 self + unsafe-inline。
- 响应式：`data-viewport-size` 30 条规则（按弹窗可视高度切换密度）；`data-reduce-motion` 14 条（动画降级）；`[data-focus-visible]` 71 条（键盘焦点环只对键盘用户显示）。

## 2. 设计令牌系统（441 个 CSS custom property）

结构（值得抄的是分层，不是具体值）：
- **accent 色**：`--accent-color-{border,branding-bits,bright,readable,tint,focus-ring}` 一套派生六件套；亮蓝基点 `hsl(212,100%,57%)`。
- **边框三级 + 焦点**：`--border-01/02/03`（faint→strong）+ `--border-08`（交互高亮）+ `--border-focus-08`（focus ring）。
- **elevation 公式**：`0 0 0 1px <fill-ring> , 0 2px 8px <shadow>`——**ring+shadow 组合**（先描一圈近背景色解决"阴影在深底上消失"），01/02/03 三档。
- **shading 五档**：heavy / medium / faint / extra-faint / barely-there（分隔线、遮罩、hover 层全用同一族）。
- 圆角：控件 `8px`，圆形件 `50%`，比例令牌 `--border-radius-ratio: 5`。
- 亮暗切换靠变量族换绑，组件规则零重复。

## 3. UI 面清单（文件即地图）

| 面 | 文件 | 作用 |
|---|---|---|
| popup | `popup/` | 工具栏弹窗（主脸） |
| app 全页 | `app/` | 整页模式（vault 全管理） |
| inline menu | `inline/menu/` | 输入框聚焦的下拉填充菜单 |
| inline modal | `inline/modal/` | 页内弹层（保存提示等） |
| inline notification | `inline/notification/` | 页内通知条 |
| universal-sign-on | `inline/universal-sign-on/` | SSO/通用登录接管 |
| tooltip / tutorial | `inline/tooltip/` `inline/tutorial/` | 引导与提示 |
| devtools panel | `devtools/` | 开发者面板 |
| 注入样式 | `inline/injected/styles/` | 页内全量样式基座 |

内容脚本架构：`all_frames: true` 起手（bootstrap 注入器 + MAIN world webauthn 钩子 + 监听器分离），`document_start`；MV3 module service worker（3.2MB）+ `declarativeNetRequest` + `nativeMessaging`（连桌面 app）。

## 4. Popup 功能面（对标目标）

1. **当前站建议优先**：打开即显示适用于当前站的登录项（一键 fill），这是第一屏主内容。
2. **搜索即一切**：顶部搜索框 type-to-search 全 vault；键盘 `↑↓` 移动、`Enter` fill、`Esc` 返回。
3. **双栏**：左列表右详情；详情含字段 copy、TOTP 实时码、密码显隐。
4. 分类导航：All Items / Logins / Documents / Tags / **Watchtower**（弱口令/复用/缺 2FA 健康面）。
5. 生成器：密码/口令短语，长度滑杆、字符集开关、发音友好选项。
6. 设置：autofill 行为开关、锁定超时、快捷键展示。
7. 状态常驻：锁定态、账户态、连接态浓缩在顶部条。

## 5. persona 现状 gap（2026-11-28）

- popup = 320px 调试控制台：八个裸 section（Bridge/Pairing/Autofill/Cloud/Account/设置/域策略/表单）平铺。
- **生成器逻辑已在 popup.ts（`gen*` 9 个 id）但 HTML 无标记**——功能从未露出。
- 引擎面反而齐全：桥接配对、云 vault、TOTP 链填、域策略、保存提示、passkey 桥——缺的是"脸"。
- 无主题令牌、无搜索、无键盘导航、无双栏。

## 6. 实施计划

- **Phase 1（换皮不改脑）**：重排 popup.html 为 double-pane 600px：左栏 = 搜索 + 当前站建议 + vault 项列表 + 生成器；右栏 = 可折叠"操作台"（全部既有 41 个 id 原位保留进分区）。令牌 CSS 独立 `popup.css`（亮暗双主题，prefers-color-scheme 默认 + data-theme 手动覆盖）。popup.ts 只加：主题初始化、分区切换、搜索过滤（不动既有逻辑）。
- **Phase 2（行为补齐）**：列表键盘导航、选中详情栏、TOTP 实时码显示、copy 动作快捷键。
- **Phase 3（页内面）**：注入菜单/通知条按令牌系统重做（shadowUi.ts）。
- 生成器、TOTP、域策略等既有引擎行为保持不变，Phase 1 仅视觉与信息架构。
