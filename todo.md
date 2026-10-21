# TODO

- [x] 缺陷：一键启用后，配置的按钮开关状态未联动（来源：用户 2026-10-14，登记 `66d0091`；2026-10-14 修完 `9abce66` 前端回读 + `dc6021c` 落盘往返测试）
  - 现象：执行「一键启用」之后，**配置里的按钮/开关状态没有跟着一起变动**（界面显示与实际启用状态不一致）
  - 风险定性：**显示与真实状态不一致**，比单纯显示错误更危险——用户会据此误判服务是否已启用
  - 验收：先复现并给根因 file:line（重点怀疑：一键启用的批量操作完成后**没有回读真实状态**、只改了本地 UI 状态、或回读结果未广播到各配置项的开关组件）；修复后**以真实状态为准刷新**，并在真实连接下验证一键启用/停用后所有相关开关一致
  - 提示：不要只在 UI 层补一次状态刷新——要确认**批量操作后存在统一的状态回读点**，否则同类不一致会再次出现
  - 根因：`desktop/src/components/SshIntegrationSection.tsx:64-98` 的 `apply()` 渲染**写入响应的快照**（`setStatus(resp.data)`）且把状态刷新 `void refreshAnalysis()`（不 await）——组件唯一的统一回读点 `refresh()`（:39-48，状态 + 配置分析一起回读）在变更后**从未被调用**；写入响应快照与盘上状态漂移（响应迟到/为空、外部并发改 config）时界面就停在旧值。**后端不是根因**：`commands.rs:5368-5410` 两个写命令落盘后都重跑 `ssh_agent_integration_status()` 回读。
  - 修法：`apply()` 成功后 `await refresh()` 走统一回读点（状态行、启用/停用按钮文案、配置分析面板同批刷新），不新增旁路刷新函数；写入失败不触发回读（无变更），保持原状态。
  - 验证：前端 14 测试全绿（含 2 条新回归：回读优先于响应快照、回读把配置分析面板一起带到最新；把 `apply()` 还原成旧实现后这 2 条如期红）；后端新增 `desktop/src-tauri/tests/ssh_integration_roundtrip.rs` 3 测试——HOME 指向临时目录**真写真读** `~/.ssh/config`，启用→回读 `enabled=true`、重复启用不产生第二个锚点块、停用→回读 `enabled=false` 且用户原配置原样保留、外部改指别处后如实报 anomaly 而非谎报已启用、读不出 config 时拒写；tsc/eslint 干净。

- [x] 缺陷：右键菜单未国际化（来源：用户 2026-10-14；2026-10-14 修完 `4b0ebac`）
  - 现象：**右键菜单（上下文菜单）文案是硬编码中文/英文，没走 i18n**，与其余界面语言不一致
  - 验收：右键菜单所有条目**纳入本仓既有 i18n 体系**（**不另起一套**，先核 i18n 机制怎么做的并给 file:line）；切换语言后右键菜单同步生效；覆盖所有触发右键的位置（列表项、空白处等），不只修一处
  - 排查：全仓 grep（排除 target/node_modules/dist）证伪 webview 内与浏览器扩展的自定义右键菜单（`onContextMenu`、`chrome.contextMenus` 均零命中）——**唯一应用自持右键菜单是系统托盘**（`desktop/src-tauri/src/lib.rs` `setup_tray`，5 条英文硬编码）。既有 i18n 机制：`desktop/src/i18n/index.ts`（i18next + initReactI18next，内联同步资源，DEFAULT_LOCALE=zh-CN）+ `desktop/src/i18n/locales/{zh-CN,en}.ts`。
  - 修法：真值源进既有 locale 表（新增 `tray.*` 命名空间，两语言各 5 键）；Rust 只渲染不存词——`set_tray_locale` 无状态命令（无锁屏门禁：锁屏时菜单也要跟界面语言）按推送文案重建菜单，setup 兜底 zh-CN 默认（与 DEFAULT_LOCALE 一致，前端首推即覆盖）；推送点 = App 启动语言恢复 ×2 + SettingsModal 切换成功。**坑**：组件级 `t` 是 `getFixedT` 旧语言快照（react-i18next useTranslation.js:76），切换后立刻推会推旧语言 → 推送处一律用全局 `i18n.t`。
  - 验证：jest 80 绿（新增回归 3：切换后推英文真值——旧实现（用组件级 t）实测红；持久化失败不推送并回滚 UI）；`cargo test --lib` 265 绿（新增 `set_tray_locale_is_harmless_noop_without_tray`：无托盘降级运行无害 no-op）；tsc/eslint/cargo fmt/clippy 干净。

- [x] 文档首页预览图拆分：电脑版 / 手机版分开展示（来源：用户 2026-10-14；2026-10-14 修完 `8f9ab29`）
  - 现状：`README.md:39` 有 `## UI Preview`，**未按设备分栏**；仓库内无 `docs/screenshots/` 目录
  - 要求：预览拆成**电脑版**与**手机版**两组分别展示，各自标注设备/尺寸，**截图取自真实运行界面**（不是示意图）
  - 验收：两组截图清晰可辨、路径相对引用、首页直接可见
  - 落地：`## UI Preview` 下分 `### Desktop — 1600×1000 window（2× DPR 截图，3200×2000 px）` 与 `### Mobile — Android phone, 1080×2400 px` 两组（README.md 与 README.zh.md 同步拆分）；截图全部用仓库已有的真实运行截图（docs/branding/ui/ 4 张桌面 + 4 张 Android 真机，mobile 截图逐张目检确认为真实运行界面：解锁页/凭据列表/工具/设置，zh-CN 默认语言深色主题），相对路径引用、首页直出，逐张核验 src 引用全部存在。
- [x] 文档双语未落地（来源：用户 2026-10-14；README 部分 `012c466` 已落地，docs 部分 2026-10-14 修完 `7087914`）
  - 现状：`README.md` **377 行单语英文**，无 `README.zh.md`
  - 要求：按全局规矩——**英文为 README 主文档**，中文转 **`README.zh.md`**，两份**顶部加切换器**（`> **English** | [中文](README.zh.md)` / `> [English](README.md) | **中文**`），切换器必须在首屏
  - 覆盖范围：**README 及 docs 下文档**（用户点名"文档没有双语"，不止 README）；中文版要完整对应，不是摘要
  - 验收：zh 行数与 en 相当；逐节覆盖；顶部切换器两份都有
  - 落地：README 对（`012c466`，375/379 行，切换器 ：17 首屏）之外，docs/ 下 30 个英文工程文档全部补 `*.zh.md`（7582 行新增），每个 en 文件标题后插入 `> English | 中文` 切换器、每个 zh 文件首行 `> English | **中文**`（与 README 同款）；术语表统一（保险库/凭据/分身/桥/主密码等），代码块/命令/路径/URL/内联代码原样保留；`审计-文档一致性.md` 本就是中文，不重复。逐对核验标题数一致、首行格式正确、无 AI 痕迹字样；docs 门禁全绿（prettier 3.6.2 --write 后 diff 干净 + VitePress build 死链检查通过）。

