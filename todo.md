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


## 原型外部审查落地(2026-10-24,来源:用户「先保存到todo.md 然后开始执行」令,审查文件 docs/review/2026-10-24-persona-external-architecture-review.md)

- [x] R-P1 switchIdentity 改为服务端成功后才更新 UI,失败保留原身份并显示错误。验收:切换后端失败时 UI 身份不变且有错误提示,不再弹成功 toast。证据:desktop/src/hooks/usePersonaService.ts:322
  - 落地(commit `5883ec2`):switchIdentity 改为先 await `setActiveIdentity` 并查 `response.success`,成功才 `setCurrentIdentity` + `loadCredentialsForIdentity` + 成功 toast;失败保留原身份、`setError` + `toast.error`、返回 `false`;`silent` 只抑制成功提示,不抑制失败反馈。新增文案 `svc.switchFailed`(zh 切换身份失败 / en Failed to switch identity)。测试新增 success:false / 抛异常 / silent 失败三臂(失败时断言原身份不变、不拉目标身份凭据、不弹成功)。
- [x] R-P2 desktop/src/hooks/ 全目录排查同款乐观更新模式(先 setState 后 await 且吞异常),逐个修复。验收:列出排查清单与每处结论
  - 落地(commit `5fec32d`):排查清单表落 docs/review/2026-10-24-persona-external-architecture-review.md「R-P2 排查清单」(已修 5 处 + 判定无需修 9 类,含范围说明)。已修:`createIdentity` 激活失败(不再误报创建成功)、`useQuickAccessBridge` 跨窗跳转落库失败、`usePasskeyApprovals` / `useSshApprovals` 的 `respond`(改为服务端确认后才移出队列,失败留队列可重试 + toast,否则 Allow 静默丢失会让浏览器/agent 请求挂到 120s 超时),加 R-P1 的 switchIdentity。新增文案 `svc.activateIdentityFailed` / `svc.approvalRespondFailed`。desktop 56 套件 736 例全绿、eslint 0 warning、tsc 0 error、vite build 通过。
- [x] R-P3 Principal/Action 体系化设计文档,基于已有 principal/policy 代码(service.rs/connect/token.rs),不重做身份 CRUD。验收:文档落 docs/design/ 并过构建
  - 落地(commit `37ffc6d`):docs/src/design/principal-action.md + 中文对(/zh/design/principal-action),进侧栏。现状盘点(authz.rs 唯一裁决点 :143、4 变体主体/4 动词/4 资源/3 裁决、4 个已收敛调用点、机制层有意在外)+ 9 条缺口(写动词未拍板、ConnectTokenRow.principal 不透明未被消费、32 处 ensure_unlocked 旁路、裁决不进审计、AutoLockPolicy 表未接线、permissions.rs 死代码、Identity≠principal 术语冲突等)+ 分阶段方案(P0 清账/P1 写动词拍板/P2 本地会话收敛+principal 绑定激活/P3 Agent 委托),每阶段带验收;非目标区明确不重做身份 CRUD。同时纠偏过时的 docs/src/concepts/principal.md(中英对):「代码里没有 principals 表、没有按主体区分的授权规则」已不符 authz.rs 现状,改为「部分已实现」+ 指向设计文档。docs prettier+build 全绿
- [x] R-P4 跨进程统一会话/授权中心调研与方案(解锁状态/活动身份通知/权限撤销/用户确认)。验收:方案文档含现状调研
  - 落地(commit `4a0bb00`):docs/src/design/session-center.md + 中文对。现状调研六节全部带 file:line:解锁态每进程内存三字段无共享存放处(五处入口五份解锁态)、自动锁跑两遍互不相识(300s vs 900/3600,workspace 设置存而不读)、活动身份唯一持久层但桌面写入旁路 service 且零广播(emit_all 零命中、Connect 数据面零引用)、七类跨进程通道盘点(SQLite 是事实总线但无人监听)、撤销仅 connect token 一类、确认是两套重复 oneshot 仅桌面 webview 能答。15 条细节收敛为 5 个核心问题;方案取向「先无 daemon」(尊重 LOCAL_SERVICE.md 历史决定):Phase 1 状态外置(sessions 表+unlock_epoch 版本列每请求重读、lock() 补全、自动锁统一、活动身份收回 service、确认原语合并+socket 模式推广给 agent),Phase 2 可选桌面 hub 受限 RPC(与 R-P3 P3 汇合),验收场景 A1-A5 与 R-P6 矩阵对齐
- [x] R-P5 同步「局域网直传」命名与实现核对,名实不符则纠偏。验收:结论+改名 commit 或「名实相符」结论记录
  - 落地(核对属实,改名 commit `b100345`):**名实不符**。全仓无 P2P/mDNS/广播/多播,也无客户端侧同步 TCP 监听;同步只有客户端→persona-server 的 HTTP REST(`core/src/sync/remote.rs` `HttpSyncRemote` → `server/src/api/sync.rs` `/api/v1/sync/*`),目标地址就是设置里的 `SyncConfig.server_url`(`core/src/models/workspace.rs:54`)。「局域网直传」=同一 `persona-server` 绑定 `PERSONA_SERVER_HOST=192.168.x.x`,没有任何「直传」机制。已更名「局域网自建中转 / LAN self-hosted relay」(6 处文档)。误称只在文档里——UI 文案、CLI 子命令(本就无 sync 子命令)、配置键均无 LAN/direct,故零破坏、无需迁移;`sync.server_url` 键名保持不动(改名会静默丢用户已配服务器)
- [x] R-P6 端到端验收场景清单 + 跨平台能力矩阵(编译/模拟/真实交互/长期运行分层)。验收:文档落 docs/
  - 落地(commit `25662c9`):docs/src/development/acceptance-matrix.md + 中文对,进侧栏。四层判定标准(编译/模拟/真实交互/长期运行)+ 状态标签(沿用 AUDIT-061 四档+移动端两档);测试资产盘点(grep 口径 2026-10-24:Rust 行内 2,294+集成 73,JS 890,iOS 2 个 XCTest 从未执行,Android/Harmony/website/safari 0);10 条诚实边界(desktop/src-tauri 独立 workspace 不在根 clippy 内、iOS/HarmonyOS 从未编译、APK 从未真机跑、长期运行零覆盖、真实交互全在 CI 外、fuzz 不在 CI、Makefile release-* 悬空等);平台×四层能力矩阵;29 条端到端场景按审查成功标准分组(身份切换/上下文选择/统一授权/跨客户端一致性/安全回归/长期运行/移动端),每条带状态+验收条款+证据或缺口;待建清单 P1-P3(两客户端一 vault harness、soak 作业为最优先)
