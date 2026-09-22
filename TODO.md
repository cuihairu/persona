# Persona Monorepo TODO

This is the master checklist for Persona's mainline product: local-first identity-material management with strong browser, desktop, CLI, and SSH workflows. Keep this file aligned with `BOUNDARY.md`.

Priority policy (2026-09): the password-manager track targets 1Password parity first. The wallet track is paused until that feature set is complete — wallet mistakes are irreversible (funds, not accounts), so wallet-grade security must be built on a proven vault foundation.

Now (current sprint)
- [x] CI: GitHub Actions (Rust fmt/clippy/test; Desktop lint/test)
- [x] Architecture diagram in docs (core/service/storage/agents/desktop/server)
- [x] CLI: identity edit/remove wired to DB
- [x] CLI: switch active identity (persist `active_identity_id`, maintain history)
- [x] Core: workspace schema v2 (persist `path`, `active_identity_id`, `settings`) + migration
- [x] Audit: emit logs from service/CLI for identity CRUD and switch
- [x] CLI: migrate command to apply DB migrations and ensure workspace row

Monorepo & Tooling
- [x] Rust workspace crates (core, cli, server, mobile/rust)
- [x] JS workspace for desktop (root `package.json`)
- [x] Add SSH Agent crate skeleton (`agents/ssh-agent`)
- [x] CODEOWNERS + PR template + Conventional Commits
- [x] Makefile targets for build/test/lint across all packages
- [x] 文档：整理统一客户端通信架构（CLI/桌面/浏览器/Agent 依赖同一个本地服务/IPC 协议）
- [x] 文档：说明本地服务 IPC 优先使用 Unix Socket（含 Windows 支持，必要时回退 Named Pipe）

Security & Auth
- [x] Key hierarchy: per-item keys wrapped by master key
- [x] SRP-like remote auth abstraction (prep for server)
- [x] Biometric unlock hooks (Touch ID/Face ID/Windows Hello)
- [x] Auto-lock timers and “re-authenticate for sensitive ops”
- [x] Secrets redaction policy for logs

Storage & Data
- [x] Workspace v2 schema + migrations and CLI migration command
- [x] Item versioning (identity/credential change history)
- [x] Attachments blob store (file chunks + refs)
- [x] Export/Import with compression + encryption + integrity checks

CLI
- [x] add/list/show wired to DB with unlock flow and fallback when no user
- [x] edit/remove identity (完整实现:交互式编辑、字段验证、备份、审计日志)
- [x] switch (activate/deactivate, history, config persistence)
- [x] credential CRUD (filters: type/tag/active/favorite)
- [x] TOTP: setup via QR + code generation
- [x] password generator options (length, symbol sets, pronounceable)
- [x] TUI mode (ratatui/crossterm)
- [x] Non-interactive CI mode with environment variable injection

SSH Agent (developer focus)
- [x] UNIX socket server implementing SSH agent protocol (list/add/remove/sign)
- [x] UNIX socket server MVP: request_identities/sign_request (ed25519), loads keys from vault
- [x] Windows named pipe support (cross-platform transport abstraction)
- [x] Key management (create/list/remove), store in core with metadata
- [x] Per-host/per-command policies; confirmation prompts
- [x] Basic confirmation prompt gating via env `PERSONA_AGENT_REQUIRE_CONFIRM`
- [x] Rate limiting via env `PERSONA_AGENT_MIN_INTERVAL_MS`
- [x] CLI control: start/stop/status, query agent identities
- [x] Known hosts policy (optional): env `PERSONA_AGENT_ENFORCE_KNOWN_HOSTS`, wrapper `persona ssh run --host <h> -- <cmd>` to pass host, confirm-on-unknown via env `PERSONA_AGENT_CONFIRM_ON_UNKNOWN`
- [x] Biometric gating for signing (with fallback to confirmation)
- [x] Comprehensive policy system (TOML-based configuration)
  - [x] Global policies (deny_all, rate limits, known_hosts enforcement)
  - [x] Per-key policies (allowed/denied hosts, time ranges, daily limits, biometric requirements)
  - [x] Per-host policies (allowed keys, confirmation requirements, hourly limits)
  - [x] Glob pattern matching for hostname restrictions
- [x] E2E tests for SSH protocol encoding/decoding
- [x] E2E tests for agent request_identities and GitHub connection
- [x] CLI commands: `persona ssh import|generate|list|list-all|export-pub|add-to-agent|start-agent|stop-agent|agent-status|run|remove`
- [x] Complete README documentation with usage examples
- [ ] Full E2E test: manual testing with real `ssh -T git@github.com` (requires user setup)
- [ ] Windows-specific testing and optimization

Wallet Material (experimental — deferred until 1Password parity; see priority policy above)
- [x] Wallet models: mnemonic/seed, HD paths, chain metadata, watch-only
- [x] Derivations: BTC (BIP32/44, P2WPKH/P2SH-P2WPKH/Taproot), ETH (SLIP‑44), Solana (SLIP‑0010 ed25519, path `m/44'/501'/0'/i'`, Phantom 兼容)
- [x] Address encoding: BIP‑173 bech32 / BIP‑350 bech32m (P2WPKH/P2WSH/P2TR)、Base58Check、EIP‑55 checksum
- [x] Import (mnemonic/private key) & export with confirmations; WIF 已支持（mainnet compressed，`import --wif` 及私钥导入自动识别）；keystore JSON 仍待做
- [x] Sign: ETH (EIP‑155 legacy + EIP‑1559 dynamic fee, 字节级规范向量/结构自洽验证)、Solana (ed25519, 签名即 tx id)；本地签名验证后再持久化
- [x] Sign: BTC raw transaction (BIP‑143 P2WPKH + BIP‑141 segwit 组装, 官方规范向量逐字节验证) — 需 UTXO `inputs` metadata；无 inputs 时仅存审计签名；PSBT 仍待做
- [x] 签名/编码层全面换用审计过的第三方库：交易序列化与签名哈希 → `alloy-consensus`（EVM）/ `rust-bitcoin`（BTC，`SighashCache::p2wpkh_signature_hash`）、地址编码 → `bech32` crate（BIP‑173/350）/ `bs58`(check) / `alloy-primitives`（EIP‑55）、WIF 解析 → `rust-bitcoin`；手写 RLP/BIP‑143/wire 组装已删除，官方规范向量保留作回归验证（SLIP‑0010 ed25519 派生暂无成熟库，保留自研）
- [x] CLI: wallet create/import/derive/list/sign (`create-transaction --sign`)
- [x] Desktop: wallet overview, address lists, QR, signing confirmations

Desktop (Tauri v2 + React)
- [x] Wire Tauri commands to core (unlock, lists, CRUD)；50+ 命令全量接线
  （identity/credential CRUD、TOTP、搜索、统计、SSH agent、钱包 9 命令、
  auto-lock、审计查询/统计/清理、passkey 7 命令、导出、敏感字段 reveal、re-auth、
  钱包交易 create/sign、SSH 签名审批应答）
- [x] Tauri v1.5 → v2 迁移（capabilities 权限模型、tauri-plugin-clipboard-manager、
  tauri-plugin-notification、官方迁移器 + 人工核对）
- [x] TOTP 下沉 core（RFC 6238 向量，桌面/CLI 共用同一路径）
- [x] ApiResponse 错误码协议（REAUTH_REQUIRED / SERVICE_LOCKED 分流）
- [x] Auto-lock 全链路：core 事件 → emit `persona://auto-lock` → 前端倒计时横幅 +
  回解锁屏；Locked 事件后端强制落锁（清内存主密钥，不依赖前端存活）
- [x] fix: `require_reauth_sensitive` 开关真正生效（2026-09 命令级测试发现）
  — `configure_auto_lock` 此前只改超时副本，管理器配置不可变导致敏感操作
  再认证闸门从未开启；现经 `AutoLockManager::update_base_config`（同步
  RwLock 原地更新）传递，`AutoLockConfigRequest` 透传 sensitive 窗口；
  `authenticate_user` 登录即记敏感活动（否则开闸后首个敏感操作被闸且
  无法自愈）；端到端：开闸 → 登录放行 → 窗口过期 REAUTH_REQUIRED →
  再认证恢复
- [x] Vault/identity/credential views; search; 三维筛选（类型/标签/仅收藏）
- [x] TOTP display; password reveal flow（re-auth 闸门 + 30s 自动隐藏 + copy-once
  clipboard）；SshKey/ApiKey/BankCard 分支渲染
- [x] SSH Agent control & signing approvals：ApprovalHandler 接缝（agent crate 无
  tauri 依赖）→ DesktopApprovalHandler（emit `persona://ssh-approval` + oneshot，
  120s 超时自动拒绝）→ SshApprovalModal；CLI 走 TTY 提示零改动；失焦系统通知
- [x] Wallet UI (addresses, QR, signing confirmations + 地址投毒启发式告警)
- [x] Desktop 集成测试矩阵扩展（2026-09-20 验收勾选：134 个 Rust 测试
  （129 lib 单测 + 5 集成）全绿；总体行覆盖 ~91.1%（lib 化前 89%）；commands.rs ~90.6%、
  types.rs 100%、passkey_bridge ~97.4%、approval ~96.5%；命令级集成测试
  基建已建：`command_layer_tests.rs` 经 `tauri::test::mock_app` 直驱 50+
  命令处理器，含 wallet 交易 create/sign 多链路径、SSH agent start/stop
  生命周期、passkey 审批 serve_on 端到端（真 Unix socket）+ service 层
  passkey_assertion（last_used_at 时间戳回写）、锁定态 SERVICE_LOCKED
  矩阵、**坏库 service 批测**（sqlx 惰性连接：手工构造已解锁但 DB 为
  垃圾文件的 service，驱动 init_service 无法到达的各命令 repo 错误臂）、
  init 幂等（existing-user 再认证 + 错密码拒绝 + 账号锁定）、wallet 五命令
  前置臂 × 死库矩阵、active identity 前置臂矩阵、AddressType 标签全臂、
  passkey_create 非法 base64 门。**lib 化**（src/lib.rs + 薄 main.rs +
  `tests/desktop_integration.rs` 独立进程）解锁：TauriApprovalSink 真
  emit 全链路（真 socket → 真事件 → passkey_approval_respond → 应答回
  socket）、锁定直接应答不弹 GUI、show_main_window 有/无窗口双臂、
  build() 整链装配（mock context + run_iteration 驱动 setup：AppState
  manage、审批服务端 spawn + socket 0600、托盘按显示会话分流）。
  剩余不可达（~9%）：setup_tray ~40 行（muda 菜单直连 GTK，需真实显示
  服务器，mock runtime 管不到）、run() 事件循环、commands.rs 防御臂
  （恒 Ok 方法的 Err 分支、签名后本地 verify 拒绝臂、emit 失败臂）——
  91% 即可达上限）
- [x] fix(desktop): lib 化顺带修复无显示会话启动崩溃（2026-09 测试发现）
  — muda 菜单/托盘不经 Runtime trait 直连 GTK，DISPLAY/WAYLAND 缺失时
  `gtk::Menu::new` 直接 panic；现 `display_session_available()` 守卫下
  降级为无托盘运行（审批链路不依赖托盘存活），有显示环境行为不变；
  另 `default_window_icon` 缺失时回退 `include_image!` 内嵌图标（原
  fail-fast panic 改为回退，dev/测试环境更稳）
- [x] 产品缺口：`password_change_required` 强制改密闭环（2026-09 落地）：
  `WorkspaceSettings.password_expiry_days`（None=不过期，opt-in，NIST 取向）
  + `user_auth.password_updated_at`（迁移 012 回填）；解锁时 core 策略引擎
  lazy 置位（读设置失败 fail-open）；`PersonaService::change_master_password`
  单事务轮换（credentials wrapped key 重包 + legacy 行重加密 + passkeys
  重包 + user_auth 复位，argon2/PBKDF2 全在事务外，回滚测试覆盖）；desktop
  强引导弹窗（解锁屏 forced 模式 PASSWORD_CHANGE_REQUIRED 码分流）+ Settings
  安全区块（Never/90/180/365 + 手动改密后回锁屏）+ CLI `persona passwd`
  （新密码仅交互，不设 env）；wallets（独立钱包密码）不受影响
- [x] Desktop 前端 23 个测试文件 tsc 类型本底（2026-09-20 验收勾选：
  tsconfig include src 无 exclude，`./node_modules/.bin/tsc --noEmit
  -p tsconfig.json` 全量 exit 0——i18n 断言批次起每轮改动均复跑；
  当年发现的 fixture 类型问题（`url: null` vs
  `url?: string`、缺 timestamp/SshAgentStatus 形状、`"private_key"` 非法
  SecretField 等）已在后续 fixture 工厂类型标注中消化。注意
  `npx tsc` 会拉到 npm 同名占位包返回假 0，永远用
  `./node_modules/.bin/tsc`）
- [x] fix(desktop): init_service 持锁调用 register_auto_lock_bridge 的死锁
  （tokio Mutex 非重入；2026-09 命令级测试发现并修复）
- [x] 前端测试第一批~三批（2026-09，jest 30 + testing-library）：115 → 202 测试，
  覆盖率 48.13% → 77.62% statements（branches 34.54→62.71、functions
  41.16→72.7、lines 47.71→77.91）。api.ts 55 方法 invoke 映射全量断言、
  usePersonaService 全 action 成功/失败/异常臂、useAutoLockEvents 事件流 +
  节流回传、clipboard fallback 链、TransactionConfirmModal 签名全流程 +
  地址投毒告警、CreateCredentialModal 全类型分支 + otpauth URI 解析、
  useReauth/ReauthModal promise 化重认证、RevealSecretButton REAUTH 重试编排
  （mock useReauth，绕开 jsdom act 外 modal 限制）、App.tsx 六视图切换 +
  auto-lock 横幅 + 审批弹窗 + statistics。
- [x] 前端测试第四批（2026-09）：四大组件补全，202 → 257 测试，覆盖率
  77.62% → 91.52% statements（branches 62.71→81.67、functions 72.7→88.59、
  lines 77.91→92.17）。CredentialList 55→97.7%（筛选纯函数、五档安全色、
  六类型详情分支、TOTP 倒计时 fake-timers + 归零自动刷新、删除确认流）、
  WalletPanel 46→95.2%（导出格式矩阵 + WIF/xpub 提示、导出密码闸门 + json
  blob 下载、create/import/addAddress 全流程含失败臂、地址表 + QR + 复制、
  Send 投毒上下文、删除确认取消/失败/成功三臂）、IdentitySwitcher 43→100%
  （六类型图标/配色、切换、CreateIdentityModal 表单流 + reset）、
  ErrorHandling 68→94.4%（边界 fallback + dev 详情 + production 上报臂、
  四样式类型矩阵）。
- [x] 功能开关（feature flags）：高级功能默认关闭，设置页可开启
  （对齐 1Password：SSH agent 在设置中显式开启；钱包/Passkey 多数用户用不到，
  默认隐藏，需要时开启。主航道密码管理不受影响。2026-09-18 最小闭环落地）
  - [x] 导航按开关显隐：SSH Agent / Wallets / Passkeys 默认关；
    Credentials / Statistics / Watchtower 恒开（App.tsx NAV_ITEMS + visibleNav）
  - [x] 开关持久化到 workspace settings（`WorkspaceSettings.features: FeatureFlags`，
    serde default 旧 JSON 缺键回退全关；`get_workspace_settings` 免解锁读 +
    `set_feature_flags` 需解锁窄写、返回全量设置作服务端真相）
  - [x] backend 联动：passkey 审批服务端移到 init_service 尾部按开关门禁
    （`maybe_start_passkey_server`，AtomicBool 幂等；lock→unlock 即生效）。
    钱包/SSH 后端命令可保留（已有解锁 + re-auth 门禁），仅隐藏 UI 入口
  - [x] 设置页 SettingsModal tab 化：General（三开关 optimistic 写 + 失败
    回滚 + toast）/ Identities（原身份管理）
  - [x] 开关即生效（2026-09-20 桌面稳定化第 3 项）：`set_feature_flags`
    持久化成功后按开关变化方向联动——关 passkeys → oneshot 关停信号 →
    accept loop 退出 + socket 文件移除 + 未应答审批丢弃 + 幂等标记复位；
    开 passkeys → 本会话即时拉起（不再等 lock→unlock）；关 ssh_agent →
    复用 `stop_ssh_agent_internal`（abort handle + 清审批 + env + state
    文件）；开 ssh_agent 不自动启动（入口显隐归 UI，agent 由用户在面板
    start，对齐 1Password 语义）
  - 已知限制：设置页开关与 active identity 对同一 workspace 行是
    last-write-wins
- [ ] UI 对齐 1Password 8 交互范式（分阶段；身份维度保留为 Persona 特色，
  信息架构不照搬——1Password 无身份/上下文概念，IdentitySwitcher 语义是
  "身份"而非"账户"）
  - [x] 双栏布局：中间条目列表（图标+标题+副标题，行内复制/详情按钮）+
    右侧常驻详情面板，取代凭据卡片网格 + 点击弹 modal
  - [x] 全局快速搜索（⌘K / 顶栏搜索框，跨身份跨类型结果分组；范围天然
    受功能开关约束）——6be7cba7 跨身份选中桥（pendingCredentialSelection
    入 store，CredentialList 凭据就绪后注入并清除）/ 74b58db5 QuickSearch
    overlay（⌘K+工具栏按钮双入口、200ms debounce、按身份分组、↑↓Enter
    键盘导航）。已知限制清理（2026-09-20）：搜索 SQL 扩 username/url 字段
    （repository `search_by_fields` 三字段 OR，同参数 bind 三次，NULL 列
    天然不参与）；loadCredentialsForIdentity 失败路径清 pending（凭据没
    加载出来 pending 永不会被注入，残留会让下次进该身份突然选中）；跨
    身份跳转 switchIdentity 传 silent（切换是手段不是用户动作，toast
    只会盖住跳转）；pending 注入同时清列表搜索词 + 复位侧栏分类（目标
    被本地筛选挡住时注入会被"筛选不可见清选中"立即清掉）、目标凭据
    已删除时 pending 作废（列表归属校验排除换身份中间态误清）
  - [x] 快速搜索结果搜索词高亮（2026-09-20 落地）：独立 Highlight 组件
    （不区分大小写整串匹配、多片段全标记、纯文本拆分渲染无注入面，
    行为对齐 SQLite LIKE 的 ASCII 大小写不敏感），QuickSearch 标题与
    用户名两处接入，命中渲染 <mark> 黄底。CredentialList 本地搜索词
    如需同款高亮可直接复用该组件
  - [x] 暗色模式（Tailwind darkMode: class；现有浅色 token 全部成对补 dark
    变体——13d75f4c 基建 / 94ee3930 Settings 三档选择器 / a79b3cbb 全组件
    sweep，顺带修复 v4 死类 bg-opacity-* 导致的弹窗遮罩纯黑实底）
  - [x] 侧栏分类导航（类型/标签/收藏树，取代筛选 chip 行）；
    IdentitySwitcher 移至侧栏顶部（对应 1Password 账户切换器的位置）
    ——e7e46df7 app shell（侧栏 + 视图导航 + footer Settings/Lock）/
    3f7060ec 分类树（单选 SidebarFilter 入 store，取代 chip 行；换身份
    自动复位）。已知限制清理（2026-09-20）：锁屏（手动 + 自动锁双路径）
    复位侧栏选中 + 清列表搜索词；筛选（搜索词/侧栏分类）变化后选中项
    不可见时自动清详情面板（1Password 语义——筛选是导航动作）；列表
    搜索词迁入 store（credentialSearchQuery）——pending 注入需要与选中/
    侧栏筛选同批更新，React state 慢一帧会产生"选中已置、搜索词未清"
    的中间帧误触清选中（jsdom 渲染探针定位）
  - [x] 条目图标：favicon 按需下载 + 本地缓存 + 设置可关
    （隐私红线：不常驻外联，不默认抓取——1Password 同款做法）
    ——7fe5b07b core（favicon_cache 表 + FaviconFetcher：SSRF 六规则校验、
    redirect 不跟随、512KiB 双保险、text/* 拒收）/ d54fc666 开关第 4 位
    fetch_favicons（默认关）+ 命令层（后端 flag 兜底）/ 本条 渲染接入
    （useFavicons 批量预取 + FaviconImg 三态收口 + 详情面板 Fetch icon
    按钮；缓存 host 级共享、锁屏清空）。已知限制：DNS rebinding 不防
    （校验只覆盖 URL 字面 host）；仅 GET favicon.ico（无 HTML link 解析，
    404 站点抓不到）；重定向不跟随（301 跳 favicon 的站点失败）；text/*
    拒缓存；前后端 host 归一化边缘差异（只影响键匹配，降级静态图标）；
    无 TTL/刷新；抓取不进 audit log（公开数据）。follow-up：HTML link
    解析 + TTL、audit log、IPv6/IDN 显示归一
  - [x] 快捷键体系（⌘K 搜索、⌘L 锁定、⌘E 复制用户名、⌘, 设置开关）
    ——c2fd6861 useGlobalShortcut hook（⌘K 重构为首个消费者）+ ⌘L 锁定
    + 锁屏清理补齐（modal bool 复位、pending/selected/favicon 随锁作废，
    auto-lock 与手动锁对齐）/ 本条 selectedCredentialId 提升进 store
    （CredentialList 派生消费）+ copyToClipboardWithToast 收口 + ⌘E/⌘,
    + 按钮 title 提示。已知限制：纯前端层（非系统级全局键）；部分
    浏览器保留键如 Ctrl+E/L 在 WebView 外不保证拦截。follow-up：密码/
    TOTP 全局复制（需把组件级 useReauth 提升到 App 级）、快捷键速查
    面板。Escape 统一关 modal 已落地（2026-09-20）：共享 hook
    useEscapeToClose（window keydown，焦点无需在 modal 内；latest-ref
    换 onClose 不重建监听），接入 CreateCredentialModal / SettingsModal /
    CreateIdentityModal（IdentitySwitcher 内）/ ReauthModal /
    ChangeMasterPasswordModal（后两者原内联实现收编，forced 模式保持
    不可逃逸）；叠开收口：下层在 ReauthModal/改密弹窗开时让位
    （isOpen && !上层开启），提交中不响应——一次 Esc 只关最上层
  - [x] 编辑凭据闭环（2026-09-20 桌面稳定化头条，此前全端无编辑能力）
    ——core `update_credential_data`：新 payload 复用**原 item key** 重封
    （wrapped_item_key 字节不动，附件不变量有专测守护——重生成 key 会让
    该 key 封存的附件全部变砖）；legacy 行（无 wrapped key）编辑时升级
    per-item key（与附件批次同模式）；走敏感操作门禁（同 get_credential_data），
    item history 自动落 Updated 行 + 审计。KeyHierarchy 新增
    `encrypt_with_item_key`（既有 key 重封，不动 wrapped 形态）。
    desktop 两命令：`update_credential`（元数据：name/security_level/url/
    username/notes/tags，空串 trim 清空，类型不可变——1Password 语义）+
    `update_credential_data`（payload，REAUTH_REQUIRED 走既有 error_code 通路）。
    前端：CreateCredentialModal create/edit 双模式（打开时预填元数据 +
    已解密 payload、类型选择器锁定、Edit Item 标题；REAUTH 弹 ReauthModal
    自动重试一次）、DetailPane Edit 按钮经 store editingCredential 桥接
    （锁屏/自动锁随锁作废）；无专属表单字段的类型（BankCard/ServerConfig/
    Certificate/GameAccount）只编辑元数据——不盲目用空 payload 覆盖既有
    密文。顺带修 create_credential 类型 match 缺 SecureNote/Identity/
    SoftwareLicense 三臂（此前经 Custom(name) 字符串往返侥幸等价）
- [x] `pnpm tauri:build` 产出安装包（本环境无 GUI，待人工验收）
  ——5f39538e 测试 fixture 对齐类型定义，清零 23 个 tsc 本底
  （beforeBuildCommand=`pnpm build` 由此解锁，前端验证基线简化为
  一条命令）/ 本条 `cd desktop && ./node_modules/.bin/tauri build
  --bundles deb`（release 全量编译 10m16s）。产物：
  bundle/deb/Persona_0.1.0_amd64.deb（12MB，包名 persona 0.1.0 amd64，
  Depends: libayatana-appindicator3-1/libwebkit2gtk-4.1-0/libgtk-3-0，
  内容 usr/bin/persona-desktop + hicolor 三档图标 + .desktop 入口）；
  二进制 36MB ELF，ldd 零缺失（webkit2gtk-4.1/gtk-3/javascriptcore 健全）。
  已知限制：`--bundles deb` 为本机 CLI 限定（bundle.targets 保持 "all"
  不改——本机无 rpmbuild，AppImage 需联网拉 linuxdeploy）；deb 未签名。
  真机安装验收（2026-09-20，本机为无 GUI 服务器，降级 xvfb 虚拟显示）：
  ① `sudo dpkg -i` 安装成功（dpkg -L 核对二进制/三档图标/.desktop 齐全）
  ② `Xvfb :99` + `dbus-run-session` 启动 persona-desktop：进程存活、
  webview2gtk 初始化成功、托盘路径不炸（仅 appindicator deprecation 警告）、
  ffmpeg x11grab 截图确认解锁屏完整渲染（logo/主密码输入框/自定义 db
  路径 checkbox/禁用态 Unlock 按钮），日志零 panic（WARNING 均为服务器
  环境级：RealtimeKit/PipeWire 缺失、无 DRI3）
  ③④ 交互冒烟与卸载保留数据 → 待有 GUI 的机器执行（deb 可直接拷贝）
  follow-up：deb 签名、更新器（updater）签名密钥、macOS x86_64/universal
  与 Linux arm64 产物。CI 打包矩阵已落地（见 desktop-build.yml 条目）。
- [x] deb control description 补全（2026-09-20 桌面稳定化第 4 项）：
  tauri.conf.json bundle 层补 shortDescription/longDescription（注意字段
  在 `bundle` 直下——顶层 description 与 `bundle.linux.deb` 均被 v2
  schema deny_unknown_fields 拒绝）；重打包验证 control Description
  落地（短句 + 完整产品长描述），产物同步带上开关联动批次代码（12.4
  →13MB，Installed-Size 37→41MB），内容（二进制/hicolor 三档图标/
  .desktop）与 ldd 依赖零缺失复核通过；产物在本机（服务器）dpkg 安装
  + xvfb 虚拟显示启动验证通过（见上条真机安装验收记录）
- [x] CI 多平台打包矩阵 desktop-build.yml（2026-09-20）：三平台矩阵——
  Linux ubuntu-22.04（deb/rpm/AppImage，apt 装 webkit2gtk-4.1/appindicator/
  rpm 工具链）、Windows（NSIS exe + WiX msi）、macOS arm64（dmg）。三个入口：
  push tag v* → 正式 Release（自动生成 notes）；每日 cron 02:23（北京）→
  滚动 nightly prerelease（删旧 release+tag 重建，产物覆盖）；手动 dispatch
  可仅构建（勾选 upload 才发布 nightly）。仓库 PUBLIC 无 runner 额度压力；
  pnpm 按 workspace 根 lockfile --filter persona-desktop... 装依赖，
  rust-cache 缓存 desktop/src-tauri workspace。已知限制：产物未签名
  （SmartScreen/Gatekeeper 安装告警）、版本号恒 0.1.0 无日期区分（资产靠
  nightly release 名日期区分）。Android 不在本矩阵：mobile 是
  persona-mobile Rust FFI（就绪）+ Flutter 宿主（工程未建），无 apk 可打，
  工程落地后另加 flutter job。发布链实测（2026-09-20 dispatch 验证）：
  nightly release 六资产齐全——deb/rpm/AppImage（12.3/12.3/85.4MB）、
  NSIS exe/WiX msi（7.7/10.6MB）、aarch64 dmg（9.7MB）；三轮踩坑已修：
  pnpm 版本与 packageManager 冲突、passkey 桥 Windows cfg 分流、
  dist glob 递归 + 空产物防御

Server & Sync (optional)
- [x] Events API, audit ingestion, metrics
  ——72aa483f `POST/GET /api/v1/events`（批量 ≤500/body ≤1MiB 全有或全
  无校验、client_event_id 部分唯一索引去重、server 分配 UUID 与
  received_at；base64url 游标分页 + action/success/since 过滤，limit
  默认 100 上限 1000）+ 单 Bearer 令牌（subtle 常量时间比较，未配置
  PERSONA_SERVER_TOKEN 即 503 fail-closed）+ 独立 SQLite 库
  （server/migrations，WAL，与 core 身份库分离）+ 统一错误形状
  {"error":{code,message,items}}；6ffaf393 `/metrics` 手写 Prometheus
  0.0.4 文本（http_requests_total 按路由模板计数、事件三计数器、
  start_time/uptime，免认证，fallback 404 计 "unmatched"）；1fb23003
  compose 令牌强制注入（:? 缺失拒绝启动）+ 命名卷持久化。THREAT_MODEL
  同 commit 登记（仅摘要/元数据、不宣称防篡改/防抵赖）。
  已知限制：无保留策略（DB 无界增长）、无速率限制、单共享 token 无
  per-client 身份、ip/user_agent 客户端自报、client_timestamp 取信
  客户端时钟、permissive CORS、405 不计入 metrics。
  follow-up：SRP
  设备认证（替代单令牌）、保留策略/TTL、ConnectInfo 采真实来源 IP
  （gzip 已由 0d48d953 落地，见上报 wire 层 gzip 条）。手工验收：带
  token 起服 → POST 事件（202）→ 重复
  client_event_id（duplicates 计数）→ GET 翻页 → /metrics 观察 →
  不设 token 重启（/api 503）→ compose 卷重启后事件仍在。
- [x] 设备令牌 + 整库加密备份保管（同步第一阶段）
  ——`PERSONA_SERVER_TOKENS="laptop:tok1,phone:tok2"` 多设备令牌
  （设备名由令牌推导、客户端不可自报；legacy 单令牌兼容为 "default"
  设备；对全部条目无早退常量时间比较；非法格式启动即错）+
  `POST/GET/DELETE /api/v1/backups`（流式落盘 256 MiB 上限、CL 预检 +
  流式计数双保险、边写边算 sha256、同设备最新版本去重 deduplicated、
  倒序游标分页 limit 默认 20 上限 100、下载 ETag=sha256 流式回传、
  删除先文件后行；`PERSONA_SERVER_BACKUP_MAX_VERSIONS` 全局删最旧）+
  backups 元数据表（文件本体在 {backup_dir}/{uuid}.persenc，服务器只
  见 PERSENC1 密文）+ metrics 加 backups_created/deleted + compose 透
  传新 env（BACKUP_DIR=/data/backups 落命名卷）。THREAT_MODEL 登记
  "备份保管端点"（不防扣留/回滚、恢复双要素、附件不进 v1 备份）。
- [x] 客户端备份链 core 模块 + CLI 命令（2026-09）
  ——core `backup` feature（进 default，reqwest/flate2/sqlite 均已在
  default 树零增量）：`file_crypto`（PERSENC1 字节级平移自 CLI，与
  `--encrypt` 导出互解，解密侧 iterations/parallelism 恒 3/1 的历史
  格式约束保留）、`snapshot`（VACUUM INTO 绑定参数优先+转义字面量
  退路、**产物存在性校验**——sqlx 对 `:memory:` 池的 VACUUM INTO 会
  返回 Ok 却不落盘（实测 0.8.6），生产路径 identities.db 恒为文件库
  不受影响、校验防静默失败流出空备份；gzip 魔数自适应；恢复链解密→
  解压→SQLite 头校验→写文件）、`client`（BackupClient 四端点，
  300s 超时、下载本地复算 sha256 对 ETag、delete 幂等 404 视成功、
  手写 TcpListener 假服务器测试——core 不引 axum/tower dev-dep）。
  CLI：`utils/file_crypto` 改薄包装（签名/测试/错误文案不变）+
  `persona backup push/list/pull/restore/delete`（env 沿用
  PERSONA_SERVER_URL/TOKEN 都非空才启用 fail-closed；push 不要求
  解锁；口令 `--passphrase-env VAR`→PERSONA_PAYLOAD_PASSPHRASE→
  交互三级；restore 确认在前口令在后、staged 临时文件复验成功才
  换库、旧库留 .bak、附件缺失提示）。
- [x] core::events::Emitter 客户端上报器（批量+重试）
  ——512b2495 wire 镜像 + 字节口径预校验（毒丸客户端逐条丢弃，防
  server 全有或全无整批 422；action 走 Display 非 serde，externally
  tagged Custom 会序列化成对象）+ Emitter（同步入队、队满丢最旧计数、
  Notify 批满唤醒 + interval 兜底、失败整批原序回队 + 1s→5min 指数
  退避、Weak 防泄漏、stop 尽力最终 flush）；e22a2395 ServerEventSink
  （events-server feature 进 default，reqwest POST + Bearer + 10s
  超时，token 宿主注入 core 不落盘）；75e3bb4e PersonaService.log_audit
  挂钩（set_event_emitter 注入，写本地库后尽力 emit，None 解除）。
  已知限制：内存队列非持久无 outbox（进程崩溃丢未 flush 批，本地
  sqlite 审计库仍是存证源）、stop 的 abort 丢失窗口上限 = 一个
  batch_size。THREAT_MODEL 同批登记客户端条目。
  follow-up：desktop/CLI/mobile 宿主接线（设置 UI + token 存储，见下条，
  desktop/CLI/mobile Rust FFI 已完成）、AutoLockManager 接线（已完成，
  见下条）、持久 outbox/回补（gzip 已由 0d48d953 落地）。手工验收：真 server +
  Emitter(ServerEventSink) 发 3 条（1 重复 id）→ GET accepted=2
  duplicates=1 → /metrics 计数增长；停服期间 queued() 增长、重启后退避
  自动送达；杀进程丢未 flush 批但 audit_logs 表完整。
- [x] 宿主接线：desktop/CLI 构造 Emitter 并注入 PersonaService（CLI 集成
  测试假服务器端到端断言 POST + Bearer + body；desktop 手工验收清单见
  批次说明）
  - [x] CLI：`PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN` 都非空才启用
    （94c113c5；env-only 不落盘；86 处 PersonaService::new 统一走
    new_service 注入，switch/remove/migrate 3 处直写审计库的点补
    emit_audit；main 尾部 stop() 尽力 flush——release panic=abort 崩溃
    路径不 flush，已知限制）
  - [x] desktop：设置页 General 加同步服务器区块（ad00da2c；settings.sync
    存 vault JSON 列无字段级加密、get_workspace_settings 免解锁可读
    sync 段——THREAT_MODEL 登记；token 空串 = 保留旧值不回填前端；
    保存即重挂停旧换新；RunEvent::Exit 尽力 flush；token 明文缺口
    已由 keyring 批次闭合，见下条）
  - [x] keyring/token 字段级加密（769f99c4；token 真值存 OS keyring
    （keyring 4，service "persona-sync"、键为 vault db_path），
    vault JSON 恒空串 + legacy 一次性迁移；attach fail-closed：enabled +
    url + keyring 三者齐备才上报；keyring 不可用拒绝保存/禁用上报；
    新增免解锁 sync_token_present 布尔查询驱动前端 placeholder；
    测试全走 InMemoryTokenStore fake，真 keyring 走手工验收）
  - [x] AutoLockManager 接线（56dde4c1；set_event_emitter 传播到 manager，
    SessionLocked/Unlocked 写库后上报，后台超时锁审计行补齐
    session_id/user_id/details；LockPending/Activity 是 UI 事件不上报）
  - [x] mobile Rust FFI 宿主接线（fe244fce；persona-mobile 十个 FFI 函数
    persona_init/version/free_string/free_result/service_init/service_unlock/
    service_lock/service_is_unlocked/configure_sync/shutdown；
    对齐 desktop/CLI 语义：service_init 建户/认证序列、unlock/lock/
    is_unlocked、configure_sync fail-closed（url+token 都非空才启用、
    空白即摘除、URL 不做格式预校验同 desktop）、shutdown 尽力 flush；
    状态全留 Rust 侧全局槽位，token/url 由 Dart 层经 FFI 参数注入、
    Rust 侧不落盘不读 env；生命周期/审计上报全链路测试 99% 行覆盖；
    本机无 Flutter SDK，手工验收清单见批次说明）
  - [x] mobile 业务 FFI（persona_identity_create/list/get/update/delete、
    persona_credential_create/list/data/delete/search、persona_totp_code：
    统一 JSON-in/JSON-out 包络 `{"ok":…,"data"|"error":…}`，复用
    `persona_free_string` 归还；加密往返/锁定门禁/UUID 与 JSON 坏入参
    防线测试；协议层与 UI 框架无关，Flutter/Dart 绑定落地时直接消费）
  - [x] 上报 wire 层 gzip（0d48d953；ServerEventSink 序列化后 1 KiB 阈值
    二选一——大批 flate2 gzip + Content-Encoding: gzip、小批明文直发、
    显式 Content-Type；server 加 RequestDecompressionLayer，tower-http
    0.5→0.6；限制语义双层：payload_size_guard 线上字节 1 MiB +
    DefaultBodyLimit 解压后明文 10 MiB 防解压炸弹；压缩在 sink 内部
    宿主零改动；THREAT_MODEL 已登记）
  - [ ] follow-up：mobile Flutter 工程/Dart 绑定（需 Flutter SDK 与设备
    验证；桥方向手写 FFI vs frb v2 待工程落地时定）、持久 outbox/回补
- [ ] Connect-like local-first secrets automation endpoint
- [ ] End-to-end encrypted sync (key envelopes, conflict resolution)
- [ ] SCIM/SSO bridging (future)
- [ ] 文档：用户可选的存储/同步模式（纯本地、自托管云/自有 iCloud、Persona Server 辅助）

Browser & Autofill (future)
- [x] Browser extension skeleton (autofill; domain rules)
  - [x] Wire popup UI to Persona desktop/CLI bridge
  - [x] Form detection + autofill heuristics (passwords, TOTP, address)
  - [x] Domain policies + phishing protections
- [x] Safari WebExtension host shell (Swift bridge + manifest sync)
  - 注意：`SafariWebExtensionHandler` 目前仅回显消息（echo stub），未接 persona bridge；
    真实桥接（复用 bridge protocol v2）待 macOS 环境验证（同 P4 OS provider 约束）
- [x] Chrome/Chromium extension "1Password-like" bridge (Native Messaging + local service)
  - [x] Define Persona Bridge Protocol v1 (hello/status/get_suggestions/request_fill/copy/totp)
  - [x] Pairing + message authentication (bind to extension instance; short-lived session)
  - [x] Implement CLI native host: `persona bridge` (stdio JSON loop) + audit logging
  - [x] Enforce origin binding + user-gesture requirement for fill/copy/reveal
  - [x] Minimal autofill MVP: username/password fill on matched domain
  - [x] Policy integration: domain trust/blocked + confirm-on-unknown
  - [x] Installation: native host manifest + install scripts (macOS/Windows/Linux) + docs
  - [x] 扩展单测套件（jest + ts-jest + jsdom，60 用例）：domainPolicy 启发式/policy 覆盖、
    formScanner 分类/评分/virtual form/observeForms、settings 与 autofillDefaults 的
    normalize 边界（内存 chrome.storage mock）、nativeBridge 配对状态机 + HMAC 签名
    （node:crypto createHmac 独立复算，验证 canonical JSON 键排序与 Rust bridge.rs 对齐）
  - [x] 清理：删除 wasm-crypto 死代码（base64 0.21 API 不兼容不可编译、仓库零引用）；
    删除 bridge.ts HTTP 探测死路径（`127.0.0.1:19945/status` 从未有服务端实现，
    BridgeStatus 类型迁入 nativeBridge.ts，扩展只走 native messaging 单通道）
  - [x] 补齐 public/icons/icon128.png（复用 desktop Tauri 128x128 图标；此前 manifest 引用落空）
- [ ] Passkeys (WebAuthn) storage + autofill — 设计稿：`docs/PASSKEYS_DESIGN.md`
  - [x] P1: 软件验证器 core/CLI（ES256 生成/签名、p256+coset、passkeys 表与 KeyHierarchy 包裹、
    PersonaService create/list/show/delete/assertion/self-test/export、审计事件、
    `persona passkey …` CLI、JSON 导出含私钥（export_allowed 门禁）、
    webauthn-rs RP 全流程回归 + 单测）
  - [x] P2: 浏览器桥接 v2（passkey_list/create/assert 三消息 + protocol_version 2、扩展 MAIN-world
    WebAuthn 拦截 + 选择/确认 UI + 回退原生、conditional mediation/cross-origin iframe 不拦截、
    桥接层 origin↔rp_id 校验与 user gesture 强制、协议文档/README 增补）
  - [x] P3: 确认闸门链路（bridge↔桌面 Unix socket 审批协议 `passkey-approval.sock` +
    `PERSONA_BRIDGE_DESKTOP_APPROVAL` auto/require/off 开关、桌面常驻审批服务端、
    通知式确认 modal（Esc=拒绝）、系统托盘 + 关窗驻留）
  - [x] P3: 桌面 passkey 管理页（跨身份列表、详情、删除、自检、导出 hex 私钥，
    敏感操作走 REAUTH_REQUIRED → ReauthModal → 自动重试）
  - [x] P4: 1PUX 导入（1Password 迁移）：core 解析器 + import planner（纯函数、
    桌面可复用）+ `persona import-1pux --dry-run` 预览/确认/落库；vault→identity、
    Login/API Credential/SSH Key 映射、TOTP 拆独立凭据、未映射类别跳过并报告；
    真实 .1pux 导出待人工验收
  - [ ] P4: OS passkey provider（macOS/Windows）、conditional mediation
- [x] Phishing protections; identity-based context switching

Game Tokens (游戏令牌)
- [x] G1 (2026-09): Steam Guard + Google Authenticator (RFC TOTP) 统一令牌层
  - [x] core/src/crypto/steam.rs：Steam Guard 算法（标准 base64 shared_secret、30s 周期、
    HMAC-SHA1 动态截断 + 26 字符字母表连续取模 5 位码；与 steamguard-cli/SteamAuth 等
    开源实现一致；Valve 无官方测试向量 → 回归依赖独立手工 ipad/opad HMAC 参照实现
    交叉验证 + 结构断言 + 周期窗口边界）
  - [x] core/src/crypto/game_token.rs：统一调度器（generate_code/_now 按 provider 路由；
    未知 provider 报 "Unsupported game token provider"——未来绑定型 provider 存入后
    读取路径正确报错而不是静默生成错误码；TwoFactor 凭据亦可经统一入口出码，
    三端消费只需一个 match 臂）
  - [x] CredentialData::GameToken 变体（追加在 Raw 之后，bincode 变体索引逐字节
    稳定回归测试；GameTokenData{provider, secret_key, issuer, account_name, url}）
  - [x] CLI：`persona totp setup-steam`（--secret base64 shared_secret 入库前解码校验、
    --account 必填、--url origin 绑定、metadata 记 provider）+ Code 子命令同时支持
    RFC TOTP 与 GameToken 凭据
  - [x] CLI bridge：get_totp 与 copy(field=totp) 加 GameToken 臂（user gesture/
    origin binding/active identity 门禁全部沿用）
  - [x] desktop get_totp_code 与 mobile persona_totp_code 加 GameToken 臂（可读码：
    digits=5、algorithm=provider 大写、period=30）
  - 注：Google Authenticator/GitHub 等标准 TOTP 此前已覆盖（core RFC 6238 引擎 +
    CLI QR/otpauth 录入），G1 补齐的是 Steam Guard 算法、统一调度器、GameToken
    存储变体与三端统一出码路径
- [x] G1.5 (2026-09): desktop 创建表单支持游戏令牌（CredentialDataRequest::GameToken
  变体 + TS 类型 + GameToken 表单字段（provider slug 规范化、secret 可选、绑定型提示）
  + 测试；credential_type 仍存 TwoFactor（与 CLI 一致），详情面板因凭据类型同为
  TwoFactor 自动获得出码组件）
- [x] G2 (2026-09): 国内游戏令牌调研 + 记录型落地（诚实区分「离线可算」与「厂商绑定
  型」，绑定型不伪造动态码，只做记录并提示出码走厂商 App）
  - [x] CLI `totp setup-game-token --provider <slug>`：厂商绑定型令牌记录入库（provider
    规范化为 [a-z0-9_] slug、secret 可选存备未来离线支持、metadata 记 provider/issuer、
    origin url 绑定；离线可算 provider 自动重定向到专用命令；读取路径统一报
    「Unsupported game token provider + 需厂商 App 出码」）
  - [x] 腾讯游戏安全中心/QQ令牌：算法为 TOTP 类（30s 6 位）但密钥由服务端配发进
    QQ安全中心 App，无导出渠道 → 绑定型，记录落地
  - [x] 网易大神将军令（含网易BUFF）：App 绑定、60s 周期动态密码、序列号解绑制 →
    绑定型，记录落地
  - [x] 米哈游/原神安全令：通行证 2FA 为自家 App 动态码 + WebAuthn，无第三方 TOTP →
    绑定型，记录落地；WebAuthn 归 Passkeys 轨道
  - [x] 4399 安全令牌：自家 App 动态密码（需联网刷新）→ 绑定型，记录落地
  - [x] 暴雪战网验证器：专有算法但有成熟社区导出（serial + restore code → 标准 TOTP
    secret，bnet-auth-export 先例）→ 导出后走现有 `totp setup --digits 8` 离线出码
  - [ ] 完美世界 / 7K7K：无公开令牌产品文档，继续待调研（`setup-game-token` 已可记录）
- [ ] G3: 国际扩展与标准增强
  - [ ] GitHub 二次登录验证：TOTP 已覆盖；安全密钥/通行密钥走 Passkeys 轨道
  - [ ] HOTP（RFC 4226 计数器型）录入与出码 —— **暂缓（2026-09）**：非 1Password
    对齐项（1Password 仅支持 TOTP）；core `hotp()` 原语已存在（crypto/totp.rs），
    若将来实现需解决「desktop/mobile 自动轮询会推进计数器」的持久化问题
  - [ ] Steam Desktop Authenticator 导出格式（maFiles .maFile）—— **不做导入
    （2026-09 定案）**：私有格式仅文档记录；steam_guard 共享密钥已可经
    `totp setup-game-token` 手工录入离线出码

1Password Parity（2026-09 起，逐批推进；对照 docs/ONEPASSWORD_FEATURES.md）
- [x] A 批：Secure Note 全文加密条目（2026-09 落地）——`CredentialData::SecureNote`
  （bincode 索引 9）+ `CredentialType::SecureNote`；CLI `credential add
  --credential-type note --note`（互斥校验 --secret/--prompt-secret）；desktop
  创建表单 + 详情面板（正文走 per-item key 加密，区别于 credentials.notes 明文列）；
  存储层 credential_type 字符串往返补 SecureNote 臂（此前读回退化为 Custom）
- [ ] B 批候选（按用户价值排序）：
  - [x] item history / change-history（2026-09 落地）：core create/update/delete
    自动记录（快照与 diff 只含明文元数据，密文变化只记 `<encrypted>` 占位；
    无实质变化的 update 不记；记录失败 warn 不阻断主操作；version 递增）；
    desktop `get_credential_history` 命令 + 详情面板懒加载时间线；
    CLI `persona credential history --id`；凭据删除后历史仍可查询。
    已知噪声：create-then-update 架构使创建产生 created+updated 两行（真实两次
    写库，UI 可将来分组展示；恢复旧版本功能待后续评估密文重放风险）
  - [x] attachments（2026-09 落地）：**修复加密链路致命缺陷**——原实现
    attach 时随机生成密钥用后即丢、retrieve 再随机生成解密密钥，加密附件
    永远无法解密（该缺陷存续期内创建的加密附件不可恢复，无迁移负担）。
    修复后附件复用所属凭据的 per-item key 封存：主密码轮换只重包
    wrapped key、item key 不变 → 附件零重写跨轮换可解密；legacy 凭据
    （无 wrapped key）首次挂加密附件时原地升级为 item key 包裹（否则
    主密钥封存的附件会在轮换后变砖）；凭据删除级联清附件 blob。
    三端落地：desktop 4 命令（list/attach/save/delete）+ 详情面板
    Attachments 区（tauri-plugin-dialog 原生文件选择/保存对话框，
    字节不过 IPC）+ CLI `credential attach/attachments/save-attachment/
    remove-attachment`（附件目录约定 `<db dir>/attachments`，desktop/CLI
    一致）。已知限制：附件大小受单文件读入内存约束（BlobStore 整文件
    加密后 >100MB 才分块，但读取路径全内存，超大文件会撑内存——
    实际用户附件场景通常 <10MB，暂不优化）
  - [x] Identity / Software License 条目类型（2026-09 落地）：1Password 标准类别
    ——`CredentialData::Identity`（bincode 索引 10：姓名/联系方式/地址/生日 +
    证件号 id_number/passport/driver_license/tax_id/组织/职位）与
    `CredentialData::SoftwareLicense`（索引 11：license_key/版本/发布商/购买
    日期/订单号/支持邮箱/下载链接/席位数/有效期）；`CredentialType` 加
    Identity/SoftwareLicense 变体 + 存储字符串往返臂（此前读回退化 Custom）；
    敏感字段（证件号/license_key）随 per-item key 加密，读取走敏感操作门禁。
    三端落地：desktop 创建表单两分支（Identity 表单含核心字段，全字段可经
    CLI flag 补齐）+ 详情面板字段渲染（空字段整行不渲染，逐字段复制）；
    CLI `credential add --credential-type identity/software-license`（21 个
    flag 全覆盖，first/last name 与 license key 缺省交互提示，--secret 互斥
    校验）+ show --reveal 展示臂。日期字段沿用自由格式文本（与 1Password
    文本字段一致，不做解析）
  - [x] Watchtower expiring items / 2FA-available 提示（2026-09-20 落地）：
    **expiring items**——SoftwareLicense.valid_until 自由文本到期检查
    （`parse_flexible_date` 宽容解析 ISO/斜线/点分三种风格，不可解析
    静默跳过；到期语义"当天仍有效"，到期时刻 = 当日 23:59:59，对齐
    BankCard 月末规则）。**2FA available**——Password 条目 url 命中内置
    2FA 目录（BUILTIN_2FA_SITES，2fa.directory 精选 62 站，随版本更新，
    纯离线不外联）且库内无 TOTP 类凭据（TwoFactor/GameToken）覆盖该站
    （host 归一化去 scheme/www/端口，子域互认）→ Low 级提示。新变体
    `TwoFactorAvailable { site }`（serde tag two_factor_available）；
    三端落地：CLI kind_label / desktop 前端类型 + KIND_LABELS + 描述
    文案 + 渲染测试。已知限制：目录硬编码会过时（follow-up：随发布
    刷新）；不做 HTML link 解析式 favicon 的 2FA 联动
  - [x] 桌面界面国际化（2026-09-20 落地）：react-i18next + zh-CN/en 双语
    （zh-CN 基准、fallbackLng zh-CN）。覆盖全部 20 个组件 + hooks/
    utils（usePersonaService/useReauth/useSshApprovals/usePasskeyApprovals/
    clipboard/ErrorBoundary）；通知文案走 `import i18n` 单例 t()。
    WorkspaceSettings 增 locale 字段（core 迁移 + Rust payload 不动），
    Settings 语言选择器持久化，启动恢复：锁屏阶段读 settings 即生效，
    已解锁路径与 flags 读取共用一次调用（避免重复 IPC）。CLI 保持英文。
    jest 侧为 i18next CJS default import 开 esModuleInterop（仅 jest
    tsconfig override，不影响 vite 构建）；434 用例断言中文化全绿
  - [x] biometric unlock 原生接线（2026-09-21 落地）：三平台 OS provider
    （Linux polkit `auth_self` 手写 CheckAuthorization 规避 CVE-2026-78422 /
    macOS LocalAuthentication / Windows Hello；mac/win 经 CI 编译验证）。
    主密码托管 OS keyring（`persona-biometric` service、键 = db_path，
    1Password 同款直存）；四命令 status/enable/disable/unlock——enable 先验
    密码后弹框、unlock 走 init_service 本尊密码不出进程、InvalidCredentials
    自删条目 + `BIOMETRIC_RESET` 防指纹路径爆破吃满锁户、改密联动更新条目。
    前端：解锁屏指纹按钮（status 防抖活查）+ 设置 SecurityPane 开关
    （ReauthModal 验密）；SSH agent require_biometric 默认拒绝 + provider
    显式注入。polkit action 随 deb 安装（rpm/AppImage/dev fail-closed 降级，
    `scripts/verify-biometric-linux.md` 实机脚本）；威胁登记见
    THREAT_MODEL.md「Biometric Unlock」（同用户恶意进程可读 keyring 为固有
    暴露，Windows Credential Manager 无 ACL）
  - Travel Mode（vault 级可见性开关）
  - 文档：存储/同步模式说明（sync server 拓扑已有，缺用户文档）

Quality & Security
- [x] Threat model & periodic security review
- [x] Fuzz tests for parsers (mnemonic/keystore/QR)
- [x] Supply chain checks (cargo-deny, npm audit)
- [x] Dependabot 开放警报处理（2026-09-20，两条均 dismissed tolerable_risk）：
  glib <0.20 medium（GHSA-wrw7-89jp-8q8g，VariantStrIter unsoundness）——修复
  版在 glib 0.20，但 tauri 2.11.6/wry 0.55.1（当前最新）仍锁 gtk-rs 0.18 线
  （gtk 0.18 semver 强制 glib ^0.18），上游迁移前不可达；受影响 API 在本仓库
  依赖树无调用方（desktop 零直接 glib 代码）。重评估条件：tauri 迁移
  gtk-rs 0.20+。elliptic <=6.6.1 low——npm 上游无修复版（最新即 6.6.1），仅
  website umi bundler 构建链引入（node-libs-browser→crypto-browserify），
  不进 desktop/扩展产物；umi 已升 4.7.19 复核仍在，上游出补丁版即
  override。顺带：tauri 2.11.5→2.11.6（desktop 全量测试+clippy 绿）
- [x] Watchtower health checks: rules engine (weak/reused/expired/stale) in core + `persona watchtower` CLI + desktop `health_scan` command (metadata-only reports)
- [x] Watchtower: desktop UI panel (scan with optional HIBP breach check; severity-grouped metadata-only report)
- [x] Watchtower: breach check (BreachChecker seam → HIBP k-anonymity; only a 5-char hash prefix leaves the machine, network failure degrades to offline rules)
- [ ] Reproducible builds

References
- docs/ONEPASSWORD_FEATURES.md
- docs/FEATURE_GAP_ANALYSIS.md
- docs/ROADMAP.md
- docs/MONOREPO.md
