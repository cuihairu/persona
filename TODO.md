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
- [ ] Desktop 集成测试矩阵扩展（当前 107 个 Rust 测试（102 lib 单测 +
  5 集成），总体行覆盖 ~91.1%（lib 化前 89%）；commands.rs ~90.6%、
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
- [ ] 产品缺口：`password_change_required` 强制改密机制仅存 schema
  （user_auth 表列 + `AuthResult::PasswordChangeRequired` + init_service
  拒绝臂），生产代码无任何置位路径（INSERT 恒 0）——密码过期/轮换策略
  未实现，init_service 的 "Password change required" 分支永不触发
  （2026-09 覆盖率分析发现，非链路断裂而是功能本体缺失）
- [ ] Desktop 前端 23 个测试文件 tsc 类型本底（2026-09 全局搜索批次发现；
  此前误记 "tsc 0 错误"——`npx tsc` 拉到 npm 同名占位包返回假 0，须用
  `./node_modules/.bin/tsc`）：全在测试 fixture（`url: null` vs
  `url?: string`、缺 timestamp/SshAgentStatus 形状、`"private_key"` 非法
  SecretField 等），源代码 0 错误；jest/ts-jest 不做全量类型检查所以
  测试照跑。修法：fixture 工厂返回类型标注 `Credential`/`Identity` 等
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
  - 已知限制：flag 关闭时已 spawn 的 passkey server 本会话不停（无 shutdown
    路径）；已运行的 SSH agent 不随开关 stop（follow-up）；设置页开关与
    active identity 对同一 workspace 行是 last-write-wins
- [ ] UI 对齐 1Password 8 交互范式（分阶段；身份维度保留为 Persona 特色，
  信息架构不照搬——1Password 无身份/上下文概念，IdentitySwitcher 语义是
  "身份"而非"账户"）
  - [x] 双栏布局：中间条目列表（图标+标题+副标题，行内复制/详情按钮）+
    右侧常驻详情面板，取代凭据卡片网格 + 点击弹 modal
  - [ ] 全局快速搜索（⌘K / 顶栏搜索框，跨身份跨类型结果分组；范围天然
    受功能开关约束）——6be7cba7 跨身份选中桥（pendingCredentialSelection
    入 store，CredentialList 凭据就绪后注入并清除）/ 74b58db5 QuickSearch
    overlay（⌘K+工具栏按钮双入口、200ms debounce、按身份分组、↑↓Enter
    键盘导航）。已知限制：搜索仅匹配 name（后端 search_credentials 现状）；
    loadCredentials 失败时 pending 残留（下次进该身份会突然选中）；身份
    切换 toast 在搜索跳转时照弹。follow-up：SQL 扩 username/url 字段、
    搜索词高亮、跳转时静音切换 toast
  - [x] 暗色模式（Tailwind darkMode: class；现有浅色 token 全部成对补 dark
    变体——13d75f4c 基建 / 94ee3930 Settings 三档选择器 / a79b3cbb 全组件
    sweep，顺带修复 v4 死类 bg-opacity-* 导致的弹窗遮罩纯黑实底）
  - [x] 侧栏分类导航（类型/标签/收藏树，取代筛选 chip 行）；
    IdentitySwitcher 移至侧栏顶部（对应 1Password 账户切换器的位置）
    ——e7e46df7 app shell（侧栏 + 视图导航 + footer Settings/Lock）/
    3f7060ec 分类树（单选 SidebarFilter 入 store，取代 chip 行；换身份
    自动复位）。已知限制：锁屏→再解锁树选中残留（与旧 chip 等价）；
    筛选变化不自动清详情面板选中（follow-up）
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
    TOTP 全局复制（需把组件级 useReauth 提升到 App 级）、Escape 统一
    关 modal、快捷键速查面板
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
  不改——本机无 rpmbuild，AppImage 需联网拉 linuxdeploy）；deb 未签名；
  control 描述为占位 "Persona Desktop Application (none)"（tauri.conf
  未填 description）；本环境无 GUI，仅产物元数据验证、未真机安装。
  follow-up：CI 打包矩阵（rpm/appimage/dmg/msi）、deb 签名、
  更新器（updater）签名密钥、tauri.conf description 补全。
  手工验收：① `sudo dpkg -i
  desktop/src-tauri/target/release/bundle/deb/Persona_0.1.0_amd64.deb`
  ② 应用列表启动 persona-desktop → 初始化 vault（主密码）→ 解锁
  ③ 冒烟：身份/凭据 CRUD、⌘K/⌘L/⌘E/⌘, 四快捷键、设置四开关、
  favicon 抓取、SSH agent 面板/托盘、自动锁定、暗色模式
  ④ `sudo dpkg -r persona` 卸载 → 确认 vault 数据目录保留

Server & Sync (optional)
- [ ] Events API, audit ingestion, metrics
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
- [x] Chrome/Chromium extension "1Password-like" bridge (Native Messaging + local service)
  - [x] Define Persona Bridge Protocol v1 (hello/status/get_suggestions/request_fill/copy/totp)
  - [x] Pairing + message authentication (bind to extension instance; short-lived session)
  - [x] Implement CLI native host: `persona bridge` (stdio JSON loop) + audit logging
  - [x] Enforce origin binding + user-gesture requirement for fill/copy/reveal
  - [x] Minimal autofill MVP: username/password fill on matched domain
  - [x] Policy integration: domain trust/blocked + confirm-on-unknown
  - [x] Installation: native host manifest + install scripts (macOS/Windows/Linux) + docs
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

Quality & Security
- [x] Threat model & periodic security review
- [x] Fuzz tests for parsers (mnemonic/keystore/QR)
- [x] Supply chain checks (cargo-deny, npm audit)
- [x] Watchtower health checks: rules engine (weak/reused/expired/stale) in core + `persona watchtower` CLI + desktop `health_scan` command (metadata-only reports)
- [x] Watchtower: desktop UI panel (scan with optional HIBP breach check; severity-grouped metadata-only report)
- [x] Watchtower: breach check (BreachChecker seam → HIBP k-anonymity; only a 5-char hash prefix leaves the machine, network failure degrades to offline rules)
- [ ] Reproducible builds

References
- docs/ONEPASSWORD_FEATURES.md
- docs/FEATURE_GAP_ANALYSIS.md
- docs/ROADMAP.md
- docs/MONOREPO.md
