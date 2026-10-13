# Persona TODO

需求清单：未完成项一条一句；完成项保留一行证据（commit hash + 测试数）。删减过程叙述与流水账。

优先级：密码管理轨先对齐 1Password；账号 + 多设备同步已进主线（隐私红线：默认关闭、显式开启、明示数据范围）。

## 未完成

- [ ] OS 自动填充集成：iOS AutoFill 供体、macOS 系统填充；Passkey 的 OS 平台认证器（macOS LocalAuthentication / Windows Hello）同属此缺口。解锁条件：需对应平台机器（iOS=macOS+Xcode、鸿蒙=DevEco），本机 Linux 无环境
- [ ] 桌面应用级填充：Windows 桌面应用内的填充注入（现状仅浏览器桥）。解锁条件：需 Windows 桌面会话实机验收
- [ ] Web 端：1Password.com 形态的浏览器端（低优先，出现真实需求再评估）
- [ ] M5 浏览器插件接账号（Safari 侧）：Swift 宿主端实现桥协议 v7（报文 → `persona bridge` 子进程封装）。解锁条件：需 macOS+Xcode 实机（挂起待实机批次，docs/BRIDGE_PROTOCOL.md §20 + browser/safari-extension/README.md）
- [ ] KDF 参数评审决策点：PBKDF2-HMAC-SHA256 主密钥派生 100k 低于 OWASP 现行 600k 建议（1Password 650k）；Argon2id 各路径恰在/高于下限（维持）。待用户拍板：是否升 600k（re-wrap 迁移）/惰性升级或显式迁移命令/Argon2id 同批上浮；拍板前参数不动（docs/review/2026-10-12-kdf-parameter-review.md）
- [ ] Windows 实机测试与优化：编译层（x86_64-pc-windows-gnu 全绿）与 CI 守卫（rust-windows + rust-windows-desktop job）已收口，缺实机行为验收
- [ ] SCIM/SSO bridging（future）
- [ ] G3 国际扩展与标准增强：GitHub 二次验证安全密钥/通行密钥走 Passkeys 轨道；HOTP（RFC 4226）录入与出码暂缓（非 1Password 对齐项；core hotp() 原语已在）
- [ ] Watchtower 外联扩展：domain breach alerts / dark web monitoring / OSINT 标识符查询。押后（2026-09-22 决策）；重启条件 = 1Password 对齐完成 + THREAT_MODEL 变更门槛 + 明确 opt-in 形态
- [ ] #21 团队与共享：家庭/团队共享库 + 共享条目权限，依赖账号体系。2026-10-01 用户裁定登记待办、暂不实现（docs/FEATURE_GAP_ANALYSIS.md #21）

## 已完成

### Core / 存储 / CLI

- [x] workspace schema v2（path + active_identity_id + settings）与 CLI migrate 命令
- [x] Item versioning（身份/凭证变更历史）
- [x] Attachments blob store（文件块 + refs）
- [x] Export/Import（压缩 + 加密 + 完整性校验）
- [x] CLI add/list/show（DB 接线 + 解锁流 + 无用户回退）；add --set-active/--from-file 2026-10-13 `fb561b6`（+2 测试）
- [x] CLI edit/remove identity（交互式编辑、字段验证、备份、审计）
- [x] CLI switch（激活/停用、历史、配置持久化）；--previous 从审计轨迹解析 2026-10-13 `b1efd2f`（+1 测试）
- [x] CLI credential CRUD（filters: type/tag/active/favorite）；set-fields/fields、attach/attachments/save-attachment/remove-attachment
- [x] CLI TOTP（QR setup + code；setup-steam/import-steam/setup-game-token）
- [x] CLI password generator（length、symbol sets、pronounceable、words）
- [x] CLI TUI（ratatui + crossterm）
- [x] CLI 非交互 CI 模式（环境变量注入）
- [x] 审计日志（service/CLI 身份 CRUD 与 switch，SSH 签名带 sha256 digest）
- [x] CLI secrets 自动化：resolve/run/k8s/external，IDENTITY/ITEM/FIELD 引用解析，CredentialDecrypted 审计链（2026-10-11）
- [x] CLI context-aware 建议阶段 1：ContextService 打分 + suggest + context map/get/unmap/status（只建议不授权）（core 30 + CLI 8 测试，2026-10-12）
- [x] CLI context-aware 建议阶段 2：shell-hook + use 别名 + 历史学习（migration 020）（core 39 + 仓库 4 + CLI 5 测试，2026-10-13）
- [x] CLI passkey create/list/show/self-test/remove（WebAuthn ES256/P-256，每条目密钥层级密封）
- [x] Passkey 跨设备同步：ItemKind::Passkey 全链路（语义快照 + tombstone + 物化臂）（2026-10-12）

### SSH Agent

- [x] UNIX socket agent 协议（list/add/remove/sign）+ Windows named pipe 传输
- [x] agent 策略引擎：PERSONA_AGENT_REQUIRE_CONFIRM / MIN_INTERVAL_MS / ENFORCE_KNOWN_HOSTS / CONFIRM_ON_UNKNOWN、TOML 策略、生物识别门控（fallback 确认）
- [x] CLI ssh 全套：import|generate|list|list-all|export-pub|add-to-agent|start-agent|stop-agent|agent-status|run|remove
- [x] git commit 签名（SSHSIG，`472a865`）；authorized_keys 分发（`85accd3`）；桌面一键集成（2026-10-05）；走查补强 + 密钥徽标 + 配置分析面板（2026-10-07/08/09）

### Server / 同步

- [x] M1 server Docker 可用化（2026-10-03）
- [x] M2 账号体系（2026-10-07）
- [x] M3 E2EE 同步接线（2026-10-04）
- [x] M4 隐私红线（默认关闭入设计）（2026-10-04）
- [x] M6 多设备真实走查（双设备演示升级真实流程）
- [x] M7 E2EE 云同步（账号模式）§5 验收锚点（2026-10-10）
- [x] Events API + 审计入库 + metrics（server）
- [x] 设备令牌 + 整库加密备份保管（同步第一阶段）；客户端备份链 core 模块 + CLI 命令
- [x] core::events::Emitter 客户端上报器（批量 + 重试）+ desktop/CLI 宿主接线
- [x] connect-server 本地自动化端点（2026-09-22）；E2EE 同步 key envelopes + conflict resolution（2026-09-24）
- [x] sync-group 模式：S1 配对与密钥层（PAKE + 组密钥管理，桌面 `725a561`）/ S2 指令流（op_id 幂等 + 定序 + 位点续传）/ S3 三形态中转（官方托管/自建 relay/局域网直传）/ S4 设备面（设备清单互见 + 自由进出）/ S5 自救口（导出/提示/恢复/服务器密文仓，`414fe4a`）

### Browser

- [x] M5 浏览器插件接账号（chromium）：sync_connect 桥发云参数 + HTTP 直连读（批1）；account_login/status/logout 账号域三件套 + sync_push_now 云端写路径 + sync_resolve_conflict（批2/3，桥协议 v7）；密文缓存离线兜底（批4a）2026-10-07 `e4ee9af`（桥侧门禁/错误分类 + 扩展侧测试，CI 全绿）
- [x] Browser extension skeleton（autofill + domain rules）
- [x] Safari WebExtension host shell（Swift bridge + manifest 同步）
- [x] Chrome/Chromium 扩展 Native Messaging + 本地服务桥
- [x] Passkeys（WebAuthn）存储 + autofill（docs/PASSKEYS_DESIGN.md）
- [x] 钓鱼防护 + 身份维度上下文切换
- [x] G1 统一令牌层（Steam Guard + RFC TOTP）；G1.5 桌面游戏令牌表单；G2 国内游戏令牌记录型

### 1Password 对齐

- [x] A 批 Secure Note 全文加密条目；B 批候选全落地（2026-09-23）
- [x] 结构化自定义字段读写链路（2026-10-09）
- [x] Quick Access 热键 + 检索浮窗（#22）；单词式 passphrase（#10，2026-09-30）；独立密码生成器（#9，2026-09-25）；UI 对齐 1Password 8 交互范式（身份维度保留为 Persona 特色）
- [x] 功能开关（feature flags，高级功能默认关，设置页可开）

### 桌面

- [x] Tauri v1.5→v2 迁移（capabilities + clipboard 插件）；TOTP 下沉 core（RFC 6238）；ApiResponse 错误码协议（REAUTH_REQUIRED / SERVICE_LOCKED）
- [x] auto-lock 全链路（core 事件 → persona://auto-lock → 倒计时横幅）；require_reauth_sensitive 开关生效；init_service 死锁修复
- [x] Vault/identity/credential 视图 + 搜索 + 三维筛选；TOTP 显示；密码 reveal（re-auth 闸门 + 30s 自动隐藏 + copy-once）
- [x] SSH Agent 控制 + 签名审批（ApprovalHandler 接缝）
- [x] 钱包 UI（地址/QR/签名确认 + 地址投毒告警）；keystore import/export 双向（2026-10-13）
- [x] 安装与打包：pnpm tauri:build 安装包（待人工验收）；deb control 补全；CI 多平台矩阵 desktop-build.yml；Windows 安装器标准升级流程（docs/WINDOWS_INSTALLER.md）
- [x] 测试矩阵：134 Rust 集成测试；前端 jest 115 → 257；tsc 类型本底

### 钱包

- [x] 钱包模型（助记词/HD 路径/链元数据/watch-only）；派生 BTC（BIP32/44 P2WPKH/P2SH-P2WPKH/Taproot）、ETH（SLIP-44）、Solana（SLIP-0010 ed25519，Phantom 兼容）
- [x] 地址编码（bech32/bech32m/Base58Check/EIP-55）；导入导出（WIF；keystore JSON Web3 Secret Storage v3 scrypt/pbkdf2，CLI --format keystore 双向，2026-10-13）
- [x] 签名：ETH（EIP-155/1559 规范向量）、Solana（ed25519 签名即 tx id）、BTC raw（BIP-143 P2WPKH + BIP-141 segwit，官方规范向量）；PSBT 切片（export/sign/finalize，2026-10-13 `671c1a0` +10 测试）；地址投毒启发式拦截（core address_poisoning.rs）
- [x] 签名/编码层第三方库化：alloy-consensus（EVM）/ rust-bitcoin（BTC）/ bech32 / bs58 / alloy-primitives；手写 RLP/BIP-143/wire 组装已删
- [x] CLI wallet create/import/derive/list/sign；passwd 口令轮换（原子 re-wrap 私钥 + 助记词两份包装）
- [x] BIP-39 passphrase（第 25 词）；详情面板种子材料 reveal；条目级独立密码；24 词全流程真实走查 14/14

### 安全 / 供应链 / 构建

- [x] 威胁模型与周期安全评审；fuzz 测试（mnemonic/keystore/QR）；供应链检查（cargo-deny、npm audit）
- [x] 可复现构建：deb 同机逐字节（scripts/normalize-deb.sh）；Dockerfile.repro 容器内同哈希（000a5265…）；跨机复验待第二台机器（docs/REPRODUCIBLE_BUILDS.md）
- [x] RustCrypto 0.10→0.11 迁移批 6 项全合（`dd4ec66` / `29a4bbc` / `83274ae` / `64c9427` / `04fb143`）
- [x] dtolnay 工具链六处钉版对齐 1.99.0（幻影版本 1.120.0 热修，`a5563d0`）；.github/dependabot.yml 已 ignore
- [x] TS7 迁移（@typescript/native 供 tsc + typescript alias 供 ts-jest；扩展 157 + desktop 723 + website build 全绿）
- [x] CI Install deps 锁文件双雷修复（`a386a4e`；typescript 钉回 ^5.9.3 + 完整 pnpm install 重建锁文件）
- [x] handlebars 三告警（#312/#313/#314）；dependabot 清账 #305 / #306-311（braces/elliptic）
- [x] 覆盖率轮次：基线与 connect-server / cli backup + travel（`b4b3a0d`）/ connect-server 两处收口

### 文档 / 站点 / 其他

- [x] 文档：统一客户端通信架构；本地服务 IPC（Unix Socket 优先，Windows 回退 Named Pipe）
- [x] 文档站 VitePress（cuihairu.github.io/persona，2026-09-24）；首页走马灯（桌面截图 + 手机原型）
- [x] Watchtower health checks：core 规则引擎（weak/reused/expired/stale）+ CLI + 桌面 health_scan（metadata-only）；HIBP breach check（k-anonymity，5 字符哈希前缀出机，网络失败降级离线规则）
- [x] BUGS.md P0 修复：logging init 幂等 + daemon 不上抛 + 2 测试（Windows 实机复测仍开放）

## References

- docs/ONEPASSWORD_FEATURES.md
- docs/REPRODUCIBLE_BUILDS.md
- docs/FEATURE_GAP_ANALYSIS.md
- docs/ROADMAP.md
- docs/MONOREPO.md
