> [English](ROADMAP.md) | **中文**

# Persona 路线图与 TODO（详细版）

优先级政策（2026-09）：密码管理器赛道先对齐 1Password。钱包赛道保持实验性，
押后到该基础被验证之后——钱包的安全要求（不可逆结果、签名确认、交易级威胁
模型）值得单独做一轮设计。每日任务跟踪在根目录 [TODO](../TODO.md)；本文件
是里程碑视图。

产品定位（2026-10）：Persona 定位为**本地优先的多分身数字身份运行时**，而
不是又一个密码管理器。密码 / SSH key / TOTP / 钱包 / Passkey 是身份*材料*；
揭示 / 复制 / 填充 / 签名 / 保存是由策略引擎治理的*动作*；场景组织为（未来
的）*主体*之下的*分身*。下面的 1Password 对齐赛道是能力基准，不是产品叙事。
概念文档：`docs/src/concepts/`。

里程碑 0–3 —— 基础（已完成）

- [x] Monorepo + CI + Conventional Commits + 供应链检查（cargo-deny、npm/pnpm audit）
- [x] Workspace v2 schema + migrations；service/CLI 的审计日志
- [x] Per-item key 层级（包裹的 item key）；类 SRP 远程认证抽象；生物识别 hooks；自动锁定 + 敏感操作重认证
- [x] CLI 对齐：identity/credential CRUD、TOTP（QR 设置 + watch）、密码生成器、TUI、导出/导入（gzip + 加密）、非交互 CI 模式
- [x] SSH agent：策略引擎（per-key/per-host 规则、限速、known_hosts、glob 允许/拒绝、生物识别门禁）、全量 CLI 控制、E2E 协议测试
- [x] 浏览器：Chromium 扩展 + Native Messaging 桥（配对、HMAC 请求认证、origin 绑定、user gesture、自动填充 MVP、防钓鱼）；Safari host 外壳

里程碑 4 —— 1Password 对齐（当前焦点）

- [x] Passkey（WebAuthn）：存储模型 + 自动填充 —— 设计见 `PASSKEYS_DESIGN.md`（P1 core/CLI 完成，含 `passkey self-test`，P2 浏览器拦截完成，含 webauthn.io/GitHub 真站互操作，P3 桌面完成 —— PasskeyPanel 列表/详情/删除 + 审批门禁 + 重认证/生物识别接线 + 域名策略；P4.1 provider 协议 + P4.4 provider 审计元数据 2026-09-24 完成。剩余：P4.2/P4.3 OS provider 需要 macOS/Windows 实机（已登记为缺口，与 OS 自动填充 #13 同一阻塞），P4.5 CXF 按设计押后到标准定稿）
- [x] 1Password 迁移：1PUX 导入 —— core 内的 parser + 纯导入规划器（`import_1pux`）、`persona import-1pux --dry-run` 计划预览（per-vault identities、Login/API Credential/SSH Key 映射、TOTP 拆为专用凭据、未映射类别/归档条目/附件的跳过报告）
- [x] Watchtower 级健康检查：规则引擎（弱/重复/过期/陈旧；core + CLI + 桌面命令层，仅元数据报告）
- [x] Watchtower：桌面 UI 面板（扫描 + 可选 HIBP 泄露检查；按严重度分组的仅元数据报告）
- [x] Watchtower：经 HIBP k-匿名做泄露检查（离线 BreachChecker 接缝；`persona watchtower --check-breaches` + 桌面 `health_scan` flag；只发送 5 字符哈希前缀出机器，网络故障降级为离线规则）
- [x] 桌面应用：在 Tauri v2 上接入 core（解锁、列表、CRUD；保险库/identity/credential 视图；搜索 + 类型/标签/收藏过滤）
- [x] 桌面：TOTP 显示（共享 core 路径，RFC 6238 向量）；密码揭示流（重认证门禁 + 30s 自动隐藏 + 一次性复制剪贴板）；SshKey/ApiKey/BankCard 渲染
- [x] 桌面：SSH agent 控制；经应用内弹窗 + 系统通知的签名审批（agent 在 ApprovalHandler 接缝之后保持无 UI；CLI 的 TTY 提示不变）
- [x] 桌面：自动锁定端到端（后端事件 → 倒计时横幅 → 强制锁定清掉内存中的主密码，即使前端已不在）
- [x] 浏览器：打磨过的 TOTP 自动填充 UX（登录后链式填充、陈旧码重取、剩余秒数提示、多候选选择器 —— 2026-09）
- [x] SSH agent：真机 E2E 测试 —— `ssh -T git@github.com` 于 2026-09-25 通过（经 `scripts/e2e-ssh-github.sh` 的真实 GitHub 往返，"successfully authenticated"；负向用例 —— 拒绝确认、限速、审计行 —— 当日关闭；审计链已验证）
- [ ] SSH agent：Windows 专项测试与优化 —— 编译层面 2026-09-28 关闭（`cargo check --target x86_64-pc-windows-gnu` 全 workspace 绿）；运行时验收（named-pipe 审批流、生物识别门禁、NSIS 安装器、SSH agent named-pipe 端到端）需要真实 Windows 机器 —— 阻塞于硬件，与 OS 自动填充（缺口 #13）同族阻塞
- [x] 可复现构建（2026-09-24：deb 同机逐字节可复现；工具链经 `rust-toolchain.toml` + CI 钉在 1.97.0；`$HOME` 经 `scripts/build-repro.sh` 重映射；剩余差距见 `docs/REPRODUCIBLE_BUILDS.md`）

里程碑 5 —— 钱包毕业（押后至里程碑 4 之后；今天为实验性）

现有实验基础：BTC（BIP-143 P2WPKH）/ ETH（EIP-155/1559）/ Solana 在审计过的
crates（rust-bitcoin、alloy、bech32）上的派生与签名，CLI 钱包流，官方测试向量
作为回归基准。

- [x] `docs/WALLET_DESIGN.md`（2026-10-13：密钥层级盘点 —— BIP39 mnemonic + BIP32 xprv 在独立钱包密码下双重包裹，主密码轮换刻意不动 `crypto_wallets`；identity 绑定经 `CryptoWallet.identity_id`；签名确认 UX 策略；威胁模型钱包章节落入 THREAT_MODEL.md。当日落地跟进：`persona wallet passwd`（经 `change_wallet_password`/`change_mnemonic_password` 对私钥 + mnemonic 的原子重包，新密码仅交互式）、后端 anti-poisoning 强制、桌面 keystore 上膛；v2 惰性重包 migration 仍待做）
- [x] keystore JSON 导入/导出（2026-10-13：完整 Web3 Secret Storage v3 —— scrypt/pbkdf2 KDF（untagged params）、AES-128-CTR 之前验证 keccak MAC、geth 默认导出参数（n=2^18,r=8,p=1）带 256MiB 导入内存上限、恒定时间 MAC 比较；canonical geth spec 向量 + OpenSSL 跨语言 KDF 钉为测试；CLI `wallet import/export --format keystore`）
- [x] PSBT 工作流（2026-10-13：单签 P2WPKH 切片 —— core `crypto/transaction_psbt.rs` 的 `export_bitcoin_psbt`/`sign_bitcoin_psbt`/`finalize_bitcoin_psbt`（BIP-174 经 rust-bitcoin；finalizer 自写，因该 crate 丢弃了它）、CLI `wallet export-psbt/sign-psbt/finalize-psbt`；export 无需密钥材料，watch-only 钱包可准备，sign 强制 per-input witness-script 归属，finalize 拒绝 0/多部分签名与非 SIGHASH_ALL；字节级回归锚：直接签名与 PSBT 路径产出相同 raw tx；multisig `Psbt::combine` 与桌面 UI 仍开放）
- [x] 签名确认核对收款地址、金额、手续费与 chain id（防 address-poisoning）（2026-10-13：桌面确认弹窗已有；后端强制落地 —— core `crypto/address_poisoning.rs` 的 `detect_address_poisoning`/`enforce_poisoning_check`（前 6 + 后 6 字符、大小写不敏感、字符安全），CLI `create-transaction --sign` 在密码提示之前拒绝伪造收款方，除非 `--confirm-poisoning-check`；桌面 `wallet_sign_transaction` 以确认弹窗的二次确认 ack（`confirm_poisoning_check`，serde 默认 false）强制同款；策略见 `docs/WALLET_DESIGN.md` §5 + THREAT_MODEL.md 钱包章节）
  - [x] 桌面确认弹窗存在：from/to/amount/fee 展示、address-poisoning 启发式警告、密码留在弹窗内、签名先验证后持久化
- [x] 桌面钱包 UI（地址、二维码、确认）
- [ ] 开放问题：硬件钱包（Ledger/Trezor）纳入本轨还是另立后续轨

里程碑 6 —— 服务器与同步（可选）

- [x] Events API、审计摄取、metrics
- [x] 设备令牌 + 加密保险库备份保管（`/api/v1/backups`：多设备 bearer token、带 sha256 去重的流式上传、版本化 list/download/delete、保留策略；服务器只持有 PERSENC1 密文 —— 同步阶段 1，2026-09）
- [x] 客户端备份链（core `backup` feature：VACUUM INTO 快照 → gzip → PERSENC1，与 `--encrypt` 导出字节兼容；`BackupClient` 对接保管端点；CLI `persona backup push/list/pull/restore/delete` —— push 无需主密码解锁，restore 经已验证临时文件 staged 并保留 `.bak`；附件不在 v1 备份内，2026-09）
- [x] 类 Connect 的本地优先 secrets 自动化端点（设计文档 `CONNECT_AUTOMATION_DESIGN.md`，2026-09）：`connect-server/` 内嵌 axum 监听器绑定 `127.0.0.1`，带 Host-header 白名单（对 DNS rebinding 回 421），scope token 只展示一次；CLI `persona connect token create/serve`；阶段 1–4 全部落地
- [x] 端到端加密同步（密钥信封、冲突解决）
  - [x] 同步阶段 2 core（2026-09-22）：设备信封（DR-1，X25519 `persona-dev-env-1`）+ 组密钥层级；oplog + LWW/冲突双版本纯逻辑（DR-4）；本地同步存储（migration 014）；服务器密文中继 `/api/v1/sync/*`（migration 0004：设备注册 / 信封保管 / 幂等 oplog push / 游标分页 pull）；客户端引擎（push/pull 周期 + Lamport clock + 出行门禁）；服务器只持密文、重放幂等、乱序容忍、主密码轮换免疫，以及在真实 TCP 上的双设备收敛（离线并发编辑保留双版本）；THREAT_MODEL "E2EE sync relay" 章节
  - [x] 阶段 3 接线（2026-10-04 审计）：桌面设备管理 UI（SettingsModal sync 段 + SyncConflictsModal）、service 写路径经 `attach_sync_capture` 喂 `record_local_change`、带 epoch 乐观锁互斥的组密钥轮换 —— 命令层测试绿；STORAGE_AND_SYNC.md 一致
- [x] 同步组模式作为默认同步路径（设计 `sync-group-mode.md`）：动态密码 PAKE 配对、指令流同步、三种中继形态 —— S1 配对协议 + 零知识配对中继 + relay 客户端 + 桌面命令层/UI 于 2026-10-04 落地（测试 + `scripts/verify-sync-group-pairing.sh`，真桌面走查 M6-批2/2b）；S2 指令流收敛（快照水位门禁 + 真实 TCP 收敛）、S3 中继形态（同一 `persona-server` 二进制，`base_url` 三态）、S4 设备面（remark 自助）、S5 自救（加密备份导出/恢复 + 数据丢失强警告）于 2026-10-05~10-10 全部关闭；设计文档中的状态表于 2026-10-12 对齐
- [x] 文档化的存储/同步选项：纯本地、自托管云、Persona-server 辅助（`STORAGE_AND_SYNC.md`，2026-09）

里程碑 7 —— 身份运行时（定位与概念；功能轨随后）

- [x] 概念文档：`docs/src/concepts/` —— identity / context / material / policy / action / principal（2026-10-04）
- [x] 站点文案与术语：homepage / intro / architecture / security 去「password-manager」化；「零知识」统一为「本地优先 + 端到端加密」（zero-knowledge 仅保留用于凭据存储语义）
- [x] 上下文感知的身份建议阶段 1+2（设计 `CONTEXT_AWARE_DESIGN.md`）：core `ContextService` 在 `core/src/context.rs`（纯评分：repo/project 精确匹配 1.0 + host 正则 0.8 + 学习候选 0.7，阈值 0.6，active 优先决胜，覆盖链 `PERSONA_CONTEXT_OVERRIDE` > repo-local `.persona/context.toml` > 全局 `~/.persona/context.toml` > 学习历史 > active）+ `persona suggest [--json|--short]` + `persona context map/get/unmap/status`（全部 workspace 豁免，可在任何项目目录使用）；阶段 2（2026-10-13）：`persona shell-hook [bash|zsh]` prompt 片段（⛵ 候选前缀、`PERSONA_NO_CONTEXT` opt-out、`suggest --short` 喂入）、`persona use` 一键确认（= `switch`，匹配 top candidate 时审计携带建议原因）、本地学习表（migration 020，默认关闭，`persona context learn on/off/status/clear`，只记录 cwd SHA-256 + identity，永不同步）；context 只建议、永不授权 —— 激活仍是 `persona switch`。阶段 3（2026-10-13）：`persona ssh run --host` 的 host 维度建议（仅目标 host 信号，stderr 提示行，`PERSONA_NO_CONTEXT` opt-out，任何加载失败静默降级）+ `--identity` 过滤实装（CLI 先校验名字；agent 经 `PERSONA_AGENT_IDENTITY` 只加载该 identity 的 SSH key，未知名字不加载任何东西，fail-closed）。阶段 4（桥协议字段 + 桌面/浏览器建议排序）：桥 + 浏览器两半于 2026-10-14 交付 —— `get_suggestions` 可选 `host`/`cwd` 信号，响应 `context` 字段 + 每条目 `identity`，被建议 identity 的凭据合并并排第一（同一 core `suggest()`；`PERSONA_NO_CONTEXT` 门禁；静默降级）；扩展 popup 消费两者（保留桥排序、identity 标签、context 提示；5 个 helper 测试）；9 个 CLI + 164 个扩展测试绿；桌面托盘候选仍在
- [ ] Principal / Agent 限定：协议与审计中的可选 `principal_id`；per-principal 动作白名单（保留方向，无时间承诺）

持续质量

- [x] 威胁模型 + 定期审查流程（`THREAT_MODEL.md`）
- [x] Fuzz 风格解析器测试：passkey clientData/creation-options 解析有确定性变异 harness（`core/src/crypto/passkey.rs` §12）；mnemonic 由 proptest 风格属性测试覆盖；keystore 与 QR 码解码于 2026-10-14 获得确定性变异 harness（字节翻转 / 截断 / 字段级篡改 / 伪造图片头 —— 永不 panic，外加 harness 暴露的 dklen 与 pbkdf2-iteration 上限作为 hostile-input 拒绝服务防护）。cargo-fuzz 脚手架于 2026-10-14 落地（`fuzz/` 是独立 workspace、钉在 nightly —— libFuzzer 需要根 1.97.0 钉版禁止的 `-Zsanitizer` 通道 —— 目标含 OpenSSH 私钥导入、Web3 Secret Storage v3、context.toml maps 与 WebAuthn creation-options；corpus/crash 产物 gitignore，CI 不跑，因无 nightly runner）。日志 secrets 脱敏策略已完成
- [ ] KDF 参数审查：两条路径均有文档（`KEY_HIERARCHY.md`）；PBKDF2 迭代次数与 Argon2 参数每季度重审，变更经 re-wrap/re-encrypt migration 应用 —— **最近一次审查 2026-10-12**（`docs/review/2026-10-12-kdf-parameter-review.md`）：所有 Argon2id 路径达到/高于 OWASP 底线（保留），PBKDF2-HMAC-SHA256 100k 低于 OWASP 建议（600k）6 倍 —— 提升提案已登记，等待用户签批（re-wrap migration，决定前不改代码）
