# TODO

- [x] 缺陷：一键启用后，配置的按钮开关状态未联动（来源：用户 2026-10-14；修复 `9abce66` 前端回读 + `dc6021c` 落盘往返测试；前端 14 测试 + 后端 3 测试全绿）
- [x] 缺陷：右键菜单未国际化（来源：用户 2026-10-14；修复 `4b0ebac`；jest 80 测试 + cargo test --lib 265 测试全绿）
- [x] 文档首页预览图拆分：电脑版 / 手机版分开展示（来源：用户 2026-10-14；修复 `8f9ab29`）
- [x] 文档双语未落地（来源：用户 2026-10-14；README `012c466` + docs `7087914`；docs 30 个工程文档补 `*.zh.md` 共 7582 行）
- [x] R-P1 switchIdentity 改为服务端成功后才更新 UI（来源：2026-10-24 原型外部审查；修复 `5883ec2`）
- [x] R-P2 desktop/src/hooks/ 同款乐观更新模式排查（来源：2026-10-24 审查；修复 `5fec32d`；修 5 处 + 判定无需修 9 类；desktop 56 套件 736 例全绿）
- [x] R-P3 Principal/Action 体系化设计文档（来源：2026-10-24 审查；修复 `37ffc6d`；docs/src/design/principal-action.md + /zh/）
- [x] R-P4 跨进程统一会话/授权中心调研与方案（来源：2026-10-24 审查；修复 `4a0bb00`；docs/src/design/session-center.md + /zh/）
- [x] R-P5 同步「局域网直传」命名与实现核对（来源：2026-10-24 审查；修复 `b100345`；名实不符，已更名「局域网自建中转 / LAN self-hosted relay」6 处）
- [x] R-P6 端到端验收场景清单 + 跨平台能力矩阵（来源：2026-10-24 审查；修复 `25662c9`；docs/src/development/acceptance-matrix.md + /zh/）
- [x] DOC-GIF 配置开关效果动态图（来源：用户令；修复 `cd902aa`；SettingsModal 4 开关 off/on 对比图 + GIF 入 `docs/branding/ui/config-switches/`，流水线 `scripts/doc-config-switch-gif.mjs` 可重跑，兼 17 条断言回归测试全绿）

## 未完成

- [ ] OS 自动填充集成：iOS AutoFill 供体、macOS 系统填充；Passkey 的 OS 平台认证器（macOS LocalAuthentication / Windows Hello）同属此缺口。解锁条件：需对应平台机器（iOS=macOS+Xcode、鸿蒙=DevEco），本机 Linux 无环境。2026-10-16 巡检复核：条件仍成立（本机 Linux，无 Xcode/DevEco）
- [ ] 桌面应用级填充：Windows 桌面应用内的填充注入（现状仅浏览器桥）。解锁条件：需 Windows 桌面会话实机验收。2026-10-16 巡检复核：条件仍成立（本机无 Windows 会话）
- [ ] Web 端：1Password.com 形态的浏览器端（低优先，出现真实需求再评估）。2026-10-16 巡检复核：未出现真实需求信号
- [ ] M5 浏览器插件接账号（Safari 侧）：Swift 宿主端实现桥协议 v7（报文 → `persona bridge` 子进程封装）。解锁条件：需 macOS+Xcode 实机（挂起待实机批次，docs/BRIDGE_PROTOCOL.md §20 + browser/safari-extension/README.md）。2026-10-16 巡检复核：条件仍成立（本机无 macOS）
- [ ] Windows 实机测试与优化：编译层（x86_64-pc-windows-gnu 全绿）与 CI 守卫（rust-windows + rust-windows-desktop job）已收口，缺实机行为验收。2026-10-16 巡检复核：条件仍成立（本机 Linux，无 Windows 实机；ROADMAP.md M4 同条目一并复核）
- [ ] SCIM/SSO bridging（future）。2026-10-16 巡检复核：无触发信号，维持 future
- [ ] Watchtower 外联扩展：domain breach alerts / dark web monitoring / OSINT 标识符查询。押后（2026-09-22 决策）；重启条件 = 1Password 对齐完成 + THREAT_MODEL 变更门槛 + 明确 opt-in 形态。2026-10-16 巡检复核：条件仍成立（1Password 对齐虽收口但 THREAT_MODEL 无变更、opt-in 形态未定；FEATURE_GAP_ANALYSIS.md:90 口径未变）
- [ ] #21 团队与共享：家庭/团队共享库 + 共享条目权限，依赖账号体系。2026-10-01 用户裁定登记待办、暂不实现（docs/FEATURE_GAP_ANALYSIS.md #21）。2026-10-16 巡检复核：裁决未变，维持搁置（不重开）

## 代码深审 2026-11-01（P2/P3 待办；来源 docs/review/2026-11-01-code-review.md）

- [ ] P2 · JS-1 · 安全 · 扩展 passkey 桥未绑定 origin：`handlePasskeyPageMessage` 校验 `payload.origin === location.origin`（content.ts:1685-1695,1740-1790），不符丢弃
- [ ] P2 · JS-2 · 安全 · NMH 配对 HMAC 密钥持久化：`pairingKeyB64`/`sessionId` 移入 `chrome.storage.session`（nativeBridge.ts:576,376；违反 cloudSync.ts:16 纪律）
- [ ] P2 · JS-3 · 健壮性 · sync pull 成功路径 JSON 解析加 try/catch（cloudSync.ts:396，对齐 :389 错误体）
- [ ] P2 · JS-4 · 竞态 · QuickSearch/QuickAccessPanel 防抖竞态加请求序号守卫（QuickSearch.tsx:66-69、QuickAccessPanel.tsx:176-179）
- [x] P2 · JS-5 · 竞态 · 身份切换凭据串号：`loadCredentialsForIdentity` 加序号守卫/AbortController（usePersonaService.ts:340-341,359） · 修复 `b1ff8e6`；`switchSeq` + `credentialLoadSeq` 双序号守卫（switchIdentity 慢完成不覆盖 currentIdentity、慢凭据响应不覆盖新身份）；usePersonaService.test.tsx 36 例全绿（含 2 例新增竞态回归），desktop `npx tsc --noEmit` 干净
- [x] P2 · 安全 · blob 附件 `storage_path` 路径穿越防御：retrieve_file/delete_file 加 travel.rs 同款逃逸检查（blob.rs:199,214,251,265；当前写入方安全，防御纵深） · 修复 `6a64c0e`；新增 `resolve_within_root`（拒绝对路径/`..`/`.` 组件，口径同 travel.rs:538）覆盖 retrieve/delete × 单文件/分块 4 处；blob 15 测试全绿（含新增 `test_storage_path_traversal_rejected` 根外诱饵文件不受读写），clippy -p persona-core 干净
- [x] P2 · 可用性 · CLI 读 agent socket 无界长度分配：ssh.rs:785/824 加长度上限（与 BUG-1 同法） · 修复 `e37c372`；`MAX_AGENT_RESP_LEN`（16MiB）查前分配，覆盖 unix/windows 双路径 query_agent_identities；新增 `query_agent_identities_rejects_oversized_length`（u32::MAX 长度前缀分配前拒绝），cli 3 例全绿，clippy -p persona-cli 干净
- [x] P2 · 竞态 · agent socket bind TOCTOU + 无条件删除：transport.rs:82-90 改 bind 失败不先删/验证陈旧（passkey_bridge.rs:177 同） · 修复 `ca27e8f`；unix bind 改"先 bind 失败才查陈旧"：活 socket 报错拒绝劫持、仅陈旧残骸（非 socket/连不上）删后重试；新增 `is_stale_socket` 并复用于 passkey_bridge.rs 审批 socket；transport 6 测试全绿（新增 live 拒绝 + 陈旧接管 2 例），clippy -p persona-ssh-agent 干净，desktop/src-tauri cargo check 通过
- [x] P3 · 健壮性 · PERSENC1 头部长度溢出：file_crypto.rs:113-116 改 checked_add/界检查 · 修复 `3ebf39b`；decrypt_bytes 的 enc_len 切片改 `cursor.checked_add(enc_len)`（u64 长度前缀不受信，溢出即 Bad ciphertext len 而非 panic）；file_crypto 5 测试全绿（新增 enc_len=u64::MAX 用例）
- [x] P3 · 健壮性 · Web3 keystore scrypt 参数溢出：wallet_encryption.rs:306 改 checked_mul + 先校验参数 · 修复 `ae9159b`；import/export 两侧 128*r*n 改 checked_mul（u32::MAX×u32::MAX 溢出即 work factor too high 而非 panic/回绕）；wallet_encryption 29 测试全绿（新增 `keystore_rejects_overflowing_scrypt_work_factor`）
- [x] P3 · 健壮性 · stop_agent 陈旧 pidfile 误杀：ssh.rs:1508-1512 kill 前验证 /proc/<pid>/cmdline · 修复 `72a9839`；`stop_agent_pid` 改三态（Stopped/AlreadyGone/Refused）：kill 前读 /proc/<pid>/cmdline 确认是 persona-ssh-agent，PID 复用即拒绝不误杀，进程已不在则当陈旧 pidfile 清理；cli stop_agent 3 测试全绿（含验证分判 stale/reused），clippy -p persona-cli 干净
- [x] P3 · 卫生 · server-18996.log 运行时日志被 git 跟踪：git rm --cached + .gitignore 加 `*.log` · 修复 `317f0d5`；`git rm --cached server-18996.log`（文件留盘），.gitignore 加 `*.log`（`git check-ignore` 验证已忽略）
- [x] P3 · 卫生 · website `lint` 死脚本：删脚本或装 eslint 依赖+配置（website/package.json；CI 不跑） · 修复 `cc1ea45`；删死 `lint` 脚本（无 eslint 依赖/配置，CI 从不跑，运行即 command not found）；website/package.json JSON 校验通过
