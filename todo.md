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

## 未完成

- [ ] OS 自动填充集成：iOS AutoFill 供体、macOS 系统填充；Passkey 的 OS 平台认证器（macOS LocalAuthentication / Windows Hello）同属此缺口。解锁条件：需对应平台机器（iOS=macOS+Xcode、鸿蒙=DevEco），本机 Linux 无环境。2026-10-16 巡检复核：条件仍成立（本机 Linux，无 Xcode/DevEco）
- [ ] 桌面应用级填充：Windows 桌面应用内的填充注入（现状仅浏览器桥）。解锁条件：需 Windows 桌面会话实机验收。2026-10-16 巡检复核：条件仍成立（本机无 Windows 会话）
- [ ] Web 端：1Password.com 形态的浏览器端（低优先，出现真实需求再评估）。2026-10-16 巡检复核：未出现真实需求信号
- [ ] M5 浏览器插件接账号（Safari 侧）：Swift 宿主端实现桥协议 v7（报文 → `persona bridge` 子进程封装）。解锁条件：需 macOS+Xcode 实机（挂起待实机批次，docs/BRIDGE_PROTOCOL.md §20 + browser/safari-extension/README.md）。2026-10-16 巡检复核：条件仍成立（本机无 macOS）
- [ ] Windows 实机测试与优化：编译层（x86_64-pc-windows-gnu 全绿）与 CI 守卫（rust-windows + rust-windows-desktop job）已收口，缺实机行为验收。2026-10-16 巡检复核：条件仍成立（本机 Linux，无 Windows 实机；ROADMAP.md M4 同条目一并复核）
- [ ] SCIM/SSO bridging（future）。2026-10-16 巡检复核：无触发信号，维持 future
- [ ] Watchtower 外联扩展：domain breach alerts / dark web monitoring / OSINT 标识符查询。押后（2026-09-22 决策）；重启条件 = 1Password 对齐完成 + THREAT_MODEL 变更门槛 + 明确 opt-in 形态。2026-10-16 巡检复核：条件仍成立（1Password 对齐虽收口但 THREAT_MODEL 无变更、opt-in 形态未定；FEATURE_GAP_ANALYSIS.md:90 口径未变）
- [ ] #21 团队与共享：家庭/团队共享库 + 共享条目权限，依赖账号体系。2026-10-01 用户裁定登记待办、暂不实现（docs/FEATURE_GAP_ANALYSIS.md #21）。2026-10-16 巡检复核：裁决未变，维持搁置（不重开）
- [ ] DOC-GIF · P2 · 文档 · 配置开关效果动态图：每个开关 off→on 对比 + GIF（验收：清单内每开关有 off/on 对比 + GIF；流水线可重跑；兼作配置效果回归测试）

## 代码深审 2026-11-01（P2/P3 待办；来源 docs/review/2026-11-01-code-review.md）

- [ ] P2 · JS-1 · 安全 · 扩展 passkey 桥未绑定 origin：`handlePasskeyPageMessage` 校验 `payload.origin === location.origin`（content.ts:1685-1695,1740-1790），不符丢弃
- [ ] P2 · JS-2 · 安全 · NMH 配对 HMAC 密钥持久化：`pairingKeyB64`/`sessionId` 移入 `chrome.storage.session`（nativeBridge.ts:576,376；违反 cloudSync.ts:16 纪律）
- [ ] P2 · JS-3 · 健壮性 · sync pull 成功路径 JSON 解析加 try/catch（cloudSync.ts:396，对齐 :389 错误体）
- [ ] P2 · JS-4 · 竞态 · QuickSearch/QuickAccessPanel 防抖竞态加请求序号守卫（QuickSearch.tsx:66-69、QuickAccessPanel.tsx:176-179）
- [x] P2 · JS-5 · 竞态 · 身份切换凭据串号：`loadCredentialsForIdentity` 加序号守卫/AbortController（usePersonaService.ts:340-341,359） · 修复 `b1ff8e6`；`switchSeq` + `credentialLoadSeq` 双序号守卫（switchIdentity 慢完成不覆盖 currentIdentity、慢凭据响应不覆盖新身份）；usePersonaService.test.tsx 36 例全绿（含 2 例新增竞态回归），desktop `npx tsc --noEmit` 干净
- [ ] P2 · 安全 · blob 附件 `storage_path` 路径穿越防御：retrieve_file/delete_file 加 travel.rs 同款逃逸检查（blob.rs:199,214,251,265；当前写入方安全，防御纵深）
- [ ] P2 · 可用性 · CLI 读 agent socket 无界长度分配：ssh.rs:785/824 加长度上限（与 BUG-1 同法）
- [ ] P2 · 竞态 · agent socket bind TOCTOU + 无条件删除：transport.rs:82-90 改 bind 失败不先删/验证陈旧（passkey_bridge.rs:177 同）
- [ ] P3 · 健壮性 · PERSENC1 头部长度溢出：file_crypto.rs:113-116 改 checked_add/界检查
- [ ] P3 · 健壮性 · Web3 keystore scrypt 参数溢出：wallet_encryption.rs:306 改 checked_mul + 先校验参数
- [ ] P3 · 健壮性 · stop_agent 陈旧 pidfile 误杀：ssh.rs:1508-1512 kill 前验证 /proc/<pid>/cmdline
- [ ] P3 · 卫生 · server-18996.log 运行时日志被 git 跟踪：git rm --cached + .gitignore 加 `*.log`
- [ ] P3 · 卫生 · website `lint` 死脚本：删脚本或装 eslint 依赖+配置（website/package.json；CI 不跑）
