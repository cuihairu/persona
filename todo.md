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
