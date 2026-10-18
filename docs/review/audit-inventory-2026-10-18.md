# Persona 审计全仓清点（2026-10-18）

> 依据 `docs/review/task-list-2026-10-18.md` §0 执行。基线 HEAD `80bdcdb`（merge 后，含核对 c436568 + phase a/b/c）。
> 本表是**审计增量**，不覆盖/删除/重写 `todo.md` 需求、用户决定、历史验收证据与 `BUGS.md`。
> A0.5 口径：本机**无 cargo/rustc/rustup**（`command -v` 三者皆空）→ Rust 侧一律「未本地编译，待 CI」；不伪造测试或设备验证。

## 清点面（git ls-files）

827 受控文件：desktop 219 / docs 165 / core 133 / browser 75 / mobile 54 / cli 45 / server 25 / website 17 / vendor 14 / .github 13 / agents 12 / scripts 10 / fuzz 7 / .spec-workflow 7 / docker 3。

## 五类计数

| 分类 | 数 | AUDIT 条目 |
|---|---|---|
| 已证实缺陷（已修） | 4 | AUDIT-001 命名冲突、AUDIT-002 工具链、AUDIT-010 审计门禁、AUDIT-003 日志卫生（phase-d WIP，stash） |
| 风险待复现 | 3 | AUDIT-021 明文泄漏（P0，主向量初核无实锤，待全量+canary）、AUDIT-032 SSH Windows（BLOCKED 无工具链/真机）、AUDIT-011 发布工作流权限 |
| 功能缺口 | 2 | AUDIT-012 发布签名（P2，未做）、AUDIT-050/060 平台验收矩阵 + 安全回归矩阵 |
| 仅需产品决策 | 5 | AUDIT-020 KDF 参数、AUDIT-030 浏览器桥确认 UX、AUDIT-041 同步冲突口径、AUDIT-051 未实现填充、AUDIT-052 解锁体验（均需产品拍板，§0 禁擅自实现） |
| 已完成无需重复 | 2 | AUDIT-030 浏览器桥缺口核对（文档边界已准确，无误报风险）、AUDIT-013 CI/本地门禁口径（phase b 已对齐） |

> 说明：AUDIT-004/022/023/024/031/040/042 等 P1 项**本轮未逐项深核**，状态＝未核对，留后续；不计入上表以免虚报。

## 已修项证据（前序 commit）

- AUDIT-001/002 → `071793d`（TODO.md→TODO_BACKLOG.md + 工具链统一 1.97.0）
- AUDIT-010 → `0911993`（审计门禁去 continue-on-error/|| true）
- 核对六条 → `c436568`（六条全属实）
- phase c → `ec4ba92`（浏览器桥核对 + SSH Windows BLOCKED）
- AUDIT-003 → phase-d WIP（stash@{0}：untrack server-18996.log + .gitignore *.log）

## 未修 + 原因

- AUDIT-021（P0）→ **已修待 CI 编译/测试验证**（`876369c`）：全仓排查后，主泄漏向量（CLI `--reveal` 有确认门 credential.rs:590；`PERSONA_MASTER_PASSWORD` 只传 authenticate_user/子进程 env，不落日志/stdout/argv；`CachedAutoLockManager` Debug 用 finish_non_exhaustive 不泄）**无活跃明文泄漏**。但发现 13 个含密 data struct 派生 Debug（`core/src/models/credential.rs`：PasswordCredentialData/SshKeyData/TwoFactorData/GameTokenData/ApiKeyData/BankCardData/CryptoWalletData/ServerConfigData/IdentityData/SoftwareLicenseData/SecurityQuestion + 2 Legacy 镜像），一旦上层 `{:?}` 即泄 SSH 私钥/TOTP seed/密码/API key/CVV/助记词。已全部改为手写脱敏 Debug（secret 字段输出 `[redacted]`，非密字段保留），只强化不弱化边界。**注：本机无 cargo/rustc/rustup，未能编译/跑测试；13 个手写 impl 需 CI 编译+测试验证，且 AUDIT-021 要求的合成 canary 回归测试本轮未加（同样需 Rust 工具链）→ 待 CI/有工具链后补。**
- AUDIT-032：BLOCKED —— 缺 Rust 工具链 + 真实 Windows 桌面会话。
- 其余 P1/P2：未核对或需产品决策，逐项见 task-list。
