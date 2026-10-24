# 验收场景清单与跨平台能力矩阵

> English | **中文**

一句话定位：**验收不只看测试绿**。这份清单把验收分成四层（编译成功 / 模拟测试 / 真实交互 /
长期运行），先给当前盘点，再给能力矩阵与逐条场景，最后是待建清单。

## 四层判定标准

| 层       | 定义                                                                     | 合格证据形态                      |
| -------- | ------------------------------------------------------------------------ | --------------------------------- |
| 编译成功 | 在该平台/工具链下能产出可运行产物                                        | CI job 通过，或本机构建日志       |
| 模拟测试 | 在受控替身中自动断言（内存 DB、mock IPC、jsdom、临时 HOME、真回环 TCP）  | `cargo test` / `nextest` / `jest` |
| 真实交互 | 与真实外部系统往返：真 sshd / 真 GitHub / 真浏览器 / 真桌面会话 / 真硬件 | 手动脚本 + 实际输出，或实机记录   |
| 长期运行 | 多小时级耐久、崩溃恢复、后台常驻、重启恢复                               | soak 作业或定时长时作业的产物     |

**状态标签**（沿用
[2026-10-18 审计任务清单](https://github.com/cuihairu/persona/blob/main/docs/review/task-list-2026-10-18.md)
的 AUDIT-061 四档，另加两档描述移动端）：

- **已实现且测试**：有代码，有自动化测试断言其行为
- **已实现但未实机验证**：有代码，行为正确性未在该平台真实执行过
- **设计中**：方案已写，代码未落地
- **明确不支持**：明确不在此平台支持（含 VM/CI 无硬件的情形）
- **有骨架**：目录与桥接口存在，但桥返回 stub 或不可编译
- **无实现**：不存在

## 现状盘点（2026-10-24 计数口径见脚注）

### 测试资产

| 表面                                      | 测试数                                                              | CI job                                           | 产物                           |
| ----------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------ |
| `core`（persona-core）                    | 行内 1,198 + `core/tests/` 7 个集成文件                             | `rust` / `rust-windows` / `rust-windows-desktop` | 仅 lib                         |
| `cli`（persona）                          | 行内 521 + 19 集成（assert_cmd 驱动）                               | 同上                                             | `persona` 二进制，**未发布包** |
| `agents/ssh-agent`                        | 行内 80 + 13（`e2e_test.rs` 10、`daemon_test.rs` 3）                | 同上                                             | 二进制，未发布                 |
| `server`（persona-server）                | 行内 131 + 6（真 TCP 双设备）                                       | 同上 + `docker.yml`                              | GHCR 镜像                      |
| `connect-server`                          | 行内 37，**无 `tests/` 目录**                                       | `rust`                                           | 无（内嵌于桌面/CLI）           |
| `desktop/src-tauri`（**独立 workspace**） | 行内 261 + 8 集成                                                   | `desktop` / `rust-windows-desktop`               | deb/rpm/AppImage/nsis/dmg      |
| `desktop/src` 前端                        | 726 个 `it()`，56 个测试文件                                        | `desktop`（`test:ci:coverage`）                  | 打进桌面包                     |
| `browser/chromium-extension`              | 164 个 `it()`/`test()`                                              | `web`                                            | CI 构建解压扩展，**未发布**    |
| `browser/safari-extension`                | **0**（`Package.swift` 无测试 target）                              | 无                                               | 无                             |
| `mobile/rust`                             | 20（`jni_android.rs` 未测）                                         | `rust`（宿主）+ `android`（aarch64）             | `libpersona_mobile.so`         |
| `mobile/android`                          | **0**（无测试源集）                                                 | `desktop-build.yml::android`                     | arm64 APK                      |
| `mobile/ios`                              | 2 个 XCTest，**从未执行**                                           | 无                                               | 无                             |
| `mobile/harmony`                          | **0**（hypium 已声明，无测试目录）                                  | 无                                               | 无                             |
| `website`                                 | **0**                                                               | `web`（仅 `run build`）                          | CI 构建，未部署                |
| fuzz                                      | 4 个 target，语料本地齐全（2,176/857/744/127 输入）                 | **不在 CI**                                      | 无                             |
| 跨实现 oracle                             | 1（`scripts/steam_guard_verify.py` 独立实现，向量被 core 测试钉死） | `rust`                                           | —                              |

### 关键事实（诚实边界）

1. **`desktop/src-tauri` 是独立 cargo workspace**：根级 `cargo clippy --workspace --all-features`
   不覆盖它，需要 `--manifest-path desktop/src-tauri/Cargo.toml` 单独跑（fmt 同理）。
2. **iOS 与 HarmonyOS 从未在任何地方编译过**——不在 CI，也没有本机编译证据；
   `rust-toolchain.toml` 只装了 `aarch64-linux-android` target。
3. **Android APK 能构建但从未真机运行**；测试源集为 0。
4. **长期运行零覆盖**：最长 job 120 分钟，nextest 240s 硬杀，无 soak 作业、无多目标
   `Makefile` 长时任务。
5. **真实交互全部不在 CI**：`scripts/e2e-ssh-github.sh`、`verify-account-redline.sh`、
   `verify-sync-group-pairing.sh`、`verify-biometric-linux.md` 都是手动脚本；`Xvfb` 与 `playwright`
   全仓零命中。
6. **`ci.yml` 的 biometric spike 是 `continue-on-error` 且显式标注非门禁**——因为 runner VM 没有
   Secure Enclave / Touch ID / Windows Hello，探针输出本身就是交付物。
7. **工具链**：`rust-toolchain.toml` 钉 `1.97.0`，workflow 里的 `dtolnay/rust-toolchain@stable`
   不生效（目录级覆盖优先）。
8. **`Makefile` 的 `release-*` 目标调用不存在的 `scripts/release.sh`**——悬空目标（与"版本号只能
   人工给出"的红线一致；`git tag` 里只有 `nightly`）。
9. `agents/ssh-agent/TESTING.md` 说"7 passed; 2 ignored"，但 `e2e_test.rs` 现有 10 个 `#[test]`——
   文档过期。
10. **`docs/src/` 此前没有任何验收/门禁内容**；`.github/ISSUE_TEMPLATE` 也没有验收字段。本页是新的。

### 平台能力矩阵

| 平台 / 表面                                           | 编译成功                                                                   | 模拟测试                      | 真实交互                                       | 长期运行  |
| ----------------------------------------------------- | -------------------------------------------------------------------------- | ----------------------------- | ---------------------------------------------- | --------- |
| Rust 核心（core/cli/server/ssh-agent/connect-server） | ✅ ubuntu + windows-gnu/msvc check                                         | ✅ 行内 1,930 + 集成 65       | ⚠️ 仅手动脚本                                  | ❌ 零覆盖 |
| 桌面（src-tauri，ubuntu）                             | ✅                                                                         | ✅ 261 + 8                    | ⚠️ Linux 走查管线在本机，不在 CI               | ❌        |
| 桌面 Windows                                          | ⚠️ **仅 `cargo check`**（`rust-windows-desktop` 注释：运行时行为仍需真机） | ⚠️ 仅宿主 `cargo test` 的部分 | ❌ 命名管道审批 / TPM / NSIS 均未实机          | ❌        |
| 桌面 macOS                                            | ⚠️ 仅 `desktop-build.yml::build` 能构建                                    | ⚠️ 无 macOS 测试 job          | ❌ Secure Enclave / Safari 桥未实机            | ❌        |
| 桌面 Linux                                            | ✅                                                                         | ✅                            | ⚠️ 手动脚本 + 本机截图管线（不在 CI）          | ❌        |
| 浏览器扩展 Chromium                                   | ✅ `web` build                                                             | ✅ 164（jsdom）               | ❌ 无真实浏览器↔host 往返                     | ❌        |
| Safari 扩展                                           | ❌ 无构建                                                                  | ❌ 0 测试                     | ❌                                             | ❌        |
| Android                                               | ✅ arm64 APK（`desktop-build.yml::android`，**受 nightly 48h 门禁影响**）  | ❌ 0 测试                     | ❌ 从未真机运行                                | ❌        |
| iOS                                                   | ❌ **从未编译**（`Persona.h` 只暴露 10 个生命周期符号，业务 FFI 未暴露）   | ❌ 2 个 XCTest 从未执行       | ❌                                             | ❌        |
| HarmonyOS                                             | ❌ 从未编译（无 hvigor wrapper，只能在 DevEco Studio 内构建）              | ❌ 0 测试                     | ❌                                             | ❌        |
| 自建 server（GHCR）                                   | ✅ docker buildx                                                           | ✅ 6 个双设备测试             | ⚠️ `verify-account-redline.sh` 手动起真 server | ❌        |

### 跨客户端一致性：最大的洞

`desktop/src-tauri/src` 里搜锁/身份通知到**其他进程**的出口：**零命中**。唯一的跨进程入口是
`passkey_bridge.rs` 的 Unix socket（且只有审批请求入站）。每个客户端各自打开同一个 vault 文件、
各持一份 `PersonaService`，没有共享锁状态、没有活动身份广播、没有权限撤销。

## 端到端场景清单

状态列用上面的标签；"证据"列写现有锚点或明确缺口。

### 身份切换

| ID  | 场景                                                      | 层       | 状态            | 验收条款                                                                         | 证据 / 缺口                                                                |
| --- | --------------------------------------------------------- | -------- | --------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| S01 | 桌面切换身份后，CLI / 浏览器扩展 / 移动端看到同一活动身份 | 模拟测试 | ❌ 无实现       | 两个客户端共享一个 vault，桌面切到 B 后另一端返回 B                              | **缺两客户端一 vault 的 harness**；`connect-server` 连活动身份都不读       |
| S02 | 切换后端失败时 UI 保留原身份并报错                        | 模拟测试 | ✅ 已实现且测试 | `success:false` / 抛异常 / `silent` 三臂均断言原身份不变、不拉目标凭据、不弹成功 | `desktop/src/hooks/usePersonaService.test.tsx`（R-P1）                     |
| S03 | 切换身份走审计与同步捕获                                  | 模拟测试 | 🔶 设计中       | 切换产生审计行与同步操作                                                         | 现路径旁路 service，见 [跨进程会话中心](/zh/design/session-center) Phase 1 |
| S04 | 锁定时切换身份被拒                                        | 模拟测试 | ✅ 已实现且测试 | 锁态返回 `Service is locked`                                                     | `desktop` set/clear handler 门禁                                           |
| S05 | 锁定在跨进程可见                                          | 模拟测试 | ❌ 无实现       | 桌面锁后 CLI/agent/bridge 下一请求返回 `vault_locked`                            | 会话中心 A2                                                                |

### 上下文选择

| ID  | 场景                                             | 层       | 状态                  | 验收条款                                          | 证据 / 缺口                            |
| --- | ------------------------------------------------ | -------- | --------------------- | ------------------------------------------------- | -------------------------------------- |
| S06 | 上下文只建议、永不授权                           | 模拟测试 | ✅ 已实现但仅单客户端 | 上下文命中不放宽任何授权判定                      | `CONTEXT_AWARE_DESIGN.md` 有阶段验收表 |
| S07 | 上下文 → 凭据 → fill / sign 的完整链跨客户端一致 | 真实交互 | ❌ 无实现             | 同一上下文在桌面 fill 与 agent 签名下取到同一凭据 | 无任何跨客户端 harness                 |

### 统一授权

| ID  | 场景                                             | 层       | 状态            | 验收条款                                             | 证据 / 缺口                                                |
| --- | ------------------------------------------------ | -------- | --------------- | ---------------------------------------------------- | ---------------------------------------------------------- |
| S08 | principal × action × resource 裁决矩阵           | 模拟测试 | ✅ 已实现且测试 | 四种裁决（含非交互折叠为拒绝）全覆盖                 | `core/src/authz.rs` 单测                                   |
| S09 | 裁决可归因（审计带主体与理由）                   | 模拟测试 | 🔶 设计中       | 放行类动作也带 `principal_kind` / `decision_reason`  | 现仅 Connect scope 拒绝有审计（P0）                        |
| S10 | Connect token 越权即时拒绝且即时收敛             | 模拟测试 | ✅ 已实现且测试 | 每请求查表，撤销跨进程即时生效                       | `connect_authenticate`；S13 回归                           |
| S11 | Agent 受限 grant：签名放行、导出与非绑定密钥拒绝 | 模拟测试 | 🔶 设计中       | 非交互上下文越权直接失败而非挂起                     | [Principal 与 Action 设计](/zh/design/principal-action) P3 |
| S12 | 写路径走统一裁决（写动词拍板后）                 | 模拟测试 | 🔶 设计中       | 32 处 `ensure_unlocked()` 收敛到 `ensure_authorized` | 同上 P1/P2                                                 |

### 跨客户端一致性

| ID  | 场景                                          | 层       | 状态            | 验收条款                                 | 证据 / 缺口                |
| --- | --------------------------------------------- | -------- | --------------- | ---------------------------------------- | -------------------------- |
| S13 | 撤销 Connect token 跨进程即时生效             | 模拟测试 | ✅ 已实现且测试 | 保留为回归项                             | `core/src/service.rs:2374` |
| S14 | 桌面解锁后 CLI 立即感知                       | 模拟测试 | ❌ 无实现       | 解锁推进版本列后 CLI 下一请求成功        | 会话中心 A1                |
| S15 | Connect 是否跟随活动身份（需显式决定）        | 模拟测试 | ⚠️ 未定义       | 跟随，或文档化"不跟随"——不允许无声不一致 | 会话中心 A3                |
| S16 | CLI 启动的 SSH agent 能把签名请求弹到桌面确认 | 真实交互 | ❌ 无实现       | 桌面弹窗可 Allow/Deny，120s 超时拒绝     | 会话中心 A5                |

### 安全回归（沿用 AUDIT-060 覆盖面）

| ID  | 场景                                                                | 层       | 状态                          | 验收条款                                        | 证据 / 缺口                                                           |
| --- | ------------------------------------------------------------------- | -------- | ----------------------------- | ----------------------------------------------- | --------------------------------------------------------------------- |
| S17 | 自动锁 / 重认证三端一致                                             | 真实交互 | ⚠️ 部分                       | Linux 有手册脚本，macOS / Windows 无实机记录    | `verify-biometric-linux.md`；`BUGS.md` 15/15                          |
| S18 | SSH agent Windows 命名管道审批 + 生物识别                           | 真实交互 | 🚫 BLOCKED                    | 需真 Windows 桌面会话                           | AUDIT-032 仍开；`ci.yml` 只跑 `cargo check`                           |
| S19 | NSIS 安装器 7 步（全新×2 / 升级 / 静默 / MSI 迁移 / 卸载×2 / 降级） | 真实交互 | ⚠️ 有清单无自动化             | 每步人工执行留记录                              | `WINDOWS_INSTALLER.md` §5                                             |
| S20 | 同步双设备真 TCP 收敛 + 真冲突双版本保留                            | 模拟测试 | ✅ 已实现且测试               | 同 lamport 异设备时败者降级进 conflict 区不丢弃 | `server/tests/sync_two_device_e2e.rs`；`E2EE_SYNC_DESIGN.md` 验收锚点 |
| S21 | 生物识别（Secure Enclave / Touch ID / TPM）                         | 真实交互 | 🚫 明确不支持（CI VM 无硬件） | spike 探针输出作为交付物，非门禁                | `desktop-build.yml::build` biometric spike                            |
| S22 | 跨实现密码学 oracle                                                 | 模拟测试 | ✅ 已实现且测试               | 独立 Python 实现向量被 core 测试钉死            | `scripts/steam_guard_verify.py`                                       |

### 长期运行与耐久

| ID  | 场景                                       | 层       | 状态            | 验收条款                                       | 证据 / 缺口                                  |
| --- | ------------------------------------------ | -------- | --------------- | ---------------------------------------------- | -------------------------------------------- |
| S23 | 重启恢复：解锁态不持久、锁后重启保持锁     | 长期运行 | ⚠️ 未测         | 重启后必须重新认证                             | 无恢复测试                                   |
| S24 | 崩溃后未落盘批次丢失                       | 长期运行 | ❌ 已知限制未测 | 明确量化丢失窗口，或补持久化 outbox            | `FINAL_SUMMARY.md` 记录为已知限制            |
| S25 | 多小时后台常驻（agent / connect / bridge） | 长期运行 | ❌ 零覆盖       | 无泄漏、无锁泄漏、无句柄增长                   | 无 soak 作业；`Makefile::benchmark` 无 bench |
| S26 | 并发客户端写同一 vault                     | 长期运行 | ⚠️ 仅事务级     | SQLite 事务正确 ≠ 会话一致（见会话中心 C1/C3） | 无并发压测                                   |

### 移动端

| ID  | 场景                                   | 层       | 状态      | 验收条款                                       | 证据 / 缺口                                  |
| --- | -------------------------------------- | -------- | --------- | ---------------------------------------------- | -------------------------------------------- |
| S27 | Android arm64 APK 真机运行完整解锁流程 | 真实交互 | ⚠️ 未验证 | 解锁 → 身份 → 凭据 → 复制/TOTP                 | APK 已构建，从未真机运行                     |
| S28 | iOS 至少能编译                         | 编译成功 | ❌ 无实现 | 补 `aarch64-apple-ios` target 并产出可编译产物 | `Persona.h` 只暴露 10 个生命周期符号         |
| S29 | HarmonyOS 桥可编译且返回真实结果       | 编译成功 | 🔶 有骨架 | `PersonaBridge.ets` 不再返回 `NOT_WIRED`       | 无 napi-rs 后端；只能在 DevEco Studio 内构建 |

## 待建清单（按优先级）

**P1**

1. **两客户端一 vault harness**（解锁 S01 / S05 / S14 / S16）：一个 vault 文件 + 桌面 + CLI 两条
   命令链，在 `tempfile` 或临时 HOME 下跑通"切身份 / 锁 / 解锁 / 撤销"的跨端断言。这是当前最大的
   单点缺口。
2. **soak 作业**（解锁 S23 / S24 / S25 / S26）：独立 workflow，`workflow_dispatch` + 每日定时，
   不阻塞 `ci.yml`；产物是内存/句柄曲线与重启恢复记录。

**P2**

3. **真实交互入 CI**（解锁 S17 / S18 / S19）：本机已有桌面截图走查管线
   （`~/.cache/persona-ui-shots/shoot.mjs`，`__TAURI_INTERNALS__` shim + Xvfb 双实例），先落
   Linux 桌面走查；Windows/macOS 需真机或云桌面 runner。
4. **iOS target 补装**（解锁 S28）：`rust-toolchain.toml` 加 `aarch64-apple-ios`，只要求编译过——
   把"从未编译"变成"已编译但未实机"。
5. **`connect-server` 集成测试**：dev-deps（`tower`、真实 TCP、真实 DB）已具备，缺 `tests/` 目录。

**P3**

6. `agents/ssh-agent/TESTING.md` 与 `e2e_test.rs` 对齐（10 个测试，文档仍写 7）。
7. `.github/ISSUE_TEMPLATE` 增加验收字段；把本页四层作为 PR 模板的勾选维度。
8. 清理悬空的 `Makefile::release-*` 目标（或补上 `scripts/release.sh` 的人工触发说明）。

## 计数口径

- Rust：`grep -rn '#\[test\]\|#\[tokio::test\]'` 覆盖 `core` / `cli` / `server` /
  `agents/ssh-agent` / `connect-server` / `desktop/src-tauri` / `mobile/rust`，合计行内 2,294；
  `tests/` 目录下 73 个；总计 **2,367**。
- JS：`grep -ro '\bit(\|test('`，`desktop/src` 726 个，`browser/chromium-extension` 164 个，
  合计 **890**。
- 其他：iOS 2 个 XCTest，Android / Harmony / website / safari 均为 0。
- 统计日期 2026-10-24。

## 关联

- [验收场景与跨客户端一致性](/zh/design/session-center)：会话中心的 A1–A5 与本页 S05 / S14 / S16 对齐
- [Principal 与 Action 授权体系设计](/zh/design/principal-action)：S08–S12 的来源
- [原型外部审查](https://github.com/cuihairu/persona/blob/main/docs/review/2026-10-24-persona-external-architecture-review.md)：四层分层的来源与 R-P6 追踪项
- [审计任务清单](https://github.com/cuihairu/persona/blob/main/docs/review/task-list-2026-10-18.md)：AUDIT-050/051/060/061 的原始定义
