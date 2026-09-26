# Windows 安装器与升级流程（NSIS）

状态：2026-09-25 落地。配置在 `desktop/src-tauri/tauri.conf.json`
（`bundle.windows.nsis`），定制模板在 `desktop/src-tauri/nsis/installer.nsi`，
回归断言在 `desktop/src-tauri/src/packaging_tests.rs`。

## 1. 背景：旧版升级逻辑的问题

Tauri 官方 NSIS 模板其实自带"重装页"（`PageReinstall`）：检测到旧版本时让用户
在"**卸载后安装** / 不卸载直接装"之间二选一，且升级场景下"卸载后安装"
**默认勾选**。但在本仓库旧配置下它实际上不可用/不可见，原因有四：

| #   | 缺口                                                                                                          | 后果                                                                                                                                                                        |
| --- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `tauri.conf.json` 没有 `bundle.windows` 段 → `installMode` 走默认 `currentUser`，旧版检测只读 HKCU（`SHCTX`） | 旧版若是 per-machine（HKLM，例如 MSI 或 perMachine NSIS）安装，**重装页根本不出现**，新版并排装进 `%LOCALAPPDATA%` —— 旧文件、旧开始菜单/桌面快捷方式、旧卸载注册表全部残留 |
| 2   | CI 同时发布 NSIS（per-user）与 MSI（per-machine）两种安装器                                                   | MSI 升级走 `msiexec`/UpgradeCode，只认 MSI 自己的旧版，**不会清 NSIS 安装**；用户在两种安装器之间切换就产生混装                                                             |
| 3   | NSIS 静默安装（`/S`）跳过所有自定义页面                                                                       | 原版模板在 `/S` 下**完全不卸载旧版**：新文件原地覆盖，版本间改名/删除过的旧文件永久残留在安装目录                                                                           |
| 4   | 交互式升级时旧版卸载器以**完整 UI** 运行                                                                      | 用户要一路点完旧版的卸载向导（含"删除应用数据"勾选框），不是"静默卸载"，也容易中途取消                                                                                      |

## 2. 现在的标准升级流程

三处改动（相对 `@tauri-apps/cli` 2.11.6 锁定链里的 `tauri-cli-v2.11.4`
基线模板，差异全部标注 `Persona 定制` 注释）：

1. **`installMode: "both"`**：首次安装出现"为本机所有用户 / 仅当前用户"
   选择页（默认当前用户，无需管理员）；选择会被记忆，升级时自动沿用旧
   安装的上下文 —— 旧版检测同时覆盖 HKCU 与 HKLM，杜绝缺口 1。
2. **升级路径默认静默卸载旧版**：重装页默认勾选"卸载后安装"（基线行为
   保留），且给旧版卸载器追加 `/S` —— 全程无 UI、无确认页（缺口 4）。
3. **完全静默安装（`/S`）同样先卸载旧版**：在 `EarlyChecks`（Section，
   静默模式照常运行）里调用 `UninstallPreviousSilent`，检测规则与重装页
   一致：先查 SHCTX 的 NSIS 卸载键，再枚举 HKLM 匹配
   `DisplayName`+`Publisher` 的 WiX/MSI 条目并以
   `msiexec /x {ProductCode} /quiet /norestart` 卸载（缺口 3）。卸载失败
   则安装器中止（fail-closed，拒绝在旧版残留之上继续安装）。

各入口的行为：

| 入口                            | 行为                                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| 双击运行（交互）                | 检测旧版 → 重装页，默认勾选"卸载后安装" → 旧版**静默**卸载 → 安装新版                 |
| `/S`（静默/无人值守）           | 检测旧版（NSIS 或 MSI）→ **静默**卸载 → 安装；失败以非零退出码中止                    |
| `/P`（被动，仅进度条）          | 同交互默认路径，页面自动按默认值通过                                                  |
| `/UPDATE`（Tauri updater 内部） | 基线语义保留：原地更新、不弹重装页、不动卸载键与自启项                                |
| 降级                            | 交互模式"不卸载"选项禁用（`ALLOWDOWNGRADES=false` 默认）；`/S` 模式同样先卸载旧版再装 |

**不再发布 MSI**（2026-09-25 起 `desktop-build.yml` Windows matrix 只构建
`nsis`）：同一版本同时发两种安装器是缺口 2 的根源。NSIS 安装器对旧 MSI
安装有迁移卸载（`msiexec /x` 静默），反向不存在。确需 MSI（如 GPO 批量
部署）时把 matrix 加回 `msi` 即可，但混装风险自负。

## 3. 数据与配置保留的保证

- Persona 桌面端库默认在 **`%APPDATA%\persona\persona.db`**
  （`commands.rs` 的 `default_db_path`：`dirs::data_dir()/persona`）。
- NSIS 卸载器自带的"删除应用数据"勾选框删的是
  `%APPDATA%\com.persona.desktop` 与 `%LOCALAPPDATA%\com.persona.desktop`
  （Tauri/WebView 缓存类数据），**不碰库目录**；且只有用户在手动卸载时
  显式勾选才会执行。升级路径的静默卸载（`/S`）没有 UI，该勾选恒为未勾。
- OS keyring 条目（生物识别/同步令牌，`token_store.rs`）与安装器无关，
  升级/卸载均不受影响。
- 结论：**升级（含 `/S` 无人值守）不会丢库、丢配置**。想彻底清理本机
  数据需在卸载后手动删除 `%APPDATA%\persona`。

## 4. 升级矩阵

| 旧安装                   | 新安装 | 结果                                                               |
| ------------------------ | ------ | ------------------------------------------------------------------ |
| NSIS per-user（HKCU）    | NSIS   | 重装页默认勾选卸载 → 静默卸载旧版（含旧快捷方式/注册表）→ 装新     |
| NSIS per-machine（HKLM） | NSIS   | `installMode=both` 沿用旧上下文，检测到 HKLM 键 → 同上（需管理员） |
| MSI（HKLM）              | NSIS   | 重装页强制走 WiX 迁移卸载（交互），`/S` 走 `msiexec /x /quiet`     |
| 无                       | NSIS   | 全新安装（出现 per-user/per-machine 选择页）                       |
| NSIS                     | MSI    | **不支持**（MSI 不会清 NSIS 安装，产生残留）—— 已停发 MSI          |

## 5. Windows 机器验收清单

本仓库在 Linux 上开发，NSIS 无法本机编译验证；以下清单供有 Windows 环境
时执行（对应 `packaging_tests.rs` 只能覆盖的配置层之上的行为层）：

1. `pnpm install --frozen-lockfile --filter persona-desktop... && pnpm exec tauri build --bundles nsis` 成功产出 `-setup.exe`。
2. 全新安装 ×2：分别选"仅当前用户"与"所有用户"，确认安装目录
   （`%LOCALAPPDATA%\Persona` / `Program Files\Persona`）与卸载键位置符合选择。
3. 升级：装旧版 → 运行新版安装器 → 确认 ① 重装页出现且"卸载后安装"
   **默认勾选**；② 旧版卸载全程无 UI；③ 完成后 HKCU/HKLM 里产品卸载键
   **只剩一条**；④ `%APPDATA%\persona\persona.db` 原样保留，旧库可直接解锁。
4. 静默升级：`persona-setup.exe /S`（cmd 检查 `%ERRORLEVEL%`=0），结果同上 ③④。
5. MSI 迁移：装旧版 MSI → 运行新版 NSIS `/S` → HKLM 旧 MSI 条目消失。
6. 手动卸载 ×2：不勾/勾选"删除应用数据"，确认两种情况下
   `%APPDATA%\persona` 都保留（勾选只清 `com.persona.desktop` 缓存目录）。
7. 降级：交互模式"不卸载"灰显；`/S` 模式仍先卸载旧版。

## 6. 模板维护

`nsis/installer.nsi` 基于
[`tauri-cli-v2.11.4`](https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.11.4/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi)
基线（`pnpm-lock.yaml` 锁定 `@tauri-apps/cli` 2.11.4，`Cargo.lock` 锁定
`tauri` 2.11.6）。升级 CLI 时：下载新基线模板 → 重放三处
`Persona 定制`（见文件头注释）→ 更新头注释里的基线标签 →
`cargo test -p persona-desktop packaging`（或全量测试）确认断言仍过。
