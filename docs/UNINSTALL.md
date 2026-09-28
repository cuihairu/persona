# 卸载与数据保留（卸载不删数据，重装接续）

状态：2026-09-28 核验收口。承诺一句话：**任何平台的卸载/升级都不会删除
vault 数据；重新安装后用原主密码解锁即接续使用**。彻底清除数据永远是
用户的显式动作（下文"彻底清除"一节），卸载器不会替你做。

## 1. 数据都在哪

| 内容                  | 位置                                                                                                          | 谁写入                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| **vault 库**          | Windows `%APPDATA%\persona\persona.db`；Linux `~/.local/share/persona/`；macOS `~/Library/Application Support/persona/` | 桌面端 `default_db_path`（`dirs::data_dir()/persona`） |
| **CLI 工作区**        | `~/.persona/`（`identities.db`、`bridge/`、SSH agent 状态）                                                    | CLI（`PERSONA_DB_PATH` 等环境变量可覆盖） |
| **OS keyring 条目**   | 系统凭据管理器（Windows Credential Manager / Secret Service / Keychain）                                       | 生物识别解锁、同步令牌（`token_store.rs`） |
| **缓存与日志**        | `<bundle 目录>`：Windows `%APPDATA%\com.persona.desktop` 与 `%LOCALAPPDATA%\com.persona.desktop`；Linux/macOS 对应 XDG/Bundle 路径 | WebView 缓存、运行日志 —— **不含任何机密** |

vault 库与缓存目录是两个互不相干的路径：库在 `persona/`，缓存在
`com.persona.desktop/`。卸载器就算清缓存也碰不到库。

## 2. 各平台卸载行为（默认全保留）

| 平台/安装方式    | 卸载动作                                            | vault 库     | CLI 工作区   | keyring  | 缓存/日志                    |
| ---------------- | --------------------------------------------------- | ------------ | ------------ | -------- | ---------------------------- |
| Windows NSIS     | "应用和功能"卸载（确认页有"删除应用数据"勾选框，**默认未勾**） | **保留**     | 保留         | 保留     | 默认保留；**显式勾选**才清 `com.persona.desktop` |
| Windows 升级     | 新安装器自动静默卸载旧版（`/S`，无 UI）             | **保留**     | 保留         | 保留     | 保留（静默路径无勾选框）     |
| Linux deb / rpm  | `apt remove` / `dnf remove`                         | **保留**     | 保留         | 保留     | 保留（包内无任何维护删除脚本，`postrm` 不存在——tauri bundler 只拷贝用户提供的脚本，本仓库未提供） |
| Linux AppImage   | 删除 .AppImage 文件                                 | **保留**     | 保留         | 保留     | 保留                         |
| macOS dmg        | 拖入废纸篓                                          | **保留**     | 保留         | 保留     | 保留                         |
| CLI（cargo/二进制） | 删除二进制                                        | 保留         | **保留**     | 保留     | 保留                         |

Windows 行为由 `desktop/src-tauri/nsis/installer.nsi` 保证，并有回归断言
钉住（`desktop/src-tauri/src/packaging_tests.rs`）：

- 升级/静默卸载给旧卸载器追加 `/S` —— 确认页不出现，"删除应用数据"
  恒为默认未勾（`nsis_bundle_config_pins_install_mode_and_custom_template`
  与 `custom_nsis_template_keeps_persona_upgrade_diffs`）；
- `nsis_uninstall_never_targets_vault_data_dir`：模板中**所有**递归删除
  指令（`RmDir /r`）必须只指向 `${BUNDLEID}` 缓存目录，且任何删除指令
  不得以 vault 目录（`\persona"`）为目标 —— 模板被改动时测试会红。

## 3. 重装接续

重装/升级后数据无需迁移：安装器不创建也不删除 vault；首次启动仍解析
`default_db_path`，用原主密码解锁即恢复全部条目、身份与设置。Linux/macOS
同理（路径见上表）。**卸载 → 重装 = 无损**；只有走到下一节的"彻底清除"
才会丢数据。

## 4. 彻底清除（显式 purge，二次确认自己做）

想真正删干净，按平台手动执行（**删前确认已有备份**；vault 删除后无法
恢复）：

**Windows（PowerShell）**

```powershell
# 卸载应用（"应用和功能"，不勾"删除应用数据"亦可）后：
Remove-Item -Recurse -Force "$env:APPDATA\persona"          # vault 库
Remove-Item -Recurse -Force "$env:APPDATA\com.persona.desktop"    # 缓存
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\com.persona.desktop" # 缓存/日志
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:USERPROFILE\.persona"  # CLI 工作区
# keyring：系统"凭据管理器"里删除 persona 相关条目
```

**Linux**

```bash
rm -rf ~/.local/share/persona   # vault 库
rm -rf ~/.persona               # CLI 工作区 + SSH agent 状态
# keyring（GNOME）：seahorse 里删除 persona 条目
```

**macOS**

```bash
rm -rf "$HOME/Library/Application Support/persona"  # vault 库
rm -rf ~/.persona                                   # CLI 工作区
# keyring：钥匙串访问里删除 persona 条目
```

卸载器之所以不带 `--purge` 之类的静默删数据开关：NSIS 模板改动无法在
Linux 本机编译验证（见 docs/WINDOWS_INSTALLER.md §5），静默删库的风险
收益不成比例——显式手敲删除命令本身就是那道"二次确认"。

## 5. 变更清单核对

涉及"卸载保数据"的文件：`desktop/src-tauri/nsis/installer.nsi`（升级
静默卸载定制）、`desktop/src-tauri/src/packaging_tests.rs`（回归断言）、
本文档、`docs/WINDOWS_INSTALLER.md` §3（Windows 细节）、README（链接）。
