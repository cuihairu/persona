# Biometric Unlock Hooks

Persona core defines a `BiometricProvider` trait so platform-specific layers (desktop/mobile/CLI) can plug in Touch ID, Face ID, Windows Hello, or Linux Secret Service prompts without forcing those dependencies into the core crate.

## Provider contract

```rust
pub trait BiometricProvider {
    fn is_available(&self, hint: Option<BiometricPlatform>) -> bool;
    fn authenticate(&self, prompt: &BiometricPrompt) -> Result<BiometricAuthResult>;
}
```

- `BiometricPlatform` enumerates Touch ID, Face ID, Windows Hello, Linux Secret Service, or `Unknown`.
- `BiometricPrompt` includes the `user_id`, a human-readable `reason`, and optional platform hint.
- `BiometricAuthResult` carries the verification flag and resolved platform.

The default `MockBiometricProvider` is used by the CLI/core for offline development; desktop/mobile targets should supply real implementations through `PersonaService::set_biometric_provider`.

## Usage in PersonaService

- `biometric_available()` checks hardware/OS support.
- `authenticate_biometric(prompt)` triggers the provider and returns `true` when verified.

This separation keeps the cryptographic unlock path in Rust while letting UI layers show native dialogs and map their callbacks to the shared prompt/result types.

## Desktop wiring（已落地）

桌面端（Tauri）提供 `OsBiometricProvider`（`desktop/src-tauri/src/biometric/`），
按平台分发到三个 cfg 模块，同步 trait 由专用 ceremony 线程 + 120s 超时桥接：

| 平台 | 模块 | 后端 | 语义 |
| ---- | ---- | ---- | ---- |
| Linux | `biometric/polkit.rs` | 手写 zbus `CheckAuthorization`（action `com.persona.desktop.biometric-unlock`，subject 用 system-bus-name） | `auth_self`：指纹（fprintd）或密码回退 |
| macOS | `biometric/macos.rs` | objc2-local-authentication `LAPolicy::DeviceOwnerAuthentication` | Touch ID + 系统密码回退 |
| Windows | `biometric/windows_hello.rs` | `UserConsentVerifier::RequestVerificationAsync` | Windows Hello（PIN/生物） |

不依赖 zbus_polkit（CVE-2026-78422）；mac/win 仅经 nightly CI 编译验证。

### 四命令（`commands.rs`）

- `biometric_status(db_path)`：免解锁只读。`enabled` = keyring 条目存在这一位
  元数据；`available` 计入 keyring 可达性，探测错误 fail-closed 为
  `enabled=false`。解锁屏 mount / 自定义路径变更时查询驱动指纹按钮显隐。
- `biometric_enable(master_password)`：解锁门禁（同 `set_locale`）；先验主
  密码再弹 OS 认证框，绝不把未验证密码写进 keyring。
- `biometric_disable()`：幂等删条目；收紧操作不设密码门禁。
- `biometric_unlock(db_path)`：先查条目（没有就干净报错不弹框）→ ceremony →
  keyring 取回主密码走 `init_service` 本尊（密码不出进程）；
  `InvalidCredentials` 当场自删条目 + 返回 `BIOMETRIC_RESET` 码（防反复点
  指纹吃满 5 次失败锁户）。

主密码托管：`persona-biometric` keyring service、键 = vault db_path（与
persona-sync token 同款 per-vault 模式）；改密成功联动更新条目，写失败即删
（fail-closed）。前端见 `UnlockScreen.tsx`（指纹按钮）与
`SettingsModal` SecurityPane（开关，开启走 ReauthModal 验密）。

威胁模型登记：`docs/THREAT_MODEL.md`「Biometric Unlock」章节——同用户恶意
进程可读 OS 钥匙串（Windows Credential Manager 无 ACL）是直存设计的固有
暴露，白纸黑字。

### 打包与实机注意事项

- **deb**：`tauri.conf.json` 的 `bundle.linux.deb.files` 把
  `polkit/com.persona.desktop.biometric-unlock.policy` 装到
  `/usr/share/polkit-1/actions/`。
- **rpm / AppImage / `pnpm tauri dev`**：不带 action 文件 →
  `CheckAuthorization` 报 ActionUnknown → biometric fail-closed 降级为不可用
  （按钮不渲染，设置页提示）。dev 手工装：
  `sudo install -Dm644 polkit/com.persona.desktop.biometric-unlock.policy /usr/share/polkit-1/actions/`
- Linux 实机验证脚本（含负路径）：`scripts/verify-biometric-linux.md`。
