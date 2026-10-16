# Biometric Unlock Hooks

> [English](BIOMETRIC_HOOKS.md) | [中文](BIOMETRIC_HOOKS.zh.md)

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

## Desktop wiring (implemented)

The desktop side (Tauri) provides `OsBiometricProvider` (`desktop/src-tauri/src/biometric/`),
which dispatches to three cfg modules per platform; the synchronous trait is bridged
by a dedicated ceremony thread with a 120s timeout:

| Platform | Module                       | Backend                                                                                                             | Semantics                                               |
| -------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Linux    | `biometric/polkit.rs`        | Hand-written zbus `CheckAuthorization` (action `com.persona.desktop.biometric-unlock`, subject via system-bus-name) | `auth_self`: fingerprint (fprintd) or password fallback |
| macOS    | `biometric/macos.rs`         | objc2-local-authentication `LAPolicy::DeviceOwnerAuthentication`                                                    | Touch ID + system password fallback                     |
| Windows  | `biometric/windows_hello.rs` | `UserConsentVerifier::RequestVerificationAsync`                                                                     | Windows Hello (PIN/biometric)                           |

It does not depend on zbus_polkit (CVE-2026-78422); mac/win are compile-verified only, via nightly CI.

### The four commands (`commands.rs`)

- `biometric_status(db_path)`: read-only, no unlock required. `enabled` is exactly
  the one bit of metadata saying a keyring entry exists; `available` also factors
  in keyring reachability, and probe errors fail closed to `enabled=false`. The
  unlock screen queries it on mount / custom-path changes to drive the fingerprint
  button's visibility.
- `biometric_enable(master_password)`: gated behind unlock (same as `set_locale`);
  the master password is verified first and only then is the OS authentication
  prompt shown — an unverified password is never written to the keyring.
- `biometric_disable()`: idempotent entry deletion; a hardening operation, so no
  password gate.
- `biometric_unlock(db_path)`: look up the entry first (a missing entry is a clean
  error, no prompt) → ceremony → retrieve the master password from the keyring and
  feed it through `init_service` proper (the password never leaves the process);
  on `InvalidCredentials` the entry is deleted immediately and the `BIOMETRIC_RESET`
  code is returned (so repeated fingerprint taps can't burn through the 5-failure
  lockout).

Master password custody: `persona-biometric` keyring service, keyed by the vault
db_path (the same per-vault pattern as the persona-sync token); a successful
password change updates the entry in lockstep, and a write failure deletes it
(fail-closed). On the frontend see `UnlockScreen.tsx` (fingerprint button) and
the `SettingsModal` SecurityPane (toggle; enabling goes through ReauthModal for
password verification).

Threat-model registration: the "Biometric Unlock" section of
`docs/THREAT_MODEL.md` spells out in black and white that a malicious same-user
process can read the OS keychain (Windows Credential Manager has no ACL) — an
inherent exposure of the direct-storage design.

### Packaging and on-device notes

- **deb**: `bundle.linux.deb.files` in `tauri.conf.json` installs
  `polkit/com.persona.desktop.biometric-unlock.policy` to
  `/usr/share/polkit-1/actions/`.
- **rpm / AppImage / `pnpm tauri dev`**: no action file shipped →
  `CheckAuthorization` returns ActionUnknown → biometric fails closed and degrades
  to unavailable (the button is not rendered; the settings page shows a hint).
  For dev, install manually:
  `sudo install -Dm644 polkit/com.persona.desktop.biometric-unlock.policy /usr/share/polkit-1/actions/`
- Linux on-device verification script (negative paths included):
  `scripts/verify-biometric-linux.md`.
