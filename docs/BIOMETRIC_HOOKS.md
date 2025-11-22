# Biometric Unlock Hooks

Persona core defines a `BiometricProvider` trait so platform-specific layers (desktop/mobile/CLI) can plug in Touch ID, Face ID, Windows Hello, or Linux Secret Service prompts without forcing those dependencies into the core crate.

## Provider contract

```rust
pub trait BiometricProvider {
    fn is_available(&self, hint: Option<BiometricPlatform>) -> bool;
    fn authenticate(&self, prompt: &BiometricPrompt) -> Result<BiometricAuthResult>;
}
```

* `BiometricPlatform` enumerates Touch ID, Face ID, Windows Hello, Linux Secret Service, or `Unknown`.
* `BiometricPrompt` includes the `user_id`, a human-readable `reason`, and optional platform hint.
* `BiometricAuthResult` carries the verification flag and resolved platform.

The default `MockBiometricProvider` is used by the CLI/core for offline development; desktop/mobile targets should supply real implementations through `PersonaService::set_biometric_provider`.

## Usage in PersonaService

* `biometric_available()` checks hardware/OS support.
* `authenticate_biometric(prompt)` triggers the provider and returns `true` when verified.

This separation keeps the cryptographic unlock path in Rust while letting UI layers show native dialogs and map their callbacks to the shared prompt/result types.
