//! OS-level biometric / user-presence provider (Touch ID / Windows Hello /
//! polkit).
//!
//! Implements core's synchronous [`BiometricProvider`] trait, while the
//! platform system-dialog APIs are all blocking or callback-based —
//! `run_with_timeout` runs the ceremony on a dedicated short-lived thread
//! and reclaims the result within a deadline, confining the blocking to the
//! thread boundary (calling keyring/zbus synchronously from async commands
//! in token_store is the same established fact). On timeout the thread
//! simply exits once the system dialog ends on its own (detached; one
//! short-lived thread per ceremony, no accumulating leak).
//!
//! The unlock-screen ceremony has no live PersonaService, so the provider
//! hangs off AppState (`types::AppState::biometric_provider`); command-layer
//! calls always wrap it further in `spawn_blocking` and never park a tokio
//! worker.
//!
//! The availability probe is fail-closed: no secret service / no polkit /
//! not one of the three desktop platforms means unavailable, and the
//! frontend hides the fingerprint entry.

use persona_core::{BiometricAuthResult, BiometricPlatform, BiometricPrompt, BiometricProvider};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Maximum wait for one system authentication dialog (timeout = the user
/// gave up, treated as failure)
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum wait for the availability probe — the unlock screen mounts and
/// must check status, so a broken system service must not slow the UI; on
/// timeout treat as unavailable (fail-closed)
const AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `f` on a dedicated thread and wait for the result with a deadline.
fn run_with_timeout<T, F>(f: F, timeout: Duration) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("persona-biometric".to_string())
        .spawn(move || {
            // Once the receiver times out and gives up, the thread exits
            // naturally when the system dialog ends; a failed send doesn't matter
            let _ = tx.send(f());
        })
        .map_err(|e| format!("biometric thread spawn failed: {e}"))?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err("biometric prompt timed out".into()),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("biometric thread exited unexpectedly".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Platform dispatch (each module exposes the free functions available/ceremony/platform_name)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as os;

#[cfg(target_os = "macos")]
pub mod macos_se;

#[cfg(target_os = "windows")]
mod windows_hello;
#[cfg(target_os = "windows")]
use windows_hello as os;

#[cfg(target_os = "windows")]
pub mod windows_tpm;

#[cfg(target_os = "linux")]
mod polkit;
#[cfg(target_os = "linux")]
use polkit as os;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
mod unsupported;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
use unsupported as os;

/// Platform enum reported at the trait layer (reuses ssh-agent detect_platform's existing mapping)
fn result_platform() -> BiometricPlatform {
    #[cfg(target_os = "macos")]
    {
        BiometricPlatform::TouchId
    }
    #[cfg(target_os = "windows")]
    {
        BiometricPlatform::WindowsHello
    }
    #[cfg(target_os = "linux")]
    {
        BiometricPlatform::LinuxSecretService
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        BiometricPlatform::Unknown
    }
}

/// OS-direct biometric provider (shared by the unlock ceremony and the SSH
/// agent policy).
///
/// `is_available` ignores `hint` (the caller's guess about the platform
/// doesn't matter; what is probed here is this machine's real
/// authentication stack); `prompt.user_id` is likewise ignored — the OS
/// authenticates the logged-in session user, not some identity in the vault.
pub struct OsBiometricProvider;

impl BiometricProvider for OsBiometricProvider {
    fn is_available(&self, _hint: Option<BiometricPlatform>) -> bool {
        run_with_timeout(|| Ok(os::available()), AVAILABILITY_TIMEOUT).unwrap_or(false)
    }

    fn authenticate(&self, prompt: &BiometricPrompt) -> persona_core::Result<BiometricAuthResult> {
        let reason = prompt.reason.clone();
        run_with_timeout(move || os::ceremony(&reason), CEREMONY_TIMEOUT)
            .map_err(persona_core::PersonaError::AuthenticationFailed)?;
        Ok(BiometricAuthResult {
            user_id: prompt.user_id,
            verified: true,
            platform: result_platform(),
        })
    }
}

/// Platform name for frontend status display ("touch-id" / "windows-hello" /
/// "linux-polkit" / "unsupported")
pub fn platform_name() -> &'static str {
    os::platform_name()
}

// ---------------------------------------------------------------------------
// Hardware-bound wrapping layer (host-side assembly of the biometric_wrap trait)
// ---------------------------------------------------------------------------

/// Gate-tier stub: with capability OsGateOnly, `wrap_master_key`/
/// `unwrap_master_key` return Unsupported explicitly, and enable/unlock
/// commands route through the historical gate layer (keyring password
/// escrow) accordingly. Linux is always on this tier (no hardware wrapping,
/// design doc §7.1); Windows is the same until Passport Key lands; macOS
/// also lands here without the spike env var.
pub struct GateOnlyKeyWrapper;

impl persona_core::BiometricKeyWrapper for GateOnlyKeyWrapper {
    fn capability(&self) -> persona_core::BiometricWrapCapability {
        persona_core::BiometricWrapCapability::OsGateOnly
    }

    fn is_available(&self) -> bool {
        // Gate-tier availability is probed separately by biometric_provider;
        // the wrapping layer is always "unavailable" — two distinct concepts,
        // fail-closed here.
        false
    }

    fn platform(&self) -> persona_core::WrapPlatform {
        #[cfg(target_os = "macos")]
        {
            persona_core::WrapPlatform::MacSecureEnclave
        }
        #[cfg(target_os = "windows")]
        {
            persona_core::WrapPlatform::WindowsTpm
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            persona_core::WrapPlatform::Linux
        }
    }

    fn enrollment_fingerprint(
        &self,
    ) -> std::result::Result<[u8; 32], persona_core::BiometricWrapError> {
        Err(persona_core::BiometricWrapError::Unsupported)
    }

    fn wrap_payload(
        &self,
        _master_key: &[u8; 32],
        _prompt: &str,
    ) -> std::result::Result<Vec<u8>, persona_core::BiometricWrapError> {
        Err(persona_core::BiometricWrapError::Unsupported)
    }

    fn unwrap_payload(
        &self,
        _payload: &[u8],
        _prompt: &str,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, persona_core::BiometricWrapError> {
        Err(persona_core::BiometricWrapError::Unsupported)
    }

    fn delete_wrap_payload(
        &self,
        _payload: &[u8],
    ) -> std::result::Result<(), persona_core::BiometricWrapError> {
        Err(persona_core::BiometricWrapError::Unsupported)
    }
}

/// Assembles the key wrapper for the current platform. macOS returns the
/// Secure Enclave route B' implementation when `PERSONA_BIOMETRIC_SE_SPIKE=1`
/// (for on-device spikes, see design doc §5), and Windows returns the
/// Passport KSP implementation when `PERSONA_BIOMETRIC_TPM_SPIKE=1`
/// (ditto, §6); everything else falls back to the gate-tier stub — the
/// production unlock path contains no route unverified on real hardware.
pub fn key_wrapper() -> Arc<dyn persona_core::BiometricKeyWrapper> {
    #[cfg(target_os = "macos")]
    {
        if let Some(wrapper) = macos_se::spike_wrapper_if_enabled() {
            return Arc::new(wrapper);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(wrapper) = windows_tpm::spike_wrapper_if_enabled() {
            return Arc::new(wrapper);
        }
    }
    Arc::new(GateOnlyKeyWrapper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_timeout_returns_error() {
        // The closure sleeps past the deadline: run_with_timeout must return
        // an error on timeout rather than hang
        let result = run_with_timeout(
            || {
                std::thread::sleep(Duration::from_secs(6));
                Ok(())
            },
            Duration::from_secs(1),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
    }

    #[test]
    fn ceremony_success_propagates_value() {
        let result = run_with_timeout(|| Ok(42u8), Duration::from_secs(5));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn availability_failure_is_false() {
        // A failed probe (error or timeout) is fail-closed as unavailable
        let probe: Result<bool, String> =
            run_with_timeout(|| Err("no secret service".into()), AVAILABILITY_TIMEOUT);
        assert!(!probe.unwrap_or(false));
    }
}
