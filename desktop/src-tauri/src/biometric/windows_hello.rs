//! Windows: Windows Hello (UserConsentVerifier).
//!
//! `CheckAvailabilityAsync` / `RequestVerificationAsync` are WinRT
//! IAsyncOperations (in windows 0.61 they are carried by windows-future; use the
//! return value directly, no import needed) — calling `get()` on the thread
//! blocks until completion, so use it directly as a ceremony closure running on
//! a dedicated thread. The prompt text is handed to the system via the message
//! parameter of `RequestVerificationAsync`. Passwords managed in Credential
//! Manager are not bound to Hello — the chaining of verification and retrieval
//! happens at the app layer (biometric_unlock command: keyring is only read
//! after the ceremony passes).
//!
//! Only compile-verified via nightly CI (no Windows hardware in this repo).

use windows::core::HSTRING;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};

pub fn platform_name() -> &'static str {
    "windows-hello"
}

pub fn available() -> bool {
    let Ok(op) = UserConsentVerifier::CheckAvailabilityAsync() else {
        return false;
    };
    matches!(op.get(), Ok(UserConsentVerifierAvailability::Available))
}

pub fn ceremony(reason: &str) -> Result<(), String> {
    let op = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(reason))
        .map_err(|e| format!("Windows Hello unavailable: {}", e.code()))?;
    let result = op
        .get()
        .map_err(|e| format!("Windows Hello prompt failed: {}", e.code()))?;
    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        other => Err(format!("Windows Hello verification failed: {other:?}")),
    }
}
