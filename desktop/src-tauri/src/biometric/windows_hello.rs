//! Windows：Windows Hello（UserConsentVerifier）。
//!
//! `CheckAvailabilityAsync` / `RequestVerificationAsync` 是 WinRT
//! IAsyncOperation（windows 0.61 里由 windows-future 承载，直接用返回值，
//! 无需 import）——线程内 `get()` 本身阻塞直到完成，直接当作
//! ceremony 闭包跑在专用线程上。提示文案经 `RequestVerificationAsync`
//! 的 message 参数交给系统展示。Credential Manager 里的托管密码不绑
//! Hello——验证与取回的串联在应用层（biometric_unlock 命令：ceremony
//! 通过才读 keyring）。
//!
//! 仅经 nightly CI 编译验证（本仓库无 Windows 实机）。

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
