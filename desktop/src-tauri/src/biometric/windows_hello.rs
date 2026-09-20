//! Windows：Windows Hello（UserConsentVerifier）。
//!
//! `CheckAvailabilityAsync` / `RequestVerificationAsync` 是 WinRT
//! IAsyncOperation——线程内 `get()` 本身阻塞直到完成，直接当作
//! ceremony 闭包跑在专用线程上。提示文案由系统提供（显示应用名 +
//! 验证请求），无自定义 reason 入参。Credential Manager 里的托管
//! 密码不绑 Hello——验证与取回的串联在应用层（biometric_unlock
//! 命令：ceremony 通过才读 keyring）。
//!
//! 仅经 nightly CI 编译验证（本仓库无 Windows 实机）。

use windows::core::IAsyncOperation;
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
    let Ok(op) = op.downcast::<IAsyncOperation<UserConsentVerifierAvailability>>() else {
        return false;
    };
    matches!(op.get(), Ok(UserConsentVerifierAvailability::Available))
}

pub fn ceremony(_reason: &str) -> Result<(), String> {
    let op: IAsyncOperation<UserConsentVerificationResult> =
        UserConsentVerifier::RequestVerificationAsync()
            .map_err(|e| format!("Windows Hello unavailable: {}", e.code()))?;
    let result = op
        .get()
        .map_err(|e| format!("Windows Hello prompt failed: {}", e.code()))?;
    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        other => Err(format!("Windows Hello verification failed: {other:?}")),
    }
}
