//! macOS：LocalAuthentication（Touch ID，密码回退）。
//!
//! `kLAPolicyDeviceOwnerAuthentication` = 生物识别 + 系统密码回退，
//! 对齐 1Password 的解锁语义。evaluatePolicy 的 reply 回调在私有
//! dispatch queue 上执行——内层 channel 等回调到达（时限比外层
//! CEREMONY_TIMEOUT 短 10s，让本层先超时报出更精确的错误）。
//!
//! 仅经 nightly CI 编译验证（本仓库无 macOS 实机）。

use objc2::runtime::Bool;
use objc2_foundation::NSString;
use objc2_local_authentication::{LAContext, LAPolicy};
use std::time::Duration;

/// 内层等待 reply 回调的时限（外层 biometric::CEREMONY_TIMEOUT 为 120s）
const REPLY_TIMEOUT: Duration = Duration::from_secs(110);

pub fn platform_name() -> &'static str {
    "touch-id"
}

pub fn available() -> bool {
    let ctx = LAContext::new();
    unsafe { ctx.canEvaluatePolicy(LAPolicy::DeviceOwnerAuthentication) }
}

pub fn ceremony(reason: &str) -> Result<(), String> {
    let ctx = LAContext::new();
    let reason_ns = NSString::from_str(reason);
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &reason_ns,
            |success: Bool, _error: *mut objc2_foundation::NSError| {
                let _ = tx.send(success.as_bool());
            },
        );
    }
    match rx.recv_timeout(REPLY_TIMEOUT) {
        Ok(true) => Ok(()),
        Ok(false) => Err("verification failed".to_string()),
        Err(_) => Err("prompt timed out".to_string()),
    }
}
