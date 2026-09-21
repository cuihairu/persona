//! macOS：LocalAuthentication（Touch ID，密码回退）。
//!
//! `kLAPolicyDeviceOwnerAuthentication` = 生物识别 + 系统密码回退，
//! 对齐 1Password 的解锁语义。evaluatePolicy 的 reply 回调在私有
//! dispatch queue 上执行——内层 channel 等回调到达（时限比外层
//! CEREMONY_TIMEOUT 短 10s，让本层先超时报出更精确的错误）。等待期间
//! `StackBlock` 活在本函数栈帧上，回调到达时 block 一定仍然有效。
//!
//! 仅经 nightly CI 编译验证（本仓库无 macOS 实机）。

use block2::StackBlock;
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
    // objc2 0.6 代系将 +new 标记为 unsafe（初始化约定未被证明安全）
    let ctx = unsafe { LAContext::new() };
    // canEvaluatePolicy_error 返回 Result<(), Retained<NSError>>：
    // Err（无生物硬件/系统限制）一律按不可用处理
    unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }.is_ok()
}

pub fn ceremony(reason: &str) -> Result<(), String> {
    let ctx = unsafe { LAContext::new() };
    let reason_ns = NSString::from_str(reason);
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    // StackBlock 要求 'static：tx move 进闭包（rx 在本函数继续等）
    let reply = StackBlock::new(move |success: Bool, _error: *mut objc2_foundation::NSError| {
        // 接收端超时放弃后 send 失败无所谓（弹窗已被系统收走）
        let _ = tx.send(success.as_bool());
    });
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &reason_ns,
            &reply,
        );
    }
    match rx.recv_timeout(REPLY_TIMEOUT) {
        Ok(true) => Ok(()),
        Ok(false) => Err("verification failed".to_string()),
        Err(_) => Err("prompt timed out".to_string()),
    }
}
