//! macOS: LocalAuthentication (Touch ID with password fallback).
//!
//! `kLAPolicyDeviceOwnerAuthentication` = biometrics + system password
//! fallback, aligned with 1Password's unlock semantics. The evaluatePolicy
//! reply callback runs on a private dispatch queue — the inner channel waits
//! for the callback to arrive (with a deadline 10s shorter than the outer
//! CEREMONY_TIMEOUT, so this layer times out first and reports a more precise
//! error). While waiting, `StackBlock` lives on this function's stack frame, so
//! the block is guaranteed to still be valid when the callback arrives.
//!
//! Only compile-verified via nightly CI (no macOS hardware in this repo).

use block2::StackBlock;
use objc2::runtime::Bool;
use objc2_foundation::NSString;
use objc2_local_authentication::{LAContext, LAPolicy};
use std::time::Duration;

/// Deadline for the inner wait on the reply callback (the outer
/// biometric::CEREMONY_TIMEOUT is 120s)
const REPLY_TIMEOUT: Duration = Duration::from_secs(110);

pub fn platform_name() -> &'static str {
    "touch-id"
}

pub fn available() -> bool {
    // The objc2 0.6 generation marks +new as unsafe (the initialization
    // convention is not proven safe)
    let ctx = unsafe { LAContext::new() };
    // canEvaluatePolicy_error returns Result<(), Retained<NSError>>:
    // Err (no biometric hardware / system restrictions) is always treated as
    // unavailable
    unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }.is_ok()
}

pub fn ceremony(reason: &str) -> Result<(), String> {
    let ctx = unsafe { LAContext::new() };
    let reason_ns = NSString::from_str(reason);
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    // StackBlock requires 'static: tx is moved into the closure (rx keeps waiting
    // in this function)
    let reply = StackBlock::new(
        move |success: Bool, _error: *mut objc2_foundation::NSError| {
            // Once the receiver times out and gives up, a failed send is fine — the dialog
            // has already been dismissed by the system
            let _ = tx.send(success.as_bool());
        },
    );
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
