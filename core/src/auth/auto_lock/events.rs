//! Auto-lock event surface: callback events, lock reasons, and callback type.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Auto-lock event types for callbacks
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AutoLockEvent {
    /// Session will be locked soon (warning)
    LockPending {
        session_id: String,
        seconds_remaining: u64,
    },
    /// Session has been locked
    Locked {
        session_id: String,
        reason: LockReason,
    },
    /// Session has been unlocked
    Unlocked { session_id: String },
    /// Activity detected
    Activity { session_id: String },
}

/// Reasons for auto-locking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LockReason {
    /// Inactivity timeout reached
    Inactivity,
    /// Absolute session timeout reached
    AbsoluteTimeout,
    /// Manual lock
    Manual,
    /// Security policy violation
    SecurityViolation,
    /// System shutdown
    SystemShutdown,
}

/// Callback type for auto-lock events
pub type AutoLockCallback = Arc<dyn Fn(AutoLockEvent) + Send + Sync>;
