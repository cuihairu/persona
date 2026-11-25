use super::*;

use crate::auth::session::AutoLockConfig;
use crate::storage::Database;
use std::sync::atomic::{AtomicU32, Ordering};

mod activity;
mod audit;
mod lock;
mod manager;
mod monitor;
mod sensitive;

// ---- Shared helpers ----

fn session_info_with_idle_seconds(idle_secs: u64) -> SessionInfo {
    let mut session = Session::new("u".to_string(), Duration::from_secs(3600));
    if idle_secs > 0 {
        session.last_activity = SystemTime::now() - Duration::from_secs(idle_secs);
    }
    SessionInfo {
        session,
        last_warning_time: None,
        warning_sent: false,
    }
}
