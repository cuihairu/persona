use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::enforcer::{HostUsageState, KeyUsageState};

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(())).lock().unwrap()
}

fn write_known_hosts(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, contents).unwrap();
    (dir, path)
}

mod config;
mod decide;
mod hosts;
mod limits;
