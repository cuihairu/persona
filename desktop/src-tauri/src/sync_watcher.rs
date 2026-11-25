//! Watcher for changes in the cloud sync directory (host side).
//!
//! The sync engine is pull-driven: nothing actively triggers a local sync once
//! the remote writes a new op into the cloud drive directory. This module
//! supplies that "remote change -> trigger run_cycle" link: it watches the
//! protocol files in `cloud_drive_dir` (`dev-*.jsonl` / `snapshot-*` /
//! `env-*` / `registry.json`) and, after debouncing (the 5s main loop is
//! natural debounce), runs one sync cycle.
//!
//! Two trigger sources:
//! - **`notify` (primary)**: directory-level filesystem events. On a network
//!   filesystem (inotify does not fire) or when the watch fails to start, it
//!   degrades automatically — only polling is left.
//! - **mtime fingerprint polling (fallback, always on)**: every 30s it takes a
//!   `(mtime_ns, size)` fingerprint of the protocol files and triggers only on
//!   change. This is what converges things when notify fails.
//!
//! Feedback suppression: the local push during a cycle writes its own shard ->
//! which triggers another cycle. After the cycle ends the baseline is refreshed
//! to the current fingerprint, so self-writes do not chain (the next cycle has
//! nothing to push and stops).
//!
//! core stays dependency-free — the watcher lives only in the desktop host
//! (`notify` is a dependency of this crate, not of core). Cycle orchestration
//! reuses [`crate::commands::sync::sync_cycle_once`], and the gates
//! (unlocked / joined / cloud drive directory configured) all live there; the
//! watcher only triggers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use notify::Watcher;
use tauri::{AppHandle, Manager};

use crate::commands::{sync_cycle_once, sync_transport_config};
use crate::types::AppState;

/// Protocol-file name predicate: only cloud sync protocol files are worth
/// triggering a cycle (unrelated files the user drops in must not disturb sync).
fn is_protocol_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    (name.starts_with("dev-") && name.ends_with(".jsonl"))
        || (name.starts_with("snapshot-") && name.ends_with(".bin"))
        || (name.starts_with("env-") && (name.ends_with(".bin") || name.ends_with(".json")))
        || name == "registry.json"
}

/// The mtime/size fingerprint of protocol files (name -> (mtime_ns, len)).
/// Directory missing / read failure = empty table (safe side: an empty-table
/// change triggers a round, so nothing is missed).
async fn fingerprint(dir: &Path) -> BTreeMap<String, (u64, u64)> {
    let mut out = BTreeMap::new();
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(_) => return out,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if !is_protocol_file(&path) {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).map(String::from);
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        if let (Some(name), Ok(modified)) = (name, meta.modified()) {
            let mtime_ns = modified
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            out.insert(name, (mtime_ns, meta.len()));
        }
    }
    out
}

/// A watcher for one cloud drive directory: notify (best effort) + fingerprint
/// polling + cycle triggering.
struct DirWatcher<R: tauri::Runtime> {
    dir: PathBuf,
    app: AppHandle<R>,
    /// notify event signal (protocol file changed -> set; debouncing happens in
    /// the main loop)
    notify_events: tokio::sync::mpsc::UnboundedReceiver<()>,
    /// The notify watcher itself (None = notify unavailable / failed to start,
    /// polling only)
    _notify: Option<notify::RecommendedWatcher>,
    baseline: BTreeMap<String, (u64, u64)>,
    last_poll: Instant,
    cycle_running: bool,
}

impl<R: tauri::Runtime> DirWatcher<R> {
    fn new(app: AppHandle<R>, dir: PathBuf) -> Self {
        // notify is best effort: directory missing / unsupported platform /
        // network filesystem -> None, polling fallback (the log records the
        // degradation reason without blocking).
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let notify =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    if event.paths.iter().any(|p| is_protocol_file(p)) {
                        let _ = tx.send(());
                    }
                }
            })
            .ok()
            .and_then(|mut watcher| {
                watcher
                    .watch(&dir, notify::RecursiveMode::NonRecursive)
                    .ok()
                    .map(|_| watcher)
            });
        if notify.is_none() {
            tracing::info!(
                dir = %dir.display(),
                "cloud sync notify unavailable; using mtime polling fallback"
            );
        }
        Self {
            dir,
            app,
            notify_events: rx,
            _notify: notify,
            baseline: BTreeMap::new(),
            last_poll: Instant::now(),
            cycle_running: false,
        }
    }

    /// Run one round (called every 5s by the main loop): drain the notify
    /// signals + poll fingerprints when due -> trigger a cycle if anything
    /// changed (re-entrancy guarded).
    async fn tick(&mut self) {
        let mut changed = false;
        // Drain the notify events (the main loop's 5s cadence is natural
        // debounce: the cycle only runs when drained, so a burst of changes
        // collapses into one round)
        while self.notify_events.try_recv().is_ok() {
            changed = true;
        }
        // Polling fallback: every 30s, fingerprint the protocol files and
        // trigger only on change
        if self.last_poll.elapsed() >= Duration::from_secs(30) {
            self.last_poll = Instant::now();
            let fp = fingerprint(&self.dir).await;
            if fp != self.baseline {
                changed = true;
            }
        }
        if changed {
            self.maybe_cycle().await;
        }
    }

    async fn maybe_cycle(&mut self) {
        if self.cycle_running {
            return;
        }
        self.cycle_running = true;
        let result = {
            let state = self.app.state::<AppState>();
            sync_cycle_once(&state).await
        };
        self.cycle_running = false;
        match result {
            Ok(report) => {
                tracing::info!(
                    pulled = report.pulled,
                    pushed = report.pushed,
                    materialized = report.materialized,
                    "cloud watcher sync cycle complete"
                );
            }
            Err(e) => {
                // Usually "locked / not joined / directory not configured" — these
                // are not faults; the gates live inside sync_cycle_once, so staying
                // quiet (debug level) is fine.
                tracing::debug!(error = %e, "cloud watcher sync cycle skipped");
            }
        }
        // Refresh the baseline after the cycle: the shards written by our own
        // push no longer trigger the next round (self-write feedback
        // suppression — the next round has nothing to push and stops).
        self.baseline = fingerprint(&self.dir).await;
    }
}

/// Spawn the cloud-drive watcher supervisor (once at app setup). A single task
/// loop: every 5s re-evaluate the config (whether transport/dir is cloud +
/// whether the directory changed) and maintain a [`DirWatcher`].
/// The task ends naturally when the process exits; no stop handle is needed —
/// the watcher only does real work while the cloud transport is configured and
/// the directory exists, and idles otherwise (one lightweight config read).
pub(crate) fn spawn_sync_watcher<R: tauri::Runtime>(app: AppHandle<R>) {
    tauri::async_runtime::spawn(async move {
        let mut watcher: Option<DirWatcher<R>> = None;
        let mut last_dir: Option<PathBuf> = None;
        loop {
            // Current config (transport + dir). An uninitialized db_path = default
            // Server -> do not watch.
            let (is_cloud, dir) = {
                let state = app.state::<AppState>();
                let (transport, cloud_dir) = sync_transport_config(&state).await;
                (
                    transport == persona_core::SyncTransport::Cloud,
                    cloud_dir.filter(|d| !d.trim().is_empty()),
                )
            };
            // Transport/directory changed -> rebuild (or stop) the watcher. An
            // empty/unconfigured/non-cloud directory -> stop (watcher=None), and
            // start again once the config returns.
            let desired: Option<PathBuf> = if is_cloud {
                dir.map(PathBuf::from)
            } else {
                None
            };
            if desired.as_deref() != last_dir.as_deref() {
                last_dir = desired.clone();
                watcher = desired.map(|dir_path| DirWatcher::new(app.clone(), dir_path));
            }
            if let Some(w) = watcher.as_mut() {
                w.tick().await;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_protocol_file_predicate() {
        assert!(is_protocol_file(Path::new("/d/dev-abc.jsonl")));
        assert!(is_protocol_file(Path::new("/d/snapshot-9.bin")));
        assert!(is_protocol_file(Path::new("/d/env-abc.bin")));
        assert!(is_protocol_file(Path::new("/d/env-abc.json")));
        assert!(is_protocol_file(Path::new("/d/registry.json")));
        // Unrelated files dropped into the directory do not trigger sync
        assert!(!is_protocol_file(Path::new("/d/photo.jpg")));
        assert!(!is_protocol_file(Path::new("/d/readme.txt")));
        assert!(!is_protocol_file(Path::new("/d/dev-abc.txt")));
    }

    #[tokio::test]
    async fn fingerprint_covers_protocol_files_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dev-a.jsonl"), b"line1\n").unwrap();
        std::fs::write(dir.path().join("snapshot-1.bin"), b"snap").unwrap();
        std::fs::write(dir.path().join("junk.txt"), b"ignore").unwrap();

        let fp = fingerprint(dir.path()).await;
        assert_eq!(fp.len(), 2, "无关文件不入指纹");
        let dev = fp.get("dev-a.jsonl").expect("dev 分片入指纹");
        assert_eq!(dev.1, 6, "size = 分片行字节数");

        // Directory missing = empty fingerprint (safe side: comparing against any
        // state triggers a round, so nothing is missed)
        assert!(fingerprint(Path::new("/definitely/not/here"))
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn fingerprint_detects_changes_and_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dev-a.jsonl"), b"v1").unwrap();
        let before = fingerprint(dir.path()).await;

        // No-op -> stable (polling does not trigger)
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(fingerprint(dir.path()).await, before);

        // A write (content or size change) -> different fingerprint (polling
        // will trigger a cycle)
        std::fs::write(dir.path().join("dev-a.jsonl"), b"v1 plus").unwrap();
        std::fs::write(dir.path().join("dev-b.jsonl"), b"new shard").unwrap();
        let after = fingerprint(dir.path()).await;
        assert_ne!(after, before);
        assert_eq!(after.len(), 2);

        // File deletion -> different fingerprint (convergence detection)
        std::fs::remove_file(dir.path().join("dev-b.jsonl")).unwrap();
        let removed = fingerprint(dir.path()).await;
        assert_ne!(removed, after);
    }
}
