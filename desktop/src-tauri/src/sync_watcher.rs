//! 云盘同步目录变更 watcher（宿主侧）。
//!
//! 同步引擎是 pull-driven：没有任何机制在远端把新 op 写进云盘目录后
//! 主动触发本机同步。本模块补上这条「远端变更 → 触发 run_cycle」链路：
//! 监听 `cloud_drive_dir` 的协议文件（`dev-*.jsonl` / `snapshot-*` /
//! `env-*` / `registry.json`）变更，去抖（5s 主循环即天然去抖）后跑一轮
//! 同步周期。
//!
//! 两条触发源：
//! - **`notify`（主）**：目录级文件系统事件。目录在网络文件系统（inotify
//!   不触发）或 watch 启动失败时自动降级——只留下轮询。
//! - **mtime 指纹轮询（兜底，恒开）**：每 30s 对协议文件做
//!   `(mtime_ns, size)` 指纹，变了才触发。notify 失效时靠它收敛。
//!
//! 反馈抑制：周期里本机 push 会写自己的分片 → 又触发一轮。周期结束后把
//! 基线刷到当前指纹，使自写不产生连锁（下一轮周期无事可推即停）。
//!
//! core 保持依赖无关——watcher 只在 desktop 宿主（`notify` 是本 crate
//! 的依赖，不进 core）。周期编排复用 [`crate::commands::sync::sync_cycle_once`]，
//! 门禁（解锁/已入组/云盘目录已配）都在那里，watcher 只负责触发。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use notify::Watcher;
use tauri::{AppHandle, Manager};

use crate::commands::{sync_cycle_once, sync_transport_config};
use crate::types::AppState;

/// 协议文件名谓词：只有云盘同步协议文件值得触发周期（用户放进去的
/// 无关文件不惊动同步）。
fn is_protocol_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    (name.starts_with("dev-") && name.ends_with(".jsonl"))
        || (name.starts_with("snapshot-") && name.ends_with(".bin"))
        || (name.starts_with("env-") && (name.ends_with(".bin") || name.ends_with(".json")))
        || name == "registry.json"
}

/// 协议文件的 mtime/size 指纹（name → (mtime_ns, len)）。目录不存在 /
/// 读失败 = 空表（安全侧：空表变化会触发一轮，不会漏）。
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

/// 一个云盘目录的监听器：notify（尽力而为）+ 轮询指纹 + 周期触发。
struct DirWatcher<R: tauri::Runtime> {
    dir: PathBuf,
    app: AppHandle<R>,
    /// notify 事件信号（协议文件变更 → 置位；去抖在主循环）。
    notify_events: tokio::sync::mpsc::UnboundedReceiver<()>,
    /// notify 监听器本体（None = notify 不可用/启动失败，只留轮询）。
    _notify: Option<notify::RecommendedWatcher>,
    baseline: BTreeMap<String, (u64, u64)>,
    last_poll: Instant,
    cycle_running: bool,
}

impl<R: tauri::Runtime> DirWatcher<R> {
    fn new(app: AppHandle<R>, dir: PathBuf) -> Self {
        // notify 尽力而为：目录不存在 / 平台不支持 / 网络文件系统 →
        // None，轮询兜底（日志记录降级原因，不阻断）。
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

    /// 跑一轮（主循环每 5s 调一次）：排空 notify 信号 + 到点轮询指纹 →
    /// 有变更则触发周期（防重入）。
    async fn tick(&mut self) {
        let mut changed = false;
        // 排空 notify 事件（主循环 5s 一次即天然去抖：周期只在排空时跑，
        // 突发变更折叠成一轮）
        while self.notify_events.try_recv().is_ok() {
            changed = true;
        }
        // 轮询兜底：每 30s 对协议文件做指纹，变了才触发
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
                // 常见是「已锁定/未入组/目录未配置」——这些不是故障，
                // 门禁在 sync_cycle_once 内，静默（debug 级）即可。
                tracing::debug!(error = %e, "cloud watcher sync cycle skipped");
            }
        }
        // 周期后基线刷新：本机 push 写的分片不再触发下一轮（自写反馈
        // 抑制——下一轮无事可推即停）。
        self.baseline = fingerprint(&self.dir).await;
    }
}

/// 启动云盘 watcher 总监督（应用 setup 时一次）。单任务循环：每 5s 重评
/// 配置（transport/dir 是否 cloud + 目录是否变化），维护一个 [`DirWatcher`]。
/// 任务随进程退出自然终止；无需 stop 句柄——watcher 只在 cloud 传输配置
/// 且目录存在时做实事，其余时间空转（一个轻量配置读取）。
pub(crate) fn spawn_sync_watcher<R: tauri::Runtime>(app: AppHandle<R>) {
    tauri::async_runtime::spawn(async move {
        let mut watcher: Option<DirWatcher<R>> = None;
        let mut last_dir: Option<PathBuf> = None;
        loop {
            // 当前配置（transport + dir）。db_path 未初始化 = 默认 Server
            // → 不 watch。
            let (is_cloud, dir) = {
                let state = app.state::<AppState>();
                let (transport, cloud_dir) = sync_transport_config(&state).await;
                (
                    transport == persona_core::SyncTransport::Cloud,
                    cloud_dir.filter(|d| !d.trim().is_empty()),
                )
            };
            // 传输/目录变化 → 重建（或停掉）监听器。目录为空/未配置/
            // 非 cloud → 停（watcher=None），配置回来再起。
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
        // 用户放进目录的无关文件不触发同步
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

        // 目录不存在 = 空指纹（安全侧：与任何状态比较都会触发一轮，不漏）
        assert!(fingerprint(Path::new("/definitely/not/here"))
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn fingerprint_detects_changes_and_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dev-a.jsonl"), b"v1").unwrap();
        let before = fingerprint(dir.path()).await;

        // 无操作 → 稳定（轮询不触发）
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(fingerprint(dir.path()).await, before);

        // 写入（内容或大小变化）→ 指纹不同（轮询会触发周期）
        std::fs::write(dir.path().join("dev-a.jsonl"), b"v1 plus").unwrap();
        std::fs::write(dir.path().join("dev-b.jsonl"), b"new shard").unwrap();
        let after = fingerprint(dir.path()).await;
        assert_ne!(after, before);
        assert_eq!(after.len(), 2);

        // 文件删除 → 指纹不同（收敛检测）
        std::fs::remove_file(dir.path().join("dev-b.jsonl")).unwrap();
        let removed = fingerprint(dir.path()).await;
        assert_ne!(removed, after);
    }
}
