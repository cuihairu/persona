//! Unix domain socket helpers shared across crates (connect server, ssh-agent).
//!
//! Kept in core so every local-IPC listener applies the same stale-socket
//! semantics: a leftover socket file must be taken over only when nothing is
//! listening on it, never silently hijacked from a live process.

/// socket 路径上的旧文件是否是可接管的陈旧残骸。
///
/// - 不存在 / 非 socket 文件（崩溃残留的普通文件、symlink 等）→ 陈旧；
/// - 是 socket 但 connect 不上（ECONNREFUSED）→ 上一进程死了没清理 → 陈旧；
/// - 是 socket 且能连上 → 有活 listener 在监听 → 非陈旧。
#[cfg(unix)]
pub fn is_stale_socket(path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            // 探测连接：连上即有人监听。连接被立刻关闭，listener 侧按 EOF 处理。
            std::os::unix::net::UnixStream::connect(path).is_err()
        }
        Ok(_) => true,
        Err(_) => true,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::is_stale_socket;

    #[test]
    fn missing_and_non_socket_paths_are_stale() {
        let dir = tempfile::tempdir().unwrap();
        // 不存在 → 陈旧
        assert!(is_stale_socket(&dir.path().join("nope.sock")));
        // 普通文件（崩溃残留的非 socket 文件）→ 陈旧
        let plain = dir.path().join("plain.sock");
        std::fs::write(&plain, b"x").unwrap();
        assert!(is_stale_socket(&plain));
    }

    #[test]
    fn dead_socket_is_stale_but_live_listener_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");

        // 活着的 listener → 非陈旧（不得劫持）
        let live = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(
            !is_stale_socket(&path),
            "活着的 listener 上的 socket 不得判为陈旧"
        );

        // 关掉监听但文件残留（进程崩溃形态）→ 陈旧
        drop(live);
        assert!(is_stale_socket(&path), "无人监听的残留 socket 应判为陈旧");
    }
}
