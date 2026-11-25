//! Unix domain socket helpers shared across crates (connect server, ssh-agent).
//!
//! Kept in core so every local-IPC listener applies the same stale-socket
//! semantics: a leftover socket file must be taken over only when nothing is
//! listening on it, never silently hijacked from a live process.

/// Whether the leftover file at `path` is a stale remnant safe to take over.
///
/// - Missing / not a socket (a plain file or symlink left by a crash) → stale;
/// - A socket that cannot be connected to (ECONNREFUSED) → the previous
///   process died without cleaning up → stale;
/// - A socket that connects → a live listener is on it → not stale.
#[cfg(unix)]
pub fn is_stale_socket(path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            // Probe connection: connecting means something is listening. The
            // connection is closed immediately; the listener side handles it as EOF.
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
        // Missing → stale
        assert!(is_stale_socket(&dir.path().join("nope.sock")));
        // Plain file (a non-socket file left by a crash) → stale
        let plain = dir.path().join("plain.sock");
        std::fs::write(&plain, b"x").unwrap();
        assert!(is_stale_socket(&plain));
    }

    #[test]
    fn dead_socket_is_stale_but_live_listener_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");

        // Live listener → not stale (must not be hijacked)
        let live = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(
            !is_stale_socket(&path),
            "活着的 listener 上的 socket 不得判为陈旧"
        );

        // Listener gone but the file remains (the crash shape) → stale
        drop(live);
        assert!(is_stale_socket(&path), "无人监听的残留 socket 应判为陈旧");
    }
}
