use super::*;

#[tokio::test]
async fn listener_binds_loopback_serves_defenses_over_tcp_and_releases_on_stop() {
    // No real service needed: neither the listener lifecycle nor the three lines
    // of defense depend on a database.
    let service: ArcTokService = Arc::new(TokioMutex::new(None));
    let handle = start_connect_server(service, 0).await.unwrap();
    assert_ne!(handle.port, 0, "端口 0 要回传 OS 分配的真实值");

    let text = http_over_tcp(
        handle.port,
        "GET",
        "/api/v1/connect/health",
        "127.0.0.1",
        "",
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "真 socket 上 health 应 200: {text}"
    );
    assert!(text.contains("\"ok\":true"), "响应缺包络: {text}");
    assert!(
        text.to_lowercase().contains("cache-control: no-store"),
        "响应缺 no-store: {text}"
    );
    // The three lines of defense are not oneshot-specific: they hold after going
    // through hyper's parsing too
    let text = http_over_tcp(
        handle.port,
        "GET",
        "/api/v1/connect/health",
        "evil.example.com",
        "",
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 421"),
        "DNS rebinding 未拦: {text}"
    );
    let text = http_over_tcp(
        handle.port,
        "GET",
        "/api/v1/connect/health",
        "127.0.0.1",
        "Origin: http://evil.example.com\r\n",
    )
    .await;
    assert!(text.starts_with("HTTP/1.1 403"), "跨源未拦: {text}");
    // The data plane is 503 while the DB is uninitialized (service None); health
    // still returns 200 (real socket)
    let service: ArcTokService = Arc::new(TokioMutex::new(None));
    let handle2 = start_connect_server(service, 0).await.unwrap();
    let auth = "Authorization: Bearer pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n";
    let text = http_over_tcp(
        handle2.port,
        "GET",
        "/api/v1/connect/health",
        "127.0.0.1",
        auth,
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "health 免鉴权，带 token 也应 200: {text}"
    );
    let text = http_over_tcp(
        handle2.port,
        "GET",
        "/api/v1/connect/items",
        "127.0.0.1",
        auth,
    )
    .await;
    assert!(text.starts_with("HTTP/1.1 503"), "未初始化库应 503: {text}");
    assert!(text.contains("vault_locked"), "503 缺错误码: {text}");
    // Missing token -> 401; the order over a real socket matches oneshot
    let text = http_over_tcp(
        handle2.port,
        "GET",
        "/api/v1/connect/items",
        "127.0.0.1",
        "",
    )
    .await;
    assert!(text.starts_with("HTTP/1.1 401"), "缺 token 应 401: {text}");
    assert_ne!(handle.port, handle2.port, "两次 bind 拿到不同端口");

    let (port1, port2) = (handle.port, handle2.port);
    handle.stop();
    handle2.stop();
    // After graceful shutdown the port accepts no more connections (poll rather
    // than sleep and guess a duration)
    let stopped = async {
        for _ in 0..100 {
            if TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port1)))
                .await
                .is_err()
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }
    .await;
    assert!(stopped, "stop() 后 listener 未释放端口 {port1}");
    let still_open = TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port2)))
        .await
        .is_err();
    assert!(still_open, "stop() 后第二个 listener 端口也应关闭");
}

#[tokio::test]
async fn bind_failure_is_propagated_instead_of_silently_retried() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    let service: ArcTokService = Arc::new(TokioMutex::new(None));
    let result = start_connect_server(service, port).await;
    assert!(
        result.is_err(),
        "端口 {port} 被占时 bind 必须报错，不得静默换端口"
    );
    let err = result.err().unwrap();
    let io = err
        .downcast_ref::<std::io::Error>()
        .expect("bind 失败应保持 io::Error 原样，供设置页显式报错");
    assert_eq!(io.kind(), std::io::ErrorKind::AddrInUse, "错误: {err}");
    drop(occupied);
}

// -------------------------------------------------------------------
// unix domain socket transport
// -------------------------------------------------------------------

/// Send raw HTTP/1.1 over a unix socket (same style as http_over_tcp: no HTTP
/// client dependency).
#[cfg(unix)]
async fn http_over_unix(
    path: &std::path::Path,
    method: &str,
    uri: &str,
    host: &str,
    extra: &str,
) -> String {
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let request =
        format!("{method} {uri} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("unix listener 未在 5s 内应答")
        .unwrap();
    String::from_utf8(buf).expect("响应非 UTF-8")
}

/// Full lifecycle of the unix transport: health returns 200 (even for an
/// **arbitrary Host** -- that allowlist belongs to TCP/loopback only, since a
/// unix socket has no name-resolution surface) -> Origin 403 -> missing token
/// 401 -> after stop the socket file is removed and no longer connectable.
#[cfg(unix)]
#[tokio::test]
async fn unix_listener_serves_defenses_and_cleans_up_socket_on_stop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("connect.sock");
    let service: ArcTokService = Arc::new(TokioMutex::new(None));
    let handle =
        start_connect_server_with_transport(service, ConnectTransport::Unix { path: path.clone() })
            .await
            .unwrap();
    assert_eq!(handle.port, 0, "unix 传输没有 TCP 端口");
    assert_eq!(handle.socket_path.as_deref(), Some(path.as_path()));

    // 0600: owner-only connectable (a unix socket connection needs write
    // permission).
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket 文件必须 0600，实际 {:o}", mode);

    // health: the Host allowlist is skipped on the unix transport (an evil Host no
    // longer gets a 421)
    let text = http_over_unix(
        &path,
        "GET",
        "/api/v1/connect/health",
        "evil.example.com",
        "",
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "unix 传输无 DNS rebinding 面，任意 Host 应 200: {text}"
    );
    assert!(text.contains("\"ok\":true"), "响应缺包络: {text}");

    // The Origin line of defense applies unchanged on the unix transport
    let text = http_over_unix(
        &path,
        "GET",
        "/api/v1/connect/health",
        "localhost",
        "Origin: http://evil.example.com\r\n",
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 403"),
        "unix 传输跨源未拦: {text}"
    );

    // The token line of defense applies unchanged (uninitialized DB -> missing
    // token is a 401)
    let text = http_over_unix(&path, "GET", "/api/v1/connect/items", "localhost", "").await;
    assert!(
        text.starts_with("HTTP/1.1 401"),
        "unix 传输缺 token 应 401: {text}"
    );

    // stop_and_wait: wait for the listener task to finish = the serve loop exits
    // and the socket file is deleted (a fire-and-forget stop would leave cleanup
    // racing with process exit).
    handle.stop_and_wait().await;
    assert!(
        !path.exists(),
        "stop_and_wait 返回后 socket 文件必须已移除: {}",
        path.display()
    );
    assert!(
        tokio::net::UnixStream::connect(&path).await.is_err(),
        "stop_and_wait 返回后连接必须被拒"
    );
}

/// Stale leftovers are taken over; a live listener is never hijacked (same
/// policy as the ssh-agent transport). Crash leftovers: socket file present,
/// nobody listening -> take over; someone listening -> error, never steal.
#[cfg(unix)]
#[tokio::test]
async fn unix_listener_takes_over_stale_socket_but_refuses_live_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("connect.sock");

    // Create a stale leftover: bind then immediately drop (the file remains,
    // nobody listening = crash form)
    let dead = tokio::net::UnixListener::bind(&path).unwrap();
    drop(dead);
    assert!(path.exists(), "崩溃残骸应留下 socket 文件");
    assert!(
        persona_core::socket::is_stale_socket(&path),
        "无人监听的残骸应判陈旧"
    );

    let service: ArcTokService = Arc::new(TokioMutex::new(None));
    let handle = start_connect_server_with_transport(
        service.clone(),
        ConnectTransport::Unix { path: path.clone() },
    )
    .await
    .expect("陈旧残骸应被接管");
    // Live listener: a second bind to the same path must error rather than
    // silently hijack
    let err =
        start_connect_server_with_transport(service, ConnectTransport::Unix { path: path.clone() })
            .await
            .expect_err("活 socket 上二次 bind 必须报错，不得劫持");
    assert!(
        err.to_string().contains("live process"),
        "错误应指明已有活 listener: {err}"
    );
    handle.stop();
}

/// Pure peer uid decision: same uid allowed, different uid rejected (the unit
/// test entry for fail-closed behavior -- a cross-uid connection would need a
/// second real user, which CI lacks, so the decision logic is pinned here).
#[cfg(unix)]
#[test]
fn peer_uid_gate_allows_owner_and_rejects_others() {
    assert!(peer_allowed(1000, 1000));
    assert!(!peer_allowed(1001, 1000));
    assert!(!peer_allowed(0, 1000), "root 也不是属主");
}

/// The accept loop's discard branch, end to end: forge owner_uid (self + 1) to
/// simulate a different uid; the connection is dropped at the accept layer --
/// the request gets no HTTP response at all (EOF) and the service keeps living.
/// A genuine cross-uid case needs a second user (unavailable in CI) and the
/// decision pure function is tested separately; this test pins the behavior
/// itself: dropped, not accepted or hung.
#[cfg(unix)]
#[tokio::test]
async fn unix_listener_drops_connections_whose_uid_is_not_the_owner() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("connect.sock");
    let inner = tokio::net::UnixListener::bind(&path).unwrap();
    let our_uid = std::fs::metadata(&path).unwrap().uid();
    let checked = UidCheckedListener {
        inner,
        owner_uid: our_uid.wrapping_add(1),
    };
    let router = build_router(ConnectServerState::new_unix(Arc::new(TokioMutex::new(
        None,
    ))));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(checked, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    // The connection itself is accepted by the kernel (the handshake is unrelated to
    // the accept-layer check) and then dropped: write a request and get no HTTP
    // response whatsoever. Either disconnection shape counts as "dropped
    // successfully" -- a graceful EOF (the request was already read) or
    // ConnectionReset (the request bytes are still in the kernel receive queue
    // and get RST'd away on close); the common denominator is that buf holds no
    // HTTP bytes at all = it never reached the parsing surface.
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    stream
        .write_all(
            b"GET /api/v1/connect/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf))
        .await
        .expect("被丢弃的连接应快速断开，而非挂起");
    // Both EOF (the request was read) and RST (the request bytes are still queued
    // in the kernel and get dropped on close) count as "dropped successfully" --
    // so fold the decision into a single expression: that one decision line runs
    // under either timing, and the message variables are precomputed (a
    // multi-line assert evaluates its message arguments only on failure).
    let discarded = read.is_ok()
        || matches!(&read, Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset);
    let outcome = format!("{read:?}");
    let got = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        discarded,
        "丢弃应表现为 EOF 或 RST，实得 {outcome}，buf: {got}"
    );
    assert!(buf.is_empty(), "不得有任何 HTTP 字节: {got}");
    let _ = shutdown_tx.send(());
}

/// peer_gate's credentials-unavailable branch (the fail-closed backstop layer):
/// on Linux a real connection's SO_PEERCRED always succeeds, so the `Err` path
/// can only be fed directly -- it must reject and log a trace, never allow.
#[cfg(unix)]
#[test]
fn peer_gate_rejects_when_credentials_are_unavailable() {
    let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no creds");
    type L = tokio::net::UnixListener;
    assert!(
        !UidCheckedListener::<L>::peer_gate(Err(err), 1000),
        "取不到凭据必须按拒绝处理（fail-closed）"
    );
    // The allow/reject decision shares the same source, peer_allowed (the mismatch
    // path is covered end to end by the drops test)
    assert!(peer_allowed(1000, 1000));
    assert!(!peer_allowed(0, 1000));
}

/// The accept loop's error classification and backoff (same policy as axum's
/// serve/listener.rs): connection-type errors retry immediately without
/// backoff; everything else logs + backs off for 1s. Real UnixListener accept
/// errors are not reproducible in tests (a deterministic Accept mock injects
/// the error sequence: Refused -> immediate retry; PermissionDenied -> backoff;
/// then hands over the real connection).
#[cfg(unix)]
#[tokio::test]
async fn accept_loop_classifies_errors_retries_and_backs_off() {
    use std::collections::VecDeque;

    /// Mock that injects an error sequence and then hands over a pre-accepted
    /// connection.
    struct FlakyAccept {
        errors: VecDeque<std::io::ErrorKind>,
        ready: Option<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>,
    }
    impl Accept for FlakyAccept {
        async fn accept(
            &mut self,
        ) -> std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)> {
            if let Some(kind) = self.errors.pop_front() {
                return Err(std::io::Error::new(kind, "injected"));
            }
            Ok(self
                .ready
                .take()
                .expect("错误序列耗尽后应交出预 accept 的连接"))
        }
        fn local_addr(&self) -> std::io::Result<tokio::net::unix::SocketAddr> {
            // Not called by tests (axum Serve::local_addr is an explicit method, the serve
            // loop never touches it); SocketAddr is not Copy and has no ==, so
            // no storage is created for it.
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "flaky mock has no local addr",
            ))
        }
    }

    // Pre-accept one real connection (client paired up); the mock's job is to spit
    // out the two errors first.
    let dir = tempfile::tempdir().unwrap();
    let real = tokio::net::UnixListener::bind(dir.path().join("real.sock")).unwrap();
    let client = tokio::net::UnixStream::connect(dir.path().join("real.sock"))
        .await
        .unwrap();
    let (server, server_addr) = real.accept().await.unwrap();
    drop(real);
    // SocketAddr has no PartialEq/Copy/Clone -- capture its Debug text before moving
    // it into the mock.
    let server_addr_dbg = format!("{server_addr:?}");

    let mut checked = UidCheckedListener {
        inner: FlakyAccept {
            errors: VecDeque::from([
                std::io::ErrorKind::ConnectionRefused, // connection-type -> retry immediately
                std::io::ErrorKind::PermissionDenied,  // everything else -> 1s backoff
            ]),
            ready: Some((server, server_addr)),
        },
        owner_uid: std::fs::metadata(dir.path().join("real.sock"))
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid()
            })
            .unwrap_or(0),
    };

    let started = std::time::Instant::now();
    let (stream, returned_addr) = tokio::time::timeout(
        Duration::from_secs(5),
        axum::serve::Listener::accept(&mut checked),
    )
    .await
    .expect("错误序列后应交付连接");
    // PermissionDenied took the 1s backoff; ConnectionRefused did not back off.
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "非连接类错误必须退避 ~1s，实测 {elapsed:?}"
    );
    assert_eq!(format!("{returned_addr:?}"), server_addr_dbg);
    // The mock's local_addr (required by the Listener trait): Flaky has no real
    // address -> Unsupported.
    {
        use axum::serve::Listener as _;
        let err = checked.local_addr().expect_err("Flaky mock 应报无地址");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
    drop(stream);
    drop(client);
}

/// local_addr pass-through (the callee of axum Serve::local_addr).
#[cfg(unix)]
#[tokio::test]
async fn unix_listener_local_addr_delegates_to_inner() {
    use axum::serve::Listener as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("addr.sock");
    let inner = tokio::net::UnixListener::bind(&path).unwrap();
    let expected = inner.local_addr().unwrap();
    let checked = UidCheckedListener {
        inner,
        owner_uid: 0,
    };
    assert_eq!(
        format!("{:?}", checked.local_addr().unwrap()),
        format!("{expected:?}")
    );
}

/// An overlong endpoint name (unix socket path limit ~108 bytes): the bind fails
/// and the path name is not taken -> an explicit "failed to bind" error, rather
/// than the misleading "a live listener already exists".
#[cfg(unix)]
#[tokio::test]
async fn unix_listener_bind_error_on_overlong_endpoint_names_the_cause() {
    let dir = tempfile::tempdir().unwrap();
    let long_name = "n".repeat(200); // beyond sun_path's 108-byte limit
    let path = dir.path().join(long_name);
    let service: ArcTokService = Arc::new(TokioMutex::new(None));
    let err = start_connect_server_with_transport(service, ConnectTransport::Unix { path })
        .await
        .expect_err("超长端点名 bind 必须失败");
    let msg = err.to_string();
    assert!(
        msg.contains("failed to bind connect socket"),
        "应指明 bind 失败: {msg}"
    );
    assert!(
        !msg.contains("live process"),
        "路径名未占用，不得误导为活 listener: {msg}"
    );
}

/// Non-unix platforms (Windows): creating a Unix transport errors immediately
/// with a TCP fallback hint -- no panic, no half-initialized listener left behind.
#[cfg(not(unix))]
#[tokio::test]
async fn unix_transport_is_rejected_on_windows_with_tcp_fallback_hint() {
    let service: ArcTokService = Arc::new(TokioMutex::new(None));
    let err = start_connect_server_with_transport(
        service,
        ConnectTransport::Unix {
            path: std::path::PathBuf::from(r"\\.\pipe\persona-connect-test"),
        },
    )
    .await
    .expect_err("Windows 上 Unix 传输必须显式报错");
    let msg = err.to_string();
    assert!(msg.contains("not supported"), "错误应说明平台不支持: {msg}");
    assert!(msg.contains("TCP"), "错误应给出 TCP 替代指引: {msg}");
}
