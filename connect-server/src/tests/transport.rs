use super::*;

#[tokio::test]
async fn listener_binds_loopback_serves_defenses_over_tcp_and_releases_on_stop() {
    // 不需要真 service：listener 生命周期与三防线都不依赖库。
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
    // 三防线不是 oneshot 专属：走 hyper 解析后同样生效
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
    // 数据面在库未初始化（service None）时 503；health 仍 200（真 socket）
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
    // 缺 token → 401；真 socket 上的顺序与 oneshot 一致
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
    // graceful shutdown 后端口不再接受连接（轮询而非 sleep 猜时长）
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
// unix domain socket 传输
// -------------------------------------------------------------------

/// 经 unix socket 发裸 HTTP/1.1（与 http_over_tcp 同款：无 HTTP 客户端依赖）。
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

/// unix 传输全生命周期：health 200（含**任意 Host**——该白名单只属
/// TCP/loopback，unix socket 无名字解析面）→ Origin 403 → 缺 token 401 →
/// stop 后 socket 文件移除且不可再连。
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

    // 0600：仅属主可连（unix socket 连接需要写权限）。
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket 文件必须 0600，实际 {:o}", mode);

    // health：Host 白名单在 unix 传输上跳过（evil Host 不再 421）
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

    // Origin 防线在 unix 传输上原样生效
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

    // token 防线原样生效（库未初始化 → 缺 token 401）
    let text = http_over_unix(&path, "GET", "/api/v1/connect/items", "localhost", "").await;
    assert!(
        text.starts_with("HTTP/1.1 401"),
        "unix 传输缺 token 应 401: {text}"
    );

    // stop_and_wait：等 listener 任务完成 = serve 循环退出 + socket 文件
    // 已删（fire-and-forget 的 stop 会把清理留在进程退出的竞态里）。
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

/// 陈旧残骸接管、活 listener 不劫持（口径同 ssh-agent transport）。
/// 崩溃残留：socket 文件在、无人监听 → 接管；有人监听 → 报错不抢。
#[cfg(unix)]
#[tokio::test]
async fn unix_listener_takes_over_stale_socket_but_refuses_live_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("connect.sock");

    // 造陈旧残骸：bind 后立刻 drop（文件留下，无人监听 = 崩溃形态）
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
    // 活 listener：第二次 bind 同一路径必须报错而非静默劫持
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

/// peer uid 判定纯函数：同 uid 放行、异 uid 拒绝（fail-closed 的单测
/// 入口——跨 uid 连接需要第二个真实用户，CI 不具备，判定逻辑在此固化）。
#[cfg(unix)]
#[test]
fn peer_uid_gate_allows_owner_and_rejects_others() {
    assert!(peer_allowed(1000, 1000));
    assert!(!peer_allowed(1001, 1000));
    assert!(!peer_allowed(0, 1000), "root 也不是属主");
}

/// accept 循环的丢弃分支端到端：伪造 owner_uid（自身 +1）模拟异 uid，
/// 连接在 accept 层被丢弃——请求得不到任何 HTTP 响应（EOF），服务继续
/// 存活。真实跨 uid 需要第二个用户（CI 不可得），判定纯函数另测；
/// 此测钉住「丢弃而非接受/挂起」的行为本身。
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

    // 连接本身会被内核接受（握手与 accept 层校验无关），随后被丢弃：
    // 写请求 → 无任何 HTTP 响应。两种断开形状都算「丢弃成功」——
    // 优雅 EOF（请求已被读走）或 ConnectionReset（请求字节还在内核
    // 接收队列里，close 时被 RST 丢弃）；共同点是 buf 里没有任何
    // HTTP 字节 = 没进解析面。
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
    // EOF（请求被读走）与 RST（请求字节仍在内核队列，close 时被丢弃）
    // 都是「丢弃成功」——判定并进单表达式：两种时序下同一条判定行恒执行，
    // 消息变量预计算（多行 assert 的消息参数行只在失败时执行）。
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

/// peer_gate 的凭据不可用分支（fail-closed 兜底层）：Linux 上真实连接
/// 的 SO_PEERCRED 恒成功，`Err` 路径只能直接喂——拒绝并留痕，不得放行。
#[cfg(unix)]
#[test]
fn peer_gate_rejects_when_credentials_are_unavailable() {
    let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no creds");
    type L = tokio::net::UnixListener;
    assert!(
        !UidCheckedListener::<L>::peer_gate(Err(err), 1000),
        "取不到凭据必须按拒绝处理（fail-closed）"
    );
    // 放行与拒绝的判定同源 peer_allowed（mismatch 路径由 drops 测试端到端覆盖）
    assert!(peer_allowed(1000, 1000));
    assert!(!peer_allowed(0, 1000));
}

/// accept 循环的错误分类与退避（axum serve/listener.rs 同口径）：
/// 连接类错误立即重试不退避；其余 log + 1s 退避。真实 UnixListener 的
/// accept 错误在测试里不可复现（确定性 Accept mock 注入错误序列：
/// Refused → 立即重试；PermissionDenied → 退避；然后交出真实连接）。
#[cfg(unix)]
#[tokio::test]
async fn accept_loop_classifies_errors_retries_and_backs_off() {
    use std::collections::VecDeque;

    /// 注入错误序列、随后交出预 accept 连接的 mock。
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
            // 测试不调用（axum Serve::local_addr 是显式方法，serve 循环不碰）；
            // SocketAddr 非 Copy/无 ==，不为它造存储。
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "flaky mock has no local addr",
            ))
        }
    }

    // 预 accept 一条真实连接（客户端配对），mock 负责先吐两个错误。
    let dir = tempfile::tempdir().unwrap();
    let real = tokio::net::UnixListener::bind(dir.path().join("real.sock")).unwrap();
    let client = tokio::net::UnixStream::connect(dir.path().join("real.sock"))
        .await
        .unwrap();
    let (server, server_addr) = real.accept().await.unwrap();
    drop(real);
    // SocketAddr 无 PartialEq/Copy/Clone——移动进 mock 前先取 Debug 文本。
    let server_addr_dbg = format!("{server_addr:?}");

    let mut checked = UidCheckedListener {
        inner: FlakyAccept {
            errors: VecDeque::from([
                std::io::ErrorKind::ConnectionRefused, // 连接类 → 立即重试
                std::io::ErrorKind::PermissionDenied,  // 其余 → 1s 退避
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
    // PermissionDenied 走了 1s 退避；ConnectionRefused 不退避。
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "非连接类错误必须退避 ~1s，实测 {elapsed:?}"
    );
    assert_eq!(format!("{returned_addr:?}"), server_addr_dbg);
    // mock 的 local_addr（Listener trait 必备）：Flaky 没有真实地址 → Unsupported。
    {
        use axum::serve::Listener as _;
        let err = checked.local_addr().expect_err("Flaky mock 应报无地址");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
    drop(stream);
    drop(client);
}

/// local_addr 透传（axum Serve::local_addr 的被调方）。
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

/// 端点名超长（unix socket 路径上限 ~108 字节）：bind 失败且路径名
/// 未占用 → 显式「failed to bind」错误，而非「已有活 listener」误导。
#[cfg(unix)]
#[tokio::test]
async fn unix_listener_bind_error_on_overlong_endpoint_names_the_cause() {
    let dir = tempfile::tempdir().unwrap();
    let long_name = "n".repeat(200); // 超过 sun_path 的 108 字节上限
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

/// 非 unix 平台（Windows）：Unix 传输创建即报错并给出 TCP 替代指引，
/// 不 panic、不留半初始化 listener。
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
