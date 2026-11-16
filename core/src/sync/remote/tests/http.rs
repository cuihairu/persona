use super::*;

/// mock 基建自身的两臂：status 0（不回包直接断开——Handler 约定，
/// 驱动客户端 send 失败）；请求头读到一半客户端断连（read_request
/// EOF → None，mock 不 panic 静默回收）。
#[tokio::test(flavor = "multi_thread")]
async fn mock_status_zero_and_mid_header_disconnect_are_tolerated() {
    let base = spawn_mock(Arc::new(|_req| (0, String::new()))).await;
    let remote = HttpSyncRemote::new(base.clone(), "tok").unwrap();
    let err = remote.push_ops(&[sample_put()]).await.unwrap_err();
    assert!(
        err.to_string().contains("sync push request failed"),
        "{err}"
    );

    // 半个请求头后直接断连
    let mut raw = TcpStream::connect(base.trim_start_matches("http://"))
        .await
        .unwrap();
    raw.write_all(b"POST /api/v1/sync/oplog HTTP/1.1\r\n")
        .await
        .unwrap();
    drop(raw);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// push/pull 的 send 失败臂都带步骤名（fail-closed，错误不吞）。
#[tokio::test(flavor = "multi_thread")]
async fn push_pull_connection_failures_carry_step_names() {
    // bind 后立即 drop：端口必然无服务
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = listener.local_addr().unwrap();
    drop(listener);
    let remote = HttpSyncRemote::new(format!("http://{dead}"), "tok").unwrap();

    let err = remote.push_ops(&[sample_put()]).await.unwrap_err();
    assert!(
        err.to_string().contains("sync push request failed"),
        "{err}"
    );
    let err = remote.pull_ops(None, 10).await.unwrap_err();
    assert!(
        err.to_string().contains("sync pull request failed"),
        "{err}"
    );
}

/// 200 但 body 不是 JSON：push/pull 各自的 malformed 响应臂。
#[tokio::test(flavor = "multi_thread")]
async fn push_pull_malformed_bodies_are_rejected() {
    let base = spawn_mock(Arc::new(|_req| (200, "not json at all".to_string()))).await;
    let remote = HttpSyncRemote::new(base, "tok").unwrap();

    let err = remote.push_ops(&[sample_put()]).await.unwrap_err();
    assert!(
        err.to_string().contains("malformed sync push response"),
        "{err}"
    );
    let err = remote.pull_ops(None, 10).await.unwrap_err();
    assert!(
        err.to_string().contains("malformed sync pull response"),
        "{err}"
    );
}

/// 非 JSON 错误体（反代 502 HTML）：只报状态码，不透传脏内容。
#[tokio::test(flavor = "multi_thread")]
async fn error_status_without_json_body_omits_summary() {
    let base = spawn_mock(Arc::new(|_req| (502, "<html>boom</html>".to_string()))).await;
    let remote = HttpSyncRemote::new(base, "tok").unwrap();

    let err = remote.push_ops(&[sample_put()]).await.unwrap_err();
    let msg = err.to_string();
    // reqwest 的 StatusCode Display 带规范原因短语
    assert!(
        msg.contains("sync push failed (HTTP 502 Bad Gateway)"),
        "{msg}"
    );
    assert!(!msg.contains("boom"), "{msg}");
}

/// wire 形状正面断言：bearer 头每请求携带、push 走 POST /oplog、
/// pull 的 since 游标进 query。
#[tokio::test(flavor = "multi_thread")]
async fn push_sends_bearer_and_pull_sends_cursor_query() {
    let captured: Arc<Mutex<Vec<Captured>>> = Default::default();
    let sink = captured.clone();
    let base = spawn_mock(Arc::new(move |req| {
        let method = req.method.clone();
        sink.lock().unwrap().push(req);
        if method == "POST" {
            (200, r#"{"accepted":1,"duplicates":0}"#.to_string())
        } else {
            (200, r#"{"ops":[],"next_cursor":null}"#.to_string())
        }
    }))
    .await;
    let remote = HttpSyncRemote::new(&base, "tok-1").unwrap();

    let (accepted, duplicates) = remote.push_ops(&[sample_put()]).await.unwrap();
    assert_eq!((accepted, duplicates), (1, 0));
    let (ops, cursor) = remote.pull_ops(Some("cursor-x"), 7).await.unwrap();
    assert!(ops.is_empty());
    assert!(cursor.is_none());

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].auth.as_deref(), Some("Bearer tok-1"));
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/v1/sync/oplog");
    assert!(reqs[1].path.contains("limit=7"), "{}", reqs[1].path);
    assert!(reqs[1].path.contains("since=cursor-x"), "{}", reqs[1].path);
}
