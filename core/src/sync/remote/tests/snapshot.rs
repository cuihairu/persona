use super::*;

/// PUT/GET /snapshot 的 wire 正面：路径、方法、bearer；PUT 响应回显
/// seq 一致放行 + pruned_ops 透传；GET 的 base64 密文解包。
#[tokio::test(flavor = "multi_thread")]
async fn snapshot_put_get_wire_contract() {
    let captured: Arc<Mutex<Vec<Captured>>> = Default::default();
    let sink = captured.clone();
    let base = spawn_mock(Arc::new(move |req| {
        let method = req.method.clone();
        sink.lock().unwrap().push(req);
        match method.as_str() {
            "PUT" => (200, r#"{"seq":5,"pruned_ops":2}"#.to_string()),
            _ => (
                200,
                format!(
                    r#"{{"seq":5,"device_id":"d","ciphertext":"{}","created_at":"t"}}"#,
                    B64.encode([9u8; 4])
                ),
            ),
        }
    }))
    .await;
    let remote = HttpSyncRemote::new(&base, "tok-1").unwrap();

    let pruned = remote
        .put_library_snapshot(5, "dev-1", &[7u8; 3])
        .await
        .unwrap();
    assert_eq!(pruned, 2);
    let snap = remote.get_library_snapshot().await.unwrap();
    assert_eq!(snap, Some((5, vec![9u8; 4])));

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].method, "PUT");
    assert_eq!(reqs[0].path, "/api/v1/sync/snapshot");
    assert_eq!(reqs[0].auth.as_deref(), Some("Bearer tok-1"));
    assert_eq!(reqs[1].method, "GET");
    assert_eq!(reqs[1].path, "/api/v1/sync/snapshot");
}

/// GET 404 → Ok(None)：新服务器尚无快照（absent）与老服务器无此路由
/// （not_found）在客户端行为上收敛为全量重放。
#[tokio::test(flavor = "multi_thread")]
async fn snapshot_fetch_404_maps_to_none() {
    for body in [
        r#"{"error":{"code":"absent","message":"no snapshot yet"}}"#,
        r#"{"error":{"code":"not_found","message":"no such route"}}"#,
    ] {
        let owned = body.to_string();
        let base = spawn_mock(Arc::new(move |_req| (404, owned.clone()))).await;
        let remote = HttpSyncRemote::new(&base, "tok").unwrap();
        assert_eq!(remote.get_library_snapshot().await.unwrap(), None);
    }
}

/// PUT 响应回显 seq 与请求不符（代理/缓存错乱面）：fail-closed。
#[tokio::test(flavor = "multi_thread")]
async fn snapshot_upload_rejects_seq_mismatch() {
    let base = spawn_mock(Arc::new(|_req| {
        (200, r#"{"seq":6,"pruned_ops":0}"#.to_string())
    }))
    .await;
    let remote = HttpSyncRemote::new(base, "tok").unwrap();
    let err = remote
        .put_library_snapshot(5, "dev-1", &[1u8; 3])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("seq mismatch"), "{err}");
}

/// malformed 响应臂：PUT 非 JSON、GET 非 JSON、GET 密文坏 base64。
#[tokio::test(flavor = "multi_thread")]
async fn snapshot_malformed_responses_are_rejected() {
    let base = spawn_mock(Arc::new(|req| match req.method.as_str() {
        "PUT" => (200, "not json".to_string()),
        _ => (200, "still not json".to_string()),
    }))
    .await;
    let remote = HttpSyncRemote::new(&base, "tok").unwrap();
    let err = remote
        .put_library_snapshot(5, "d", &[1u8; 3])
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("malformed sync snapshot upload response"),
        "{err}"
    );
    let err = remote.get_library_snapshot().await.unwrap_err();
    assert!(
        err.to_string().contains("malformed sync snapshot response"),
        "{err}"
    );

    let base = spawn_mock(Arc::new(|_req| {
        (200, r#"{"seq":1,"ciphertext":" !!! "}"#.to_string())
    }))
    .await;
    let remote = HttpSyncRemote::new(base, "tok").unwrap();
    let err = remote.get_library_snapshot().await.unwrap_err();
    assert!(err.to_string().contains("bad base64"), "{err}");
}
