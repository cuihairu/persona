use super::*;

/// The two arms of the mock infrastructure itself: status 0 (drop the connection without replying — the
/// Handler contract — which drives the client's send failure); and the client disconnecting mid request
/// head (read_request EOF -> None, so the mock silently reclaims the connection instead of panicking).
#[tokio::test(flavor = "multi_thread")]
async fn mock_status_zero_and_mid_header_disconnect_are_tolerated() {
    let base = spawn_mock(Arc::new(|_req| (0, String::new()))).await;
    let remote = HttpSyncRemote::new(base.clone(), "tok").unwrap();
    let err = remote.push_ops(&[sample_put()]).await.unwrap_err();
    assert!(
        err.to_string().contains("sync push request failed"),
        "{err}"
    );

    // Disconnect right after half a request head
    let mut raw = TcpStream::connect(base.trim_start_matches("http://"))
        .await
        .unwrap();
    raw.write_all(b"POST /api/v1/sync/oplog HTTP/1.1\r\n")
        .await
        .unwrap();
    drop(raw);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// The send-failure arms of push and pull both carry the step name (fail-closed, no swallowed errors).
#[tokio::test(flavor = "multi_thread")]
async fn push_pull_connection_failures_carry_step_names() {
    // Drop right after binding: nothing can be listening on that port
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

/// A 200 whose body is not JSON: the malformed response arm for push and pull alike.
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

/// A non-JSON error body (a reverse proxy's 502 HTML): only the status code is reported, never the dirty content.
#[tokio::test(flavor = "multi_thread")]
async fn error_status_without_json_body_omits_summary() {
    let base = spawn_mock(Arc::new(|_req| (502, "<html>boom</html>".to_string()))).await;
    let remote = HttpSyncRemote::new(base, "tok").unwrap();

    let err = remote.push_ops(&[sample_put()]).await.unwrap_err();
    let msg = err.to_string();
    // reqwest's StatusCode Display carries the canonical reason phrase
    assert!(
        msg.contains("sync push failed (HTTP 502 Bad Gateway)"),
        "{msg}"
    );
    assert!(!msg.contains("boom"), "{msg}");
}

/// Happy-path wire shape assertions: the bearer header is sent with every request, push goes over
/// POST /oplog, and pull's since cursor lands in the query string.
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
