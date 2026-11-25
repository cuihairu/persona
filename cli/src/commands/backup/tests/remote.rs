use super::*;

use crate::utils::prompt::scripted::ScriptedUi;

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn push_uploads_a_decryptable_snapshot_and_reports_the_verdict() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = vault_ready(&dir).await;

    let meta = serde_json::json!({
        "id": "b1",
        "device_name": "tester",
        "size_bytes": 4096,
        "sha256": "a".repeat(64),
        "created_at": "2026-09-27T00:00:00Z",
        "deduplicated": false,
    });
    let (addr, log) = spawn_stub(Box::new(move |method, path, _body| {
        assert_eq!(method, "POST");
        assert_eq!(path, "/api/v1/backups");
        json_response(201, &meta)
    }));
    let (_url, _token) = server_env(addr);
    let _pw = TempEnv::set("PERSONA_BACKUP_TEST_PW", "backup-pass");
    execute_with(push_args(), &config, &ScriptedUi::new())
        .await
        .unwrap();

    let served = log.lock().unwrap();
    assert_eq!(served.len(), 1, "push 只该发一个请求");
    assert_eq!(served[0].auth.as_deref(), Some("Bearer test-token"));
    let pushed = served[0].body.clone();
    drop(served);
    assert!(
        !pushed.starts_with(b"SQLite format 3"),
        "推上去的必须是密文，不是明文快照"
    );
    // The promised semantics are "what is on the server can be restored with the same passphrase": actually decrypt it once.
    let staged = dir.path().join("verify.db");
    restore_backup_bytes(&pushed, "backup-pass", &staged).unwrap();
    assert_eq!(identity_count(&staged).await, 1);
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn push_reports_unchanged_when_server_deduplicates() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = vault_ready(&dir).await;

    let meta = serde_json::json!({
        "id": "b0",
        "device_name": "tester",
        "size_bytes": 4096,
        "sha256": "b".repeat(64),
        "created_at": "2026-09-26T00:00:00Z",
        "deduplicated": true,
    });
    let (addr, log) = spawn_stub(Box::new(move |_, _, _| json_response(200, &meta)));
    let (_url, _token) = server_env(addr);
    let _pw = TempEnv::set("PERSONA_BACKUP_TEST_PW", "backup-pass");
    execute_with(push_args(), &config, &ScriptedUi::new())
        .await
        .unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn push_surfaces_the_server_error_message_and_status() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = vault_ready(&dir).await;

    let (addr, log) = spawn_stub(Box::new(|_, _, _| {
        json_response(
            500,
            &serde_json::json!({"error": {"code": "storage_full", "message": "disk full"}}),
        )
    }));
    let (_url, _token) = server_env(addr);
    let _pw = TempEnv::set("PERSONA_BACKUP_TEST_PW", "backup-pass");
    let text = execute_with(push_args(), &config, &ScriptedUi::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(text.contains("push backup failed"), "unexpected: {text}");
    assert!(
        text.contains("disk full"),
        "服务器的 message 要透出来: {text}"
    );
    assert!(text.contains("500"), "状态码要透出来: {text}");
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn list_renders_rows_and_passes_limit_cursor_through() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);

    // Three pages: rows + cursor → empty page → rows without cursor (three prints, three shapes)
    let pages = [
        serde_json::json!({
            "backups": [
                {"id":"b2","device_name":"laptop","size_bytes":2048,
                 "sha256":"c".repeat(64),"created_at":"2026-09-26T10:00:00Z"},
                {"id":"b1","device_name":"phone","size_bytes":1024,
                 "sha256":"d".repeat(64),"created_at":"2026-09-25T10:00:00Z"}
            ],
            "next_cursor": "cur-2"
        }),
        serde_json::json!({"backups": [], "next_cursor": null}),
        serde_json::json!({
            "backups": [
                {"id":"b3","device_name":"laptop","size_bytes":3072,
                 "sha256":"e".repeat(64),"created_at":"2026-09-27T10:00:00Z"}
            ],
            "next_cursor": null
        }),
    ];
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tick = Arc::clone(&counter);
    let (addr, log) = spawn_stub(Box::new(move |method, path, _| {
        assert_eq!(method, "GET");
        assert_eq!(path.split('?').next(), Some("/api/v1/backups"));
        let index = tick.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Only the second call carries a cursor, and it must be exactly the value the server gave on the previous page (echoed back verbatim)
        if index == 1 {
            assert!(path.contains("cursor=cur-2"), "游标必须回传: {path}");
        } else {
            assert!(
                !path.contains("cursor="),
                "不带游标的请求不该有 cursor=: {path}"
            );
        }
        json_response(200, &pages[index.min(2)])
    }));
    let (_url, _token) = server_env(addr);

    execute_with(list_args(20, None), &config, &ScriptedUi::new())
        .await
        .unwrap();
    execute_with(list_args(2, Some("cur-2")), &config, &ScriptedUi::new())
        .await
        .unwrap();
    execute_with(list_args(20, None), &config, &ScriptedUi::new())
        .await
        .unwrap();

    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 3);
    let served = log.lock().unwrap();
    assert!(served[0].path.contains("limit=20"), "{}", served[0].path);
    assert!(served[1].path.contains("limit=2"), "{}", served[1].path);
    assert!(
        served[1].path.contains("cursor=cur-2"),
        "{:#?}",
        served[1].path
    );
    assert!(!served[0].path.contains("cursor="), "首页不该有游标");
    assert!(served
        .iter()
        .all(|r| r.auth.as_deref() == Some("Bearer test-token")));
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn list_reports_the_empty_page_without_error() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
        json_response(
            200,
            &serde_json::json!({"backups": [], "next_cursor": null}),
        )
    }));
    let (_url, _token) = server_env(addr);
    execute_with(list_args(20, None), &config, &ScriptedUi::new())
        .await
        .unwrap();
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn pull_writes_verified_bytes_and_refuses_a_mismatch() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let source = seeded_db(&dir.path().join("source.db")).await;
    let blob = create_backup_bytes(source.pool(), "backup-pass", None)
        .await
        .unwrap();
    let digest = sha256_hex(&blob.bytes);
    source.close().await;

    // (1) ETag matches the bytes -> the file written must be byte-identical to what the server sent
    let bytes = blob.bytes.clone();
    let etag = format!("\"{digest}\"");
    let first_etag = etag.clone();
    let (addr, _log) = spawn_stub(Box::new(move |method, path, _| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/api/v1/backups/b1");
        (200, vec![("ETag", first_etag.clone())], bytes.clone())
    }));
    let (_url, _token) = server_env(addr);
    let out = dir.path().join("vault.persenc");
    execute_with(pull_args("b1", out.clone()), &config, &ScriptedUi::new())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), blob.bytes);

    // (2) ETag mismatch -> the integrity check errors out, and it must never leave a half-written file
    let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
        (
            200,
            vec![("ETag", "\"deadbeef\"".to_owned())],
            b"tampered".to_vec(),
        )
    }));
    let _url2 = TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}"));
    let bad = dir.path().join("tampered.persenc");
    let text = execute_with(pull_args("b1", bad.clone()), &config, &ScriptedUi::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        text.contains("integrity check failed"),
        "unexpected: {text}"
    );
    assert!(!bad.exists(), "校验失败不该落盘");

    // (3) verification passes but writing the file fails -> the error must name the "write", not the "download"
    let bytes2 = blob.bytes.clone();
    let etag2 = etag.clone();
    let (addr, _log) = spawn_stub(Box::new(move |_, _, _| {
        (200, vec![("ETag", etag2.clone())], bytes2.clone())
    }));
    let _url3 = TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}"));
    let nowhere = dir.path().join("no-such-dir").join("vault.persenc");
    let text = execute_with(pull_args("b1", nowhere), &config, &ScriptedUi::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(text.contains("failed to write"), "unexpected: {text}");
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn pull_without_an_etag_header_is_an_error() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
        (
            200,
            vec![("Content-Type", "application/octet-stream".to_owned())],
            b"snapshot".to_vec(),
        )
    }));
    let (_url, _token) = server_env(addr);
    let out = dir.path().join("no-etag.persenc");
    let text = execute_with(pull_args("b1", out.clone()), &config, &ScriptedUi::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        text.contains("did not return an ETag"),
        "unexpected: {text}"
    );
    assert!(!out.exists(), "拿不到摘要就不该写文件");
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn restore_from_server_id_downloads_swaps_and_keeps_bak() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let db_path = config.get_database_path();

    // The backup comes from a vault with a single identity; the live vault then grows to two
    let source = seeded_db(&dir.path().join("source.db")).await;
    let blob = create_backup_bytes(source.pool(), "backup-pass", None)
        .await
        .unwrap();
    let digest = sha256_hex(&blob.bytes);
    source.close().await;
    let live = seeded_db(&db_path).await;
    let repo = IdentityRepository::new(live.clone());
    repo.create(&Identity::new(
        "After Backup".to_owned(),
        IdentityType::Personal,
    ))
    .await
    .unwrap();
    live.close().await;
    assert_eq!(identity_count(&db_path).await, 2);

    let bytes = blob.bytes.clone();
    let etag = format!("\"{digest}\"");
    let (addr, log) = spawn_stub(Box::new(move |method, path, _| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/api/v1/backups/b9");
        (200, vec![("ETag", etag.clone())], bytes.clone())
    }));
    let (_url, _token) = server_env(addr);

    let ui = ScriptedUi::new().confirm(true).password("backup-pass");
    execute_with(restore_args(Some("b9"), None), &config, &ui)
        .await
        .unwrap();
    assert!(ui.exhausted(), "确认与口令提示都应被消费");
    assert_eq!(log.lock().unwrap().len(), 1, "restore 只下载一次");

    assert_eq!(identity_count(&db_path).await, 1, "库回到备份时刻");
    let bak = db_path.with_extension("bak");
    assert_eq!(identity_count(&bak).await, 2, "覆盖前的状态留在 .bak");
    let staged = db_path.with_extension("restore.tmp");
    assert!(!staged.exists(), "暂存文件必须被 rename 走");
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn delete_cancels_locally_and_reports_the_server_verdict() {
    let _guard = env_guard();
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);

    // (1) Cancel: the confirmation gate comes before the client is built, so not a single byte should leave the machine
    let (addr, log) = spawn_stub(Box::new(|_, _, _| {
        json_response(200, &serde_json::json!({}))
    }));
    let (_url, _token) = server_env(addr);
    let ui = ScriptedUi::new().confirm(false);
    execute_with(delete_args("b1", false), &config, &ui)
        .await
        .unwrap();
    assert!(ui.exhausted());
    assert!(log.lock().unwrap().is_empty(), "取消后不得打到服务器");

    // (2) --yes -> the DELETE lands, with Bearer auth
    execute_with(delete_args("b1", true), &config, &ScriptedUi::new())
        .await
        .unwrap();
    {
        let served = log.lock().unwrap();
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].method, "DELETE");
        assert_eq!(served[0].path, "/api/v1/backups/b1");
        assert_eq!(served[0].auth.as_deref(), Some("Bearer test-token"));
    }

    // (3) 404 counts as an idempotent success (an already-deleted backup)
    let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
        json_response(
            404,
            &serde_json::json!({"error": {"code": "not_found", "message": "no such backup"}}),
        )
    }));
    let _url2 = TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}"));
    execute_with(delete_args("b1", true), &config, &ScriptedUi::new())
        .await
        .unwrap();

    // (4) any other status code -> the error carries the server's message
    let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
        json_response(
            500,
            &serde_json::json!({"error": {"code": "db", "message": "readonly"}}),
        )
    }));
    let _url3 = TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}"));
    let text = execute_with(delete_args("b1", true), &config, &ScriptedUi::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(text.contains("delete backup failed"), "unexpected: {text}");
    assert!(text.contains("readonly"), "unexpected: {text}");
}
