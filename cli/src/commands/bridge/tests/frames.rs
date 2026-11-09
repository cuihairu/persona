use super::*;

#[tokio::test]
async fn frame_codec_roundtrip_enforces_length_limits() {
    // Round trip a JSON payload through write_frame/read_frame.
    let (mut client, mut server) = tokio::io::duplex(4096);
    write_frame(&mut client, &serde_json::json!({"hello": "bridge"}))
        .await
        .unwrap();
    let frame = read_frame(&mut server)
        .await
        .unwrap()
        .expect("frame must be present");
    let value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(value["hello"], "bridge");

    // EOF before any bytes means a clean shutdown.
    let (client, mut server) = tokio::io::duplex(64);
    drop(client);
    assert!(read_frame(&mut server).await.unwrap().is_none());

    // A zero length prefix is rejected.
    let (mut client, mut server) = tokio::io::duplex(64);
    client.write_all(&0u32.to_le_bytes()).await.unwrap();
    drop(client);
    let err = read_frame(&mut server).await.unwrap_err();
    assert!(
        err.to_string().contains("invalid_frame_length"),
        "got: {err}"
    );

    // Lengths above the 10 MiB cap are rejected.
    let (mut client, mut server) = tokio::io::duplex(64);
    client
        .write_all(&(10u32 * 1024 * 1024 + 1).to_le_bytes())
        .await
        .unwrap();
    drop(client);
    let err = read_frame(&mut server).await.unwrap_err();
    assert!(
        err.to_string().contains("invalid_frame_length"),
        "got: {err}"
    );

    // A truncated body is an error, not a hang.
    let (mut client, mut server) = tokio::io::duplex(64);
    client.write_all(&64u32.to_le_bytes()).await.unwrap();
    client.write_all(b"partial").await.unwrap();
    drop(client);
    assert!(read_frame(&mut server).await.is_err());
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn bridge_run_bridge_frame_loop_round_trips() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

    let (mut client, server) = tokio::io::duplex(4096);
    let (mut server_rd, mut server_wr) = tokio::io::split(server);
    let handle = tokio::spawn({
        let db_path = db_path.clone();
        let state_dir = state_dir.clone();
        async move { run_bridge(&db_path, &state_dir, &mut server_rd, &mut server_wr).await }
    });

    // A malformed frame is answered with an invalid_json error, and the
    // loop keeps reading afterwards.
    let junk = b"{not json";
    client
        .write_all(&(junk.len() as u32).to_le_bytes())
        .await
        .unwrap();
    client.write_all(junk).await.unwrap();
    let frame = read_frame(&mut client).await.unwrap().unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["type"], "error");
    assert!(
        resp["error"].as_str().unwrap().starts_with("invalid_json"),
        "got: {resp}"
    );

    // A well-formed hello request gets a real response frame.
    let hello = serde_json::to_vec(&serde_json::json!({
        "request_id": "req-1",
        "type": "hello",
        "payload": {
            "extension_id": "ext-loop",
            "extension_version": "1.0",
            "protocol_version": 2,
            "client_instance_id": "inst-loop"
        }
    }))
    .unwrap();
    client
        .write_all(&(hello.len() as u32).to_le_bytes())
        .await
        .unwrap();
    client.write_all(&hello).await.unwrap();
    let frame = read_frame(&mut client).await.unwrap().unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(resp["ok"], true, "hello must succeed: {resp}");
    assert_eq!(resp["type"], "hello_response");

    // EOF on the reader side ends the loop cleanly.
    drop(client);
    handle.await.unwrap().unwrap();

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
}

#[tokio::test]
async fn bridge_run_bridge_rejects_zero_length_frame() {
    // A zero-length frame header is rejected before any request handling.
    let mut reader = std::io::Cursor::new(0u32.to_le_bytes().to_vec());
    let mut writer = Vec::new();
    let err = run_bridge(Path::new(""), Path::new(""), &mut reader, &mut writer)
        .await
        .expect_err("zero-length frame must fail");
    assert!(
        err.to_string().contains("invalid_frame_length"),
        "got: {err}"
    );
}
