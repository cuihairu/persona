use super::*;

/// A register response whose device_id is not a UUID: fail-closed.
#[tokio::test(flavor = "multi_thread")]
async fn register_device_rejects_non_uuid_device_id() {
    let base = spawn_mock(Arc::new(|_req| {
        (200, r#"{"device_id":"nope"}"#.to_string())
    }))
    .await;
    let admin = SyncAdminApi::new(base, "tok").unwrap();

    let err = admin
        .register_device("laptop", &[7u8; 32])
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("malformed device_id in sync register response"),
        "{err}"
    );
}

/// The field-defense arms of list_devices: a non-UUID id, a public_key with bad base64, and a
/// public_key whose length is not 32 bytes — rejected one category at a time.
#[tokio::test(flavor = "multi_thread")]
async fn list_devices_rejects_bad_id_and_bad_public_key() {
    let short_key = B64.encode([0u8; 16]);
    let mk_body = |id: &str, key: &str| {
        format!(
            r#"{{"devices":[{{"id":"{id}","device_name":"laptop","public_key":"{key}","created_at":"t"}}]}}"#
        )
    };
    let cases = [
        (
            "malformed device id",
            mk_body("nope", &B64.encode([7u8; 32])),
        ),
        ("bad base64", mk_body(&Uuid::new_v4().to_string(), " !!! ")),
        (
            "bad length",
            mk_body(&Uuid::new_v4().to_string(), &short_key),
        ),
    ];
    for (needle, body) in cases {
        let base = spawn_mock(Arc::new(move |_req| (200, body.clone()))).await;
        let admin = SyncAdminApi::new(base, "tok").unwrap();
        let err = admin.list_devices().await.unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "expected {needle:?} in: {err}"
        );
    }
}

/// The remark field: a new server parses it verbatim; an old server (without the field) defaults to an empty string.
#[tokio::test(flavor = "multi_thread")]
async fn list_devices_parses_remark_and_defaults_missing_to_empty() {
    let device_json = |remark: &str| {
        let field = if remark.is_empty() {
            String::new()
        } else {
            format!(r#","remark":"{remark}""#)
        };
        format!(
            r#"{{"devices":[{{"id":"{}","device_name":"laptop","public_key":"{}","created_at":"t"{field}}}]}}"#,
            Uuid::new_v4(),
            B64.encode([7u8; 32]),
        )
    };
    let base_with = spawn_mock(Arc::new(move |_req| (200, device_json("主力机")))).await;
    let admin = SyncAdminApi::new(&base_with, "tok").unwrap();
    let devices = admin.list_devices().await.unwrap();
    assert_eq!(devices[0].remark, "主力机");

    let base_without = spawn_mock(Arc::new(move |_req| (200, device_json("")))).await;
    let admin = SyncAdminApi::new(&base_without, "tok").unwrap();
    let devices = admin.list_devices().await.unwrap();
    assert_eq!(devices[0].remark, "");
}

/// set_device_remark: PUT /devices/remark with a bearer token and a JSON body; the echoed remark is the
/// server-trimmed stored value. A device that is not registered (404) reports a fail-closed error.
#[tokio::test(flavor = "multi_thread")]
async fn set_device_remark_sends_put_and_surfaces_absent_device() {
    let captured: Arc<Mutex<Vec<Captured>>> = Default::default();
    let sink = captured.clone();
    let base = spawn_mock(Arc::new(move |req| {
        sink.lock().unwrap().push(req);
        (
            200,
            r#"{"device_name":"laptop","remark":"主力机"}"#.to_string(),
        )
    }))
    .await;
    let admin = SyncAdminApi::new(&base, "tok-laptop").unwrap();

    let stored = admin.set_device_remark("主力机").await.unwrap();
    assert_eq!(stored, "主力机");
    // Block-scope guard (clippy@1.99's await_holding_lock does not accept an explicit drop(), and there are
    // still two await points below: spawn_mock/set_device_remark)
    {
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");
        assert_eq!(reqs[0].path, "/api/v1/sync/devices/remark");
        assert_eq!(reqs[0].auth.as_deref(), Some("Bearer tok-laptop"));
        assert!(reqs[0].body.contains("主力机"), "{}", reqs[0].body);
    }

    let base = spawn_mock(Arc::new(|_req| {
        (
            404,
            r#"{"error":{"code":"absent","message":"device not registered"}}"#.to_string(),
        )
    }))
    .await;
    let admin = SyncAdminApi::new(base, "tok").unwrap();
    let err = admin.set_device_remark("孤儿").await.unwrap_err();
    assert!(
        err.to_string().contains("set device remark"),
        "error should name the failed call: {err}"
    );
}

/// The field-defense arms of group-keys: a non-UUID device_id and an envelope with bad base64.
#[tokio::test(flavor = "multi_thread")]
async fn group_keys_rejects_bad_device_id_and_bad_envelope() {
    let cases = [
        (
            "malformed device_id",
            r#"{"keys":[{"device_id":"nope","envelope":"AAAA","sealed_by":"s","created_at":"t"}],"epoch":0}"#,
        ),
        (
            "malformed envelope",
            &format!(
                r#"{{"keys":[{{"device_id":"{}","envelope":" !!! ","sealed_by":"s","created_at":"t"}}],"epoch":1}}"#,
                Uuid::new_v4()
            ),
        ),
    ];
    for (needle, body) in cases {
        let owned = body.to_string();
        let base = spawn_mock(Arc::new(move |_req| (200, owned.clone()))).await;
        let admin = SyncAdminApi::new(base, "tok").unwrap();
        let err = admin.group_keys_with_epoch().await.unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "expected {needle:?} in: {err}"
        );
    }
}

/// Old-server compatibility: a group-keys response without an epoch field -> serde default 0
/// (the same shape as "never rotated", and the safe direction for begin).
#[tokio::test(flavor = "multi_thread")]
async fn group_keys_without_epoch_field_defaults_to_zero() {
    let base = spawn_mock(Arc::new(|_req| (200, r#"{"keys":[]}"#.to_string()))).await;
    let admin = SyncAdminApi::new(base, "tok").unwrap();

    let (keys, epoch) = admin.group_keys_with_epoch().await.unwrap();
    assert!(keys.is_empty());
    assert_eq!(epoch, 0);
}

// ---- Vault-level snapshot wire (S2) ----
