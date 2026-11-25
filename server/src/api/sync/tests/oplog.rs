use super::*;

// ---- Server-side oplog retention policy (§11 open question 3 closeout) ----

#[tokio::test]
async fn oplog_retention_prunes_over_window_and_repush_rebuilds() {
    let (router, state) = setup_with_retention(Some(TOKEN), 30, 0).await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4();
    let old_op = put_op_json(
        &Uuid::new_v4().to_string(),
        &item.to_string(),
        1,
        &device,
        &[1u8; 8],
    );
    let fresh_op = put_op_json(
        &Uuid::new_v4().to_string(),
        &item.to_string(),
        2,
        &device,
        &[2u8; 8],
    );

    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [old_op, fresh_op]}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 2);

    // Roll the first entry back outside the window
    let stale_received_at = (Utc::now() - chrono::Duration::try_days(31).unwrap())
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    sqlx::query("UPDATE sync_oplog SET received_at = ? WHERE lamport = 1")
        .bind(&stale_received_at)
        .execute(&state.pool)
        .await
        .unwrap();

    // Push again (exercising the cleanup path): re-pushing fresh = duplicates, nothing new
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [fresh_op]}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 0);
    assert_eq!(body["duplicates"], 1);

    // Pull: only the in-window fresh op remains
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/oplog")).await;
    let ops = body["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["lamport"], 2);
    assert!(state
        .metrics
        .render()
        .contains("persona_sync_ops_pruned_total 1"));

    // Cooperative semantics: re-pushing a pruned op rebuilds it idempotently by op_id
    // (a cursor reset + full re-pull loses no drafts)
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [old_op]}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 1);
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/oplog")).await;
    assert_eq!(body["ops"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn oplog_retention_zero_keeps_everything() {
    let (router, state) = setup_with_retention(Some(TOKEN), 0, 0).await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4();
    let op = put_op_json(
        &Uuid::new_v4().to_string(),
        &item.to_string(),
        1,
        &device,
        &[1u8; 8],
    );
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [op]}).to_string(),
        ),
    )
    .await;
    assert_eq!(body["accepted"], 1, "{status}");

    // Roll far back and push to exercise the cleanup path: 0 = no cleanup, the row stays
    sqlx::query("UPDATE sync_oplog SET received_at = '2000-01-01T00:00:00.000Z'")
        .execute(&state.pool)
        .await
        .unwrap();
    let (_, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [put_op_json(
                &Uuid::new_v4().to_string(),
                &item.to_string(),
                2,
                &device,
                &[2u8; 8],
            )]})
            .to_string(),
        ),
    )
    .await;
    assert_eq!(body["accepted"], 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sync_oplog")
            .fetch_one(&state.pool)
            .await
            .unwrap(),
        2
    );
    assert!(state
        .metrics
        .render()
        .contains("persona_sync_ops_pruned_total 0"));
}

/// Per-field validation arms of the oplog (kind boundaries / oversized payload /
/// unknown op verb / malformed rfc3339 timestamp), a malformed JSON body, pull's
/// limit boundaries and bad cursor, and reading a corrupted row whose payload is
/// only partially populated (one of the two columns empty).
#[tokio::test]
async fn oplog_validation_and_pull_error_arms() {
    let (router, state) = crate::test_support::setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4().to_string();

    // One request per bad field: 422 and items pointing at the offending field
    let oversized = b64(&vec![0u8; MAX_PAYLOAD_BYTES + 1]);
    let bad_op = |mutate: &dyn Fn(&mut Value)| {
        let mut op = put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, &[0u8; 4]);
        mutate(&mut op);
        op
    };
    let cases: Vec<(&str, Value)> = vec![
        ("kind", bad_op(&|op| op["kind"] = json!(""))),
        ("kind", bad_op(&|op| op["kind"] = json!("x".repeat(65)))),
        (
            "ciphertext",
            bad_op(&|op| op["payload"]["ciphertext"] = json!(oversized)),
        ),
        ("op", bad_op(&|op| op["op"] = json!("patch"))),
        (
            "timestamp",
            bad_op(&|op| op["timestamp"] = json!("not-a-timestamp")),
        ),
    ];
    for (field, op) in cases {
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": [op]}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["field"] == *field),
            "字段 {field} 未被定位: {body}"
        );
    }

    // Malformed JSON body -> 400 (same rejection convention as the events endpoint)
    let (status, body) = send(
        router.clone(),
        req("POST", "/api/v1/sync/oplog", "not json at all"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "bad_request");

    // Pull limit: both 0 and above PULL_MAX_FETCH are 422
    for limit in ["0", "501"] {
        let (status, body) = send(
            router.clone(),
            get_req(&format!("/api/v1/sync/oplog?limit={limit}")),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["message"], "invalid limit");
    }

    // Pull with a bad cursor -> 422 invalid cursor (same codec as events)
    let (status, body) = send(
        router.clone(),
        get_req("/api/v1/sync/oplog?since=not-a-cursor"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["message"], "invalid cursor");

    // Corrupted row: ciphertext set but wrapped_item_key NULL -> 500 internal
    // (a half-ciphertext row is unusable to clients; it must not be silently
    // dropped or folded into a 4xx)
    sqlx::query(
        "INSERT INTO sync_oplog
            (op_id, item_id, kind, op, lamport, device_id, timestamp,
             ciphertext, wrapped_item_key)
         VALUES (?, ?, 'credential', 'put', 1, ?, NULL, X'01', NULL)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&item)
    .bind(device.to_string())
    .execute(&state.pool)
    .await
    .unwrap();
    let (status, body) = send(router, get_req("/api/v1/sync/oplog")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"]["code"], "internal");
}

/// A retention cleanup failure only warns and never blocks writes (growth governance
/// is not a precondition of relay correctness): a trigger makes retention's DELETE
/// error out, yet push still returns 200 and the op lands in the store.
#[tokio::test]
async fn oplog_retention_delete_failure_does_not_block_push() {
    let (router, state) = crate::test_support::setup_with_retention(Some(TOKEN), 1, 0).await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4().to_string();

    let first = put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, &[1u8; 4]);
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [first]}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    sqlx::query(
        "CREATE TRIGGER block_retention BEFORE DELETE ON sync_oplog
         BEGIN SELECT RAISE(ABORT, 'retention blocked'); END",
    )
    .execute(&state.pool)
    .await
    .unwrap();

    let second = put_op_json(&Uuid::new_v4().to_string(), &item, 2, &device, &[2u8; 4]);
    let (status, body) = send(
        router,
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [second]}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 1, "清理失败不得回滚已写入的 op");
}

#[tokio::test]
async fn oplog_push_pull_round_trip_with_cursor() {
    let router = router().await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4();
    let ops: Vec<Value> = (0..3)
        .map(|i| {
            put_op_json(
                &Uuid::new_v4().to_string(),
                &item.to_string(),
                i + 1,
                &device,
                &[i as u8; 8],
            )
        })
        .collect();
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": ops}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 3);
    assert_eq!(body["duplicates"], 0);

    // First page limit=2 -> 2 entries + next_cursor (pointing at row 2)
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/oplog?limit=2")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ops"].as_array().unwrap().len(), 2);
    let cursor = body["next_cursor"].as_str().unwrap().to_string();

    // Continuing with the since cursor -> 1 entry left; a non-empty page always
    // returns a cursor (pointing at row 3)
    let (status, body) = send(
        router.clone(),
        get_req(&format!("/api/v1/sync/oplog?since={cursor}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rest = body["ops"].as_array().unwrap();
    assert_eq!(rest.len(), 1);
    let last_cursor = body["next_cursor"].as_str().unwrap().to_string();

    // Pulling again from the last row's cursor -> empty page + null cursor
    // (the client loop's stop point)
    let (status, body) = send(
        router.clone(),
        get_req(&format!("/api/v1/sync/oplog?since={last_cursor}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ops"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());

    // Payload b64 round-trip
    let payload = rest[0]["payload"].as_object().unwrap();
    let ciphertext = B64.decode(payload["ciphertext"].as_str().unwrap()).unwrap();
    assert_eq!(ciphertext.len(), 8);
}

#[tokio::test]
async fn oplog_push_is_idempotent_by_op_id() {
    let router = router().await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4().to_string();
    let op = put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, &[9u8; 4]);
    let body_text = json!({"ops": [op.clone()]}).to_string();

    let (_, body) = send(
        router.clone(),
        req("POST", "/api/v1/sync/oplog", &body_text),
    )
    .await;
    assert_eq!(
        (body["accepted"].as_u64(), body["duplicates"].as_u64()),
        (Some(1), Some(0))
    );

    // Re-push the same batch verbatim (network retry): all duplicates, no rows repeated
    let (_, body) = send(
        router.clone(),
        req("POST", "/api/v1/sync/oplog", &body_text),
    )
    .await;
    assert_eq!(
        (body["accepted"].as_u64(), body["duplicates"].as_u64()),
        (Some(0), Some(1))
    );

    let (_, body) = send(router, get_req("/api/v1/sync/oplog")).await;
    assert_eq!(body["ops"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn oplog_rejects_oversized_batch_and_malformed_ops() {
    let router = router().await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4().to_string();

    // 501 entries -> 422
    let flood: Vec<Value> = (0..501)
        .map(|_| put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, &[0u8; 4]))
        .collect();
    let (status, _) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": flood}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Per-entry multi-field errors carry index: [0] a put missing payload,
    // [1] a delete carrying payload
    let bad_ops = json!({"ops": [
        {"op_id": Uuid::new_v4().to_string(), "item_id": item, "kind": "credential",
         "op": "put", "lamport": 1, "device_id": device.to_string(),
         "timestamp": null, "payload": null},
        {"op_id": Uuid::new_v4().to_string(), "item_id": item, "kind": "credential",
         "op": "delete", "lamport": 2, "device_id": device.to_string(),
         "timestamp": null,
         "payload": {"ciphertext": b64(&[1u8; 4]), "wrapped_item_key": b64(&[1u8; 32])}},
    ]});
    let (status, body) = send(
        router.clone(),
        req("POST", "/api/v1/sync/oplog", &bad_ops.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let items = body["error"]["items"].as_array().unwrap();
    assert!(items
        .iter()
        .any(|i| i["index"] == 0 && i["field"] == "payload"));
    assert!(items
        .iter()
        .any(|i| i["index"] == 1 && i["field"] == "payload"));

    // A non-UUID op_id -> per-entry 422
    let bad_uuid = json!({"ops": [
        {"op_id": "not-a-uuid", "item_id": item, "kind": "credential",
         "op": "put", "lamport": 1, "device_id": device.to_string(),
         "timestamp": null,
         "payload": {"ciphertext": b64(&[1u8; 4]), "wrapped_item_key": b64(&[1u8; 32])}}
    ]});
    let (status, body) = send(
        router,
        req("POST", "/api/v1/sync/oplog", &bad_uuid.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

/// Direct assertion that the server is a pure relay: a "ciphertext" containing a
/// plaintext magic value is pushed up, and ops with lamport above i64::MAX are
/// rejected (audit round 2 #6): the server's lamport column is i64; without the
/// check, `as i64` wraps a malicious ~u64::MAX value into a negative on insert,
/// and the client reads the inflated value back with `as u64` — pinning the LWW
/// total order and deadlocking the local clock's MAX() anti-regression guard.
#[tokio::test]
async fn oplog_rejects_lamport_above_i64_max() {
    let router = router().await;
    let device = register_device(&router, "poisoner").await;
    let item = Uuid::new_v4().to_string();

    for lamport in [(i64::MAX as u64) + 1, u64::MAX] {
        let ops = json!({"ops": [put_op_json(
            &Uuid::new_v4().to_string(),
            &item,
            lamport,
            &device,
            &[7u8; 4],
        )]});
        let (status, body) = send(
            router.clone(),
            req("POST", "/api/v1/sync/oplog", &ops.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let items = body["error"]["items"].as_array().unwrap();
        assert!(
            items.iter().any(|i| i["field"] == "lamport"),
            "lamport must be named: {body}"
        );
    }

    // The boundary value i64::MAX is allowed through (the storage column is i64).
    let ops = json!({"ops": [put_op_json(
        &Uuid::new_v4().to_string(),
        &item,
        i64::MAX as u64,
        &device,
        &[7u8; 4],
    )]});
    let (status, body) = send(router, req("POST", "/api/v1/sync/oplog", &ops.to_string())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 1);
}

/// In the database row the magic value appears only in the ciphertext column — the
/// server has no (and cannot have any) plaintext copy column. The real plaintext
/// leakage surface is empty.
#[tokio::test]
async fn server_stores_only_ciphertext() {
    let (router, app_state) = crate::test_support::setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;
    let magic = b"TOPSECRET-PLAINTEXT-MUST-NOT-LEAK";
    let item = Uuid::new_v4().to_string();
    let op = put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, magic);
    let (status, body) = send(
        router,
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [op]}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let rows = sqlx::query(
        "SELECT op_id, item_id, kind, op, lamport, device_id, timestamp, ciphertext, wrapped_item_key FROM sync_oplog",
    )
    .fetch_all(&app_state.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    let stored: Vec<u8> = row.get("ciphertext");
    assert_eq!(stored, magic); // ciphertext column == client-uploaded bytes (relay fidelity)
                               // no other column contains the magic value
    for column in ["op_id", "item_id", "kind", "device_id"] {
        let text: String = row.get(column);
        assert!(
            !text.as_bytes().windows(magic.len()).any(|w| w == magic),
            "plaintext leaked in column {column}"
        );
    }
    assert!(row.get::<Option<String>, _>("timestamp").is_some());
}

/// The server does not arbitrate conflicts (DR-4): two genuinely conflicting ops for
/// the same item with the same lamport but different devices are stored verbatim as a
/// pair and returned verbatim as a pair on pull — adjudication belongs entirely to
/// the client.
#[tokio::test]
async fn server_does_not_arbitrate_conflicts() {
    let router = router().await;
    let device_a = register_device(&router, "device-a").await;
    let device_b = register_device(&router, "device-b").await;
    let item = Uuid::new_v4().to_string();
    let ops = vec![
        put_op_json(&Uuid::new_v4().to_string(), &item, 7, &device_a, &[1u8; 4]),
        put_op_json(&Uuid::new_v4().to_string(), &item, 7, &device_b, &[2u8; 4]),
    ];
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": ops}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 2);

    let (_, body) = send(router, get_req("/api/v1/sync/oplog")).await;
    let pulled = body["ops"].as_array().unwrap();
    assert_eq!(pulled.len(), 2);
    let lamports: Vec<u64> = pulled
        .iter()
        .map(|op| op["lamport"].as_u64().unwrap())
        .collect();
    assert_eq!(lamports, vec![7, 7]);
    let devices: Vec<&str> = pulled
        .iter()
        .map(|op| op["device_id"].as_str().unwrap())
        .collect();
    assert!(devices.contains(&device_a.to_string().as_str()));
    assert!(devices.contains(&device_b.to_string().as_str()));
}

#[tokio::test]
async fn unauthenticated_sync_request_is_rejected() {
    let router = router().await;
    let (status, _) = send(
        router,
        request("GET", "/api/v1/sync/devices", None, None, ""),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
