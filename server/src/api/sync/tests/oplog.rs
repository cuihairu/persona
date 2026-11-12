use super::*;

// ---- server 侧 oplog 保留策略（§11 开放问题 3 收口）----

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

    // 第一条回拨到窗口外
    let stale_received_at = (Utc::now() - chrono::Duration::try_days(31).unwrap())
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    sqlx::query("UPDATE sync_oplog SET received_at = ? WHERE lamport = 1")
        .bind(&stale_received_at)
        .execute(&state.pool)
        .await
        .unwrap();

    // 再 push（触发清理路径）：fresh 重推 = duplicates，不新增
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

    // pull 只剩窗口内的 fresh
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/oplog")).await;
    let ops = body["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["lamport"], 2);
    assert!(state
        .metrics
        .render()
        .contains("persona_sync_ops_pruned_total 1"));

    // 协同语义：被清的 op 重推 → op_id 幂等重建（游标重置重拉不丢底稿）
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

    // 回拨到很远再 push 触发清理路径：0 = 不清理，行仍在
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

/// oplog 逐字段校验臂（kind 边界 / 超大 payload / 未知 op 动词 /
/// 坏 rfc3339 时间戳）、坏 JSON 正文、pull 的 limit 边界与坏游标、
/// 以及「payload 两列部分为空」的损坏行读取。
#[tokio::test]
async fn oplog_validation_and_pull_error_arms() {
    let (router, state) = crate::test_support::setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4().to_string();

    // 每个坏字段单独一条请求：422 且 items 指向对应字段
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

    // 坏 JSON 正文 → 400（沿 events 端点的 rejection 口径）
    let (status, body) = send(
        router.clone(),
        req("POST", "/api/v1/sync/oplog", "not json at all"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "bad_request");

    // pull limit：0 与超 PULL_MAX_FETCH 都 422
    for limit in ["0", "501"] {
        let (status, body) = send(
            router.clone(),
            get_req(&format!("/api/v1/sync/oplog?limit={limit}")),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["message"], "invalid limit");
    }

    // pull 坏游标 → 422 invalid cursor（与 events 同一编解码口径）
    let (status, body) = send(
        router.clone(),
        get_req("/api/v1/sync/oplog?since=not-a-cursor"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["message"], "invalid cursor");

    // 损坏行：ciphertext 有值而 wrapped_item_key 为 NULL → 500 internal
    // （半行密文对客户端不可用，不能静默丢弃或折成 4xx）
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

/// 保留策略清理失败仅告警不打断写入（增长治理不是中继正确性的前置
/// 条件）：触发器让 retention 的 DELETE 报错，push 仍 200 且 op 落库。
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

    // 第一页 limit=2 → 2 条 + next_cursor（指向第 2 行）
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/oplog?limit=2")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ops"].as_array().unwrap().len(), 2);
    let cursor = body["next_cursor"].as_str().unwrap().to_string();

    // since 游标续拉 → 剩 1 条；非空页恒返回游标（指向第 3 行）
    let (status, body) = send(
        router.clone(),
        get_req(&format!("/api/v1/sync/oplog?since={cursor}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rest = body["ops"].as_array().unwrap();
    assert_eq!(rest.len(), 1);
    let last_cursor = body["next_cursor"].as_str().unwrap().to_string();

    // 从最后一行游标再拉 → 空页 + null 游标（客户端循环的停点）
    let (status, body) = send(
        router.clone(),
        get_req(&format!("/api/v1/sync/oplog?since={last_cursor}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ops"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());

    // 载荷 b64 round-trip
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

    // 同批原样重推（网络重试）：全量 duplicates，库不重复
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

    // 501 条 → 422
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

    // 单条多字段错误带 index：[0] 缺 payload 的 put、[1] delete 带 payload
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

    // 非 UUID 的 op_id → 逐条 422
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

/// 服务器 = 纯中继的直接断言：给一个含明文魔数的「密文」push 上去，
/// lamport 超过 i64::MAX 的 op 拒收（audit 批2 #6）：服务器 lamport 列是
/// i64，无校验时 `as i64` 把 ≈u64::MAX 的恶意值回绕成负数入库，客户端
/// `as u64` 读回膨胀值——LWW 全序被钉死、本地时钟 MAX() 防回退卡死。
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

    // 边界值 i64::MAX 合法放行（存储列就是 i64）。
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

/// 数据库行里该魔数只出现在 ciphertext 列——服务器没有（也不可能有）
/// 任何明文副本列。真正的明文泄露面为空。
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
    assert_eq!(stored, magic); // 密文列 == 客户端上传字节（中继保真）
                               // 其余任何列都不含该魔数
    for column in ["op_id", "item_id", "kind", "device_id"] {
        let text: String = row.get(column);
        assert!(
            !text.as_bytes().windows(magic.len()).any(|w| w == magic),
            "plaintext leaked in column {column}"
        );
    }
    assert!(row.get::<Option<String>, _>("timestamp").is_some());
}

/// 服务器不做胜负判定（DR-4）：同 item 同 lamport 异 device 的两条
/// 真冲突 op 原样双存、pull 原样双回——裁决权完全在客户端。
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
