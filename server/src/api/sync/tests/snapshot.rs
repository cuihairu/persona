use super::*;

#[tokio::test]
async fn snapshot_put_get_roundtrip_and_prunes_covered_ops() {
    let (router, state) = setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;

    // 尚未上传：404 absent（空库 bootstrap 照旧从头拉，语义合流设计稿）
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "absent");

    // 三条 op（seq 1..3）后打包 seq=2：覆盖区间（≤2）在事务内被压缩
    let item = Uuid::new_v4();
    for lamport in 1..=3u64 {
        let op = put_op_json(
            &Uuid::new_v4().to_string(),
            &item.to_string(),
            lamport,
            &device,
            &[lamport as u8; 8],
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
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let total: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM sync_oplog")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(total, 3);

    let ciphertext = B64.encode(b"sealed-library-snapshot-bytes");
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/snapshot",
            &put_snapshot_json(2, &device, &ciphertext).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["seq"], 2);
    assert_eq!(body["pruned_ops"], 2, "seq ≤ 2 的两条被压缩");

    // 只留 seq > S 的 ops（与 retention 同向的缩水，宽容口径不变）
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM sync_oplog")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);

    // GET 回读字节一致——服务器盲存不解密（零知识面）
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["seq"], 2);
    assert_eq!(body["ciphertext"], ciphertext);
    assert_eq!(body["device_id"], device.to_string());

    // 重传（更大 seq 覆盖）：单快照 upsert，旧行不堆积、区间继续压缩
    let next = B64.encode(b"v2-snapshot");
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/snapshot",
            &put_snapshot_json(7, &device, &next).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["seq"], 7);
    assert_eq!(body["pruned_ops"], 1, "seq 3 也被新快照覆盖");
    let snapshots: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM sync_snapshots")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(snapshots, 1, "只留最新快照");
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ciphertext"], next);
}

#[tokio::test]
async fn snapshot_rejects_negative_seq_bad_base64_and_empty_bytes() {
    let (router, _state) = setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;

    for (payload, field) in [
        (put_snapshot_json(-1, &device, &B64.encode(b"x")), "seq"),
        (put_snapshot_json(1, &device, "not base64!!"), "ciphertext"),
        (
            put_snapshot_json(1, &device, &B64.encode(b"")),
            "ciphertext",
        ),
    ] {
        let (status, body) = send(
            router.clone(),
            req("PUT", "/api/v1/sync/snapshot", &payload.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["items"][0]["field"], field, "{body}");
    }
    // 空白 device_id（打包设备自报，仅展示但不许空串——观测字段要有主）
    let mut blank = put_snapshot_json(1, &device, &B64.encode(b"x"));
    blank["device_id"] = json!("   ");
    let (status, body) = send(
        router.clone(),
        req("PUT", "/api/v1/sync/snapshot", &blank.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["items"][0]["field"], "device_id");

    // 一个也没写进去
    let (status, _) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// 水位单调闸（E2EE_SYNC_DESIGN §5 测试锚点「并发 PUT 快照，head 单调」）：
// 落后端 PUT 被拒——否则「快照回退旧 seq + 覆盖区间 ops 已删」= bootstrap
// 数据洞；同 seq 重打包幂等放行；409 不附带任何 oplog 压缩。
#[tokio::test]
async fn snapshot_stale_put_rejected_and_head_monotonic() {
    let (router, state) = setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;

    // 三条 op（seq 1..3），A 端打包 seq=2
    let item = Uuid::new_v4();
    for lamport in 1..=3u64 {
        let op = put_op_json(
            &Uuid::new_v4().to_string(),
            &item.to_string(),
            lamport,
            &device,
            &[lamport as u8; 8],
        );
        let (status, _) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": [op]}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let v1 = B64.encode(b"snapshot-at-seq-2");
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/snapshot",
            &put_snapshot_json(2, &device, &v1).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pruned_ops"], 2);

    // 落后端（水位 1 < 2）PUT → 409，快照与 oplog 都原样
    let stale = B64.encode(b"stale-snapshot-at-seq-1");
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/snapshot",
            &put_snapshot_json(1, &device, &stale).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "conflict");
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(body["seq"], 2);
    assert_eq!(body["ciphertext"], v1, "落后上传不得覆盖");
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM sync_oplog")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1, "409 路径不附带压缩");

    // 同 seq 重打包幂等放行（覆盖同水位内容，head 不动）
    let v1b = B64.encode(b"repackaged-at-seq-2");
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/snapshot",
            &put_snapshot_json(2, &device, &v1b).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pruned_ops"], 0);
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(body["seq"], 2);
    assert_eq!(body["ciphertext"], v1b);
}

// 真·并发两路 PUT：无论到达次序如何，最终 head = max(seqs) 且字节归属
// 高水位者——空表时低者可先立、高者随后覆盖；高者先立时低者 409。
#[tokio::test]
async fn snapshot_concurrent_puts_head_monotonic() {
    let (router, _state) = setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;

    let hi = B64.encode(b"snapshot-at-seq-10");
    let lo = B64.encode(b"snapshot-at-seq-8");
    let put = |seq: i64, ciphertext: String| {
        let router = router.clone();
        async move {
            send(
                router,
                req(
                    "PUT",
                    "/api/v1/sync/snapshot",
                    &put_snapshot_json(seq, &device, &ciphertext).to_string(),
                ),
            )
            .await
        }
    };
    let ((hi_status, _hi_body), (lo_status, lo_body)) =
        tokio::join!(put(10, hi.clone()), put(8, lo.clone()));

    // 高水位必在库：低者要么被拒（高者先立），要么先立后被覆盖
    assert!(
        (hi_status == StatusCode::OK && lo_status == StatusCode::OK)
            || (hi_status == StatusCode::OK && lo_status == StatusCode::CONFLICT),
        "hi={hi_status} lo={lo_status} {lo_body}"
    );
    let (_, body) = send(router, get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(body["seq"], 10, "head 单调：终值=max(seqs)");
    assert_eq!(body["ciphertext"], hi);
}
