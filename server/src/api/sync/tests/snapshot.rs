use super::*;

#[tokio::test]
async fn snapshot_put_get_roundtrip_and_prunes_covered_ops() {
    let (router, state) = setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;

    // Not uploaded yet: 404 absent (an empty store bootstraps by pulling from the start, as in the design)
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "absent");

    // After three ops (seq 1..3), package at seq=2: the covered range (<=2) is compacted inside the transaction
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

    // Only the ops with seq > S remain (a shrink in the same direction as retention; the lenient invariant is unchanged)
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM sync_oplog")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);

    // GET reads back identical bytes — the server stores them blind and never decrypts (zero-knowledge surface)
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["seq"], 2);
    assert_eq!(body["ciphertext"], ciphertext);
    assert_eq!(body["device_id"], device.to_string());

    // Re-upload (a larger seq overwrites): single-snapshot upsert, no old rows accumulate and the range keeps compacting
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
    // Blank device_id (self-reported by the packaging device, display-only, but a blank string is
    // disallowed — an observation field must have an owner)
    let mut blank = put_snapshot_json(1, &device, &B64.encode(b"x"));
    blank["device_id"] = json!("   ");
    let (status, body) = send(
        router.clone(),
        req("PUT", "/api/v1/sync/snapshot", &blank.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["items"][0]["field"], "device_id");

    // Not a single one was written
    let (status, _) = send(router.clone(), get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// Water-level monotonic gate (E2EE_SYNC_DESIGN §5 test anchor "concurrent PUT snapshots, monotonic head"):
// a lagging end's PUT is rejected — otherwise "the snapshot regresses to the older seq + the ops in the
// covered range are already deleted" = a bootstrap data hole; re-packaging the same seq is allowed
// idempotently; a 409 carries no oplog compaction with it.
#[tokio::test]
async fn snapshot_stale_put_rejected_and_head_monotonic() {
    let (router, state) = setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;

    // Three ops (seq 1..3), and end A packages at seq=2
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

    // A lagging end (water level 1 < 2) PUTs -> 409, and the snapshot and oplog stay untouched
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

    // Re-packaging the same seq passes idempotently (overwriting same-water-level content; head is unmoved)
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

// Genuinely concurrent PUTs on two paths: whatever the arrival order, the final head = max(seqs)
// and the bytes belong to the higher water level — on an empty table the lower one can land first
// and the higher one overwrites it afterwards; if the higher one lands first, the lower one gets 409.
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

    // The high water level must be in the store: the lower one is either rejected (the higher one landed
    // first) or lands first and gets overwritten afterwards
    assert!(
        (hi_status == StatusCode::OK && lo_status == StatusCode::OK)
            || (hi_status == StatusCode::OK && lo_status == StatusCode::CONFLICT),
        "hi={hi_status} lo={lo_status} {lo_body}"
    );
    let (_, body) = send(router, get_req("/api/v1/sync/snapshot")).await;
    assert_eq!(body["seq"], 10, "head 单调：终值=max(seqs)");
    assert_eq!(body["ciphertext"], hi);
}
