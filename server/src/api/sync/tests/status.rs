use super::*;

#[tokio::test]
async fn status_reports_group_head_seq() {
    let router = router().await;

    // Empty group: head_seq = 0 (leaking nothing beyond existence; pure metadata)
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/status")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["head_seq"], 0);

    // After pushing 3 entries head_seq = 3; a duplicate op (rejected idempotently) does not raise the water level
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

    let (status, body) = send(router, get_req("/api/v1/sync/status")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["head_seq"], 3);
}

// The group version must not regress after compaction (§5.5 "monotonic version"): the snapshot point is
// already the covered position of the facts, and head = max(oplog max, snapshot seq) — once the oplog is
// emptied it still reports the snapshot's water level.
#[tokio::test]
async fn status_head_stays_monotonic_across_snapshot_compression() {
    let (router, _state) = setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;
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
    let (status, _) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/snapshot",
            &put_snapshot_json(3, &device, &B64.encode(b"snapshot-at-3")).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The oplog has been emptied (compaction took effect), but the group version stays at the snapshot point and does not regress
    let (status, body) = send(router, get_req("/api/v1/sync/status")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["head_seq"], 3);
}
