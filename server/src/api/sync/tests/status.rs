use super::*;

#[tokio::test]
async fn status_reports_group_head_seq() {
    let router = router().await;

    // 空组：head_seq = 0（不泄存在性之外的任何东西，纯元数据）
    let (status, body) = send(router.clone(), get_req("/api/v1/sync/status")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["head_seq"], 0);

    // 推 3 条后 head_seq = 3；重复 op（幂等拒收）不涨水位
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

// 压缩后组版本号不回退（§5.5「单调版本号」）：快照点即已覆盖的事实位置，
// head = max(oplog max, snapshot seq)——oplog 清空后仍报快照水位。
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

    // oplog 已清空（压缩生效），但组版本号停在快照点不回退
    let (status, body) = send(router, get_req("/api/v1/sync/status")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["head_seq"], 3);
}
