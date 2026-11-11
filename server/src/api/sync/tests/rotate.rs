use super::*;

// ---- 并发轮换互斥（§11 开放问题 2：epoch 乐观锁）----

#[tokio::test]
async fn rotate_begin_cas_mutex_and_epoch_exposure() {
    let router = router().await;

    // 初始 epoch = 0，group-keys 响应携带基线
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(body["epoch"], 0);

    // CAS 命中：0 → 1
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/group-key/rotate-begin",
            &json!({"if_epoch": 0}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["epoch"], 1);

    // 陈旧基线重放 → 409 fail-closed（后到者干净中止）
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/group-key/rotate-begin",
            &json!({"if_epoch": 0}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // 重读新基线后可再抢（重试路径）：1 → 2
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/group-key/rotate-begin",
            &json!({"if_epoch": 1}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["epoch"], 2);

    // group-keys 反映最新代数
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(body["epoch"], 2);
}

/// 两台设备并发轮换：先到者抢到互斥窗口，后到者拿陈旧基线 begin 得
/// ConcurrentConflict（core 侧 409 映射）；重读新基线后可完成重试。
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_rotation_second_device_fails_closed() {
    use persona_core::sync::device::DeviceIdentity;
    use persona_core::sync::remote::SyncAdminApi;

    const TOKEN: &str = "sync-rotate-race-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");
    let admin_a = SyncAdminApi::new(&base, TOKEN).unwrap();
    let admin_b = SyncAdminApi::new(&base, TOKEN).unwrap();

    // A 自举建组（epoch 仍 0）
    let dev_a = DeviceIdentity::generate("racer-a").unwrap();
    let id_a = admin_a
        .register_device("racer-a", dev_a.key_pair.public_bytes())
        .await
        .unwrap();
    assert!(admin_a
        .bootstrap_group_if_empty(id_a, dev_a.key_pair.public_bytes())
        .await
        .unwrap());

    // 两台各自读到同一基线
    let (_, baseline_b) = admin_b.group_keys_with_epoch().await.unwrap();
    assert_eq!(baseline_b, 0);

    // A 抢到互斥（0 → 1）；B 拿陈旧基线 begin → ConcurrentConflict
    let won = admin_a.begin_group_rotation(baseline_b).await.unwrap();
    assert_eq!(won, 1);
    let err = admin_b.begin_group_rotation(baseline_b).await.unwrap_err();
    assert!(
        err.downcast_ref::<persona_core::PersonaError>()
            .is_some_and(|e| matches!(e, persona_core::PersonaError::ConcurrentConflict(_))),
        "unexpected error: {err}"
    );

    // B 重读新基线 → 重试成功（1 → 2）
    let (_, fresh) = admin_b.group_keys_with_epoch().await.unwrap();
    assert_eq!(fresh, 1);
    assert_eq!(admin_b.begin_group_rotation(fresh).await.unwrap(), 2);

    task.abort();
}
