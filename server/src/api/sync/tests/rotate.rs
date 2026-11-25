use super::*;

// ---- Concurrent rotation mutual exclusion (§11 open question 2: optimistic epoch locking) ----

#[tokio::test]
async fn rotate_begin_cas_mutex_and_epoch_exposure() {
    let router = router().await;

    // The initial epoch = 0, and the group-keys response carries the baseline
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(body["epoch"], 0);

    // CAS hits: 0 -> 1
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

    // Replaying a stale baseline -> 409 fail-closed (the latecomer aborts cleanly)
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

    // After re-reading the new baseline it can compete again (the retry path): 1 -> 2
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

    // group-keys reflects the latest generation
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(body["epoch"], 2);
}

/// Two devices rotating concurrently: the first one grabs the exclusive window, while the
/// second begins with a stale baseline and gets ConcurrentConflict (mapped to 409 on the
/// core side); after re-reading the new baseline the retry can complete.
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

    // A bootstraps the group (epoch still 0)
    let dev_a = DeviceIdentity::generate("racer-a").unwrap();
    let id_a = admin_a
        .register_device("racer-a", dev_a.key_pair.public_bytes())
        .await
        .unwrap();
    assert!(admin_a
        .bootstrap_group_if_empty(id_a, dev_a.key_pair.public_bytes())
        .await
        .unwrap());

    // Both devices read the same baseline
    let (_, baseline_b) = admin_b.group_keys_with_epoch().await.unwrap();
    assert_eq!(baseline_b, 0);

    // A grabs the mutex (0 -> 1); B begins with the stale baseline -> ConcurrentConflict
    let won = admin_a.begin_group_rotation(baseline_b).await.unwrap();
    assert_eq!(won, 1);
    let err = admin_b.begin_group_rotation(baseline_b).await.unwrap_err();
    assert!(
        err.downcast_ref::<persona_core::PersonaError>()
            .is_some_and(|e| matches!(e, persona_core::PersonaError::ConcurrentConflict(_))),
        "unexpected error: {err}"
    );

    // B re-reads the new baseline -> the retry succeeds (1 -> 2)
    let (_, fresh) = admin_b.group_keys_with_epoch().await.unwrap();
    assert_eq!(fresh, 1);
    assert_eq!(admin_b.begin_group_rotation(fresh).await.unwrap(), 2);

    task.abort();
}
