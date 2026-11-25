use super::*;

#[tokio::test]
async fn device_register_list_delete_round_trip() {
    let router = router().await;
    let id = register_device(&router, "laptop").await;

    let (status, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["devices"].as_array().unwrap().len(), 1);
    assert_eq!(body["devices"][0]["device_name"], "laptop");
    // Public key b64 round-trip
    let key = B64
        .decode(body["devices"][0]["public_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(key, vec![7u8; 32]);

    let (status, _) = send(
        router.clone(),
        req("DELETE", &format!("/api/v1/sync/devices/{id}"), ""),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(body["devices"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn device_remark_self_service_round_trip() {
    let router = router().await;
    // With a single-token config the token's owning device name is "default"
    // (AuthTokens::single); the remark endpoint locates the row by the token's
    // owning name — the registration name must match.
    register_device(&router, "default").await;

    // Default empty remark
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(body["devices"][0]["remark"], "");

    // Set -> echoed back -> reflected in the list
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/devices/remark",
            &json!({ "remark": "我的笔记本" }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_name"], "default");
    assert_eq!(body["remark"], "我的笔记本");

    let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(body["devices"][0]["remark"], "我的笔记本");

    // Blank string = clear
    let (status, _) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/devices/remark",
            &json!({ "remark": "  " }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(body["devices"][0]["remark"], "");
}

#[tokio::test]
async fn device_remark_is_locked_to_own_device() {
    let router = two_device_router().await;
    register_device_with_token(&router, "laptop", "tok-laptop").await;
    register_device_with_token(&router, "phone", "tok-phone").await;

    // Each writes only its own
    let (status, _) = send(
        router.clone(),
        req_with_token(
            "PUT",
            "/api/v1/sync/devices/remark",
            "tok-laptop",
            &json!({ "remark": "主力机" }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        router.clone(),
        req_with_token(
            "PUT",
            "/api/v1/sync/devices/remark",
            "tok-phone",
            &json!({ "remark": "备用机" }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // With the laptop token, re-read the list: its own remark is there; phone's remark
    // is not laptop's to manage and was left untouched
    let (_, body) = send(
        router.clone(),
        request(
            "GET",
            "/api/v1/sync/devices",
            Some("Bearer tok-laptop"),
            None,
            "",
        ),
    )
    .await;
    let rows = body["devices"].as_array().unwrap();
    let laptop = rows.iter().find(|d| d["device_name"] == "laptop").unwrap();
    let phone = rows.iter().find(|d| d["device_name"] == "phone").unwrap();
    assert_eq!(laptop["remark"], "主力机");
    assert_eq!(phone["remark"], "备用机");
}

#[tokio::test]
async fn device_remark_rejects_over_limit_and_unregistered_device() {
    let router = router().await;

    // > 128 bytes -> 422 validation (the uniform field-validation shape)
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/devices/remark",
            &json!({ "remark": "长".repeat(129) }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], "validation");

    // The token's owning device name is not registered -> 404 absent (there is no
    // cross-device path in the API shape at all)
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/devices/remark",
            &json!({ "remark": "孤儿" }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn device_registration_rejects_duplicate_name_and_bad_key() {
    let router = router().await;
    register_device(&router, "phone").await;
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/devices",
            &json!({"device_name": "phone", "public_key": b64(&[7u8; 32])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Both a wrong-length public key (31B) and malformed b64 are 422
    for bad in [b64(&[7u8; 31]), "!!!not-base64!!!".to_string()] {
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/devices",
                &json!({"device_name": "other", "public_key": bad}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }
}

#[tokio::test]
async fn group_key_envelope_round_trip_and_fail_closed() {
    let router = router().await;
    let device = register_device(&router, "laptop").await;
    let envelope_bytes: Vec<u8> = (0..80).map(|i| i as u8).collect();

    // Attach an envelope to an unregistered device -> 422 (the server-side half of fail-closed)
    let ghost = Uuid::new_v4();
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": ghost.to_string(), "envelope": b64(&envelope_bytes)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Normal upload -> GET returns it verbatim
    let (status, _) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": device.to_string(), "envelope": b64(&envelope_bytes)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["device_id"], device.to_string());
    assert_eq!(
        B64.decode(keys[0]["envelope"].as_str().unwrap()).unwrap(),
        envelope_bytes
    );
    assert_eq!(keys[0]["sealed_by"], "default"); // AuthTokens::single's device name

    // An envelope whose length is not 80B is rejected
    let (status, _) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": device.to_string(), "envelope": b64(&[0u8; 79])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Revoke the device -> its envelope disappears with it
    send(
        router.clone(),
        req("DELETE", &format!("/api/v1/sync/devices/{device}"), ""),
    )
    .await;
    let (_, body) = send(router, get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(body["keys"].as_array().unwrap().len(), 0);
}

/// Validation/failure arms of the device registration and envelope endpoints:
/// device_name boundaries (blank after trim, and 129 bytes), the idempotent 204 for
/// DELETE with a malformed UUID, put_group_key's device_id / envelope base64
/// validation, and fail-closed 500s when the envelope table or the epoch table is
/// corrupted (including a delete cascade failing midway — the idempotent-retry
/// design does not disguise a failure as a 204).
#[tokio::test]
async fn device_and_group_key_error_arms() {
    let (router, state) = crate::test_support::setup(Some(TOKEN)).await;

    // device_name: blank after trim / 129 bytes -> 422 (the 1..=128 byte boundary)
    for name in ["   ".to_string(), "x".repeat(129)] {
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/devices",
                &json!({"device_name": name, "public_key": b64(&[7u8; 32])}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["code"], "validation");
        assert!(body["error"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["field"] == "device_name"));
    }

    // DELETE with a malformed UUID: handled as the idempotent "absent" semantics -> 204
    let (status, _) = send(
        router.clone(),
        req("DELETE", "/api/v1/sync/devices/not-a-uuid", ""),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let device = register_device(&router, "laptop").await;
    let envelope = b64(&(0..80u8).collect::<Vec<u8>>());

    // put_group_key: non-UUID device_id / malformed envelope base64 -> 422
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": "not-a-uuid", "envelope": envelope}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": device.to_string(), "envelope": "!!!not-base64!!!"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // The envelope table is dropped: an enrolled device's upsert -> 500 internal
    // (sqlx details are not leaked)
    sqlx::query("DROP TABLE sync_group_keys")
        .execute(&state.pool)
        .await
        .unwrap();
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": device.to_string(), "envelope": envelope}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

    // The delete cascade fails midway (the name lookup succeeds, the envelope delete
    // errors) -> 500; the whole thing is retryable and must not lie about success.
    let (status, _) = send(
        router.clone(),
        req("DELETE", &format!("/api/v1/sync/devices/{device}"), ""),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // The single-row epoch table is corrupted: group-keys' epoch read and
    // rotate-begin's transaction commit both fail closed with 500
    sqlx::query("DROP TABLE sync_group_epoch")
        .execute(&state.pool)
        .await
        .unwrap();
    let (status, _) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (status, _) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/group-key/rotate-begin",
            &json!({"if_epoch": 0}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// After the connection pool is closed (equivalent to any underlying DB failure),
/// every sync read/write endpoint uniformly surfaces 500 internal: register's
/// non-UNIQUE insert failure, list_devices, delete's name lookup, group-keys row
/// reads, oplog push persistence and pull queries — none of them may fold DB
/// flakiness into a 4xx and mislead clients.
#[tokio::test]
async fn db_failure_surfaces_internal_across_sync_endpoints() {
    let (router, state) = crate::test_support::setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4().to_string();
    state.pool.close().await;

    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/devices",
            &json!({"device_name": "phone", "public_key": b64(&[7u8; 32])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"]["code"], "internal");

    let (status, _) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let (status, _) = send(
        router.clone(),
        req("DELETE", &format!("/api/v1/sync/devices/{device}"), ""),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let (status, _) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // A valid op that passes all validation: persistence fails -> 500 (not a 4xx)
    let op = put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, &[0u8; 4]);
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [op]}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

    let (status, _) = send(router, get_req("/api/v1/sync/oplog")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
