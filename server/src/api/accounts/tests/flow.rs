use super::*;

#[tokio::test]
async fn account_register_login_flow() {
    let router = router().await;

    // Register account
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            "/api/v1/accounts/register",
            None,
            Some("application/json"),
            &json!({"username": "alice@example.com", "display_name": "Alice"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let account_id = body["account_id"].as_str().unwrap().to_string();

    // Duplicate registration should fail
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            "/api/v1/accounts/register",
            None,
            Some("application/json"),
            &json!({"username": "alice@example.com"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Generate recovery codes
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/recovery-codes"),
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["codes"].as_array().unwrap().len(), 8);

    // Verify a recovery code
    let code = body["codes"][0].as_str().unwrap();
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/recovery-codes/verify"),
            &json!({"code": code}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], true);

    // Same code should not work again
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/recovery-codes/verify"),
            &json!({"code": code}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], false);
}

#[tokio::test]
async fn account_device_management() {
    let router = router().await;

    // Register account
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            "/api/v1/accounts/register",
            None,
            Some("application/json"),
            &json!({"username": "bob@example.com"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let account_id = body["account_id"].as_str().unwrap().to_string();

    // Register a sync device first
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/devices",
            &json!({"device_name": "laptop", "public_key": b64(&[7u8; 32])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let sync_device_id = body["device_id"].as_str().unwrap().to_string();

    // Authorize device for account
    let (status, body) = send(
        router.clone(),
        req("POST", &format!("/api/v1/accounts/{account_id}/devices"),
            &json!({"device_id": sync_device_id, "device_name": "laptop", "public_key": b64(&[7u8; 32])}).to_string()),
    ).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let _auth_device_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["status"], "authorized");

    // List devices
    let (status, body) = send(
        router.clone(),
        get_req(&format!("/api/v1/accounts/{account_id}/devices")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["devices"].as_array().unwrap().len(), 1);
    assert_eq!(body["devices"][0]["status"], "authorized");

    // Revoke device
    let (status, _) = send(
        router.clone(),
        request(
            "DELETE",
            &format!("/api/v1/accounts/{account_id}/devices/{sync_device_id}"),
            Some(&format!("Bearer {TOKEN}")),
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify revoked
    let (status, body) = send(
        router.clone(),
        get_req(&format!("/api/v1/accounts/{account_id}/devices")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["devices"].as_array().unwrap()[0]["status"], "revoked");
}
