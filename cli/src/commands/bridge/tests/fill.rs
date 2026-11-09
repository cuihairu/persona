use super::*;

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_fill_totp_copy_and_gesture_paths() {
    use persona_core::models::credential::{CredentialData, PasswordCredentialData, SecurityLevel};

    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

    // Seed a password credential bound to example.com.
    let cred_id: uuid::Uuid;
    {
        let db = open_db(&db_path).await.unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        assert_eq!(
            service.authenticate_user(PASSWORD).await.unwrap(),
            persona_core::auth::authentication::AuthResult::Success
        );
        let mut cred = service
            .create_credential(
                identity_id,
                "Example login".to_string(),
                persona_core::models::credential::CredentialType::Password,
                SecurityLevel::High,
                &CredentialData::Password(PasswordCredentialData {
                    password: "hunter2".to_string(),
                    email: Some("alice@example.com".to_string()),
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();
        cred.username = Some("alice@example.com".to_string());
        cred.url = Some("https://example.com/login".to_string());
        // Persist the URL/username hints through the repository.
        use persona_core::storage::CredentialRepository;
        use persona_core::Repository;
        let db = open_db(&db_path).await.unwrap();
        CredentialRepository::new(db).update(&cred).await.unwrap();
        cred_id = cred.id;
    }

    // status now reports the active identity.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("status", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert!(resp.ok, "status must succeed: {:?}", resp.error);

    // get_suggestions returns an item for example.com.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_suggestions",
            serde_json::json!({ "origin": "https://example.com" }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "suggestions must succeed: {:?}", resp.error);

    // request_fill without a user gesture is rejected.
    let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({ "origin": "https://example.com", "item_id": uuid::Uuid::new_v4().to_string() }),
            ),
        )
        .await
        .expect_err("fill without gesture must fail");
    assert!(
        err.to_string().contains("user_gesture_required"),
        "got: {err}"
    );

    // Unknown host origin is rejected outright.
    let _err = handle_request(
        &db_path,
        &state_dir,
        request("request_fill", serde_json::json!({ "origin": "not a url" })),
    )
    .await
    .expect_err("invalid origin must fail");

    // copy with an unknown field is rejected (item exists; field check runs
    // only after the item lookup succeeds).
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": cred_id.to_string(),
                "field": "bogus",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("copy unknown field must fail");
    assert!(err.to_string().contains("unknown field"), "got: {err}");

    // copy of a ghost item reports not_found.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": uuid::Uuid::new_v4().to_string(),
                "field": "username",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("copy ghost item must fail");
    assert!(err.to_string().contains("not_found"), "got: {err}");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_request_fill_success_and_error_branches() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let pw_id = seed_password_credential(
        &db_path,
        identity_id,
        "Fill me",
        Some("https://example.com/login"),
        Some("alice@example.com"),
        "hunter2",
    )
    .await;
    let totp_id = seed_totp_credential(
        &db_path,
        identity_id,
        "TOTP entry",
        Some("https://example.com/totp"),
    )
    .await;

    // Happy path: kind, request id, and decrypted payload fields.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "fill must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "fill_response");
    assert_eq!(resp.request_id.as_deref(), Some("req-1"));
    let payload = resp.payload.unwrap();
    assert_eq!(payload["username"], "alice@example.com");
    assert_eq!(payload["password"], "hunter2");

    // Bad payload -> context error.
    let err = handle_request(
        &db_path,
        &state_dir,
        request("request_fill", serde_json::json!({})),
    )
    .await
    .expect_err("fill without payload fields must fail");
    assert!(
        err.to_string().contains("invalid payload for request_fill"),
        "got: {err}"
    );

    // Non-UUID item id.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": "not-a-uuid",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("fill with a non-uuid item must fail");
    assert!(
        err.to_string().starts_with("invalid item_id uuid"),
        "got: {err}"
    );

    // Ghost item reports not_found.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": uuid::Uuid::new_v4().to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("fill of a ghost item must fail");
    assert!(err.to_string().contains("not_found"), "got: {err}");

    // Filling a TOTP credential is unsupported.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": totp_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("fill of a totp credential must fail");
    assert!(
        err.to_string().contains("unsupported_credential_type"),
        "got: {err}"
    );

    // Origin mismatch is rejected.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://evil.com",
                "item_id": pw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("fill from a mismatched origin must fail");
    assert!(err.to_string().starts_with("origin_mismatch"), "got: {err}");

    // Credential owned by another identity.
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("fill for a foreign identity must fail");
    assert!(err.to_string().starts_with("wrong_identity"), "got: {err}");
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(identity_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    // With the gesture requirement disabled, a gestureless fill passes.
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "0");
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string()
            }),
        ),
    )
    .await
    .unwrap();
    assert!(
        resp.ok,
        "gestureless fill must pass when requirement disabled: {:?}",
        resp.error
    );

    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_fill_mismatched_payload_arms_and_totp_gates() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

    // A credential whose row type is Password but whose sealed payload is
    // raw bytes: the type gate passes and the fill match takes the Raw
    // arm (username only, no password).
    let raw_id = seed_password_typed_credential(
        &db_path,
        identity_id,
        "Raw payload",
        Some("https://example.com/raw"),
        &CredentialData::Raw(vec![1, 2, 3]),
    )
    .await;
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com/raw",
                "item_id": raw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    assert!(
        resp.ok,
        "fill of raw payload must succeed: {:?}",
        resp.error
    );
    let payload = resp.payload.unwrap();
    assert_eq!(payload["password"], serde_json::Value::Null);
    assert_eq!(payload["username"], serde_json::Value::Null);

    // The catch-all arm: row type Password, sealed payload an API key.
    let api_id = seed_password_typed_credential(
        &db_path,
        identity_id,
        "Api payload",
        Some("https://example.com/api"),
        &CredentialData::ApiKey(persona_core::models::ApiKeyData {
            api_key: "sk-1".to_string(),
            api_secret: None,
            token: None,
            permissions: Vec::new(),
            expires_at: None,
        }),
    )
    .await;
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com/api",
                "item_id": api_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    assert!(
        resp.ok,
        "fill of api payload must succeed: {:?}",
        resp.error
    );
    let payload = resp.payload.unwrap();
    assert_eq!(payload["password"], serde_json::Value::Null);

    // get_totp: gesture gate rejects background requests.
    let totp_id = seed_totp_credential(
        &db_path,
        identity_id,
        "TOTP entry",
        Some("https://example.com/totp"),
    )
    .await;
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com/totp",
                "item_id": totp_id.to_string()
            }),
        ),
    )
    .await
    .expect_err("gestureless totp must fail");
    assert!(
        err.to_string().starts_with("user_gesture_required"),
        "got: {err}"
    );

    // get_totp: origin mismatch with the credential URL.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://evil.com",
                "item_id": totp_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("totp from a mismatched origin must fail");
    assert!(err.to_string().starts_with("origin_mismatch"), "got: {err}");

    // get_totp: credential owned by the (now) inactive identity.
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com/totp",
                "item_id": totp_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("totp for a foreign identity must fail");
    assert!(err.to_string().starts_with("wrong_identity"), "got: {err}");

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_request_fill_bank_card_returns_card_without_cvv() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let card_id = seed_bank_card_credential(&db_path, identity_id, "Personal card", "123").await;
    let pw_id = seed_password_credential(
        &db_path,
        identity_id,
        "Shop login",
        Some("https://shop.example.com"),
        Some("alice@example.com"),
        "hunter2",
    )
    .await;

    // Cards carry no URL: any checkout origin must be accepted.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://checkout.anywhere.example",
                "item_id": card_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "bank card fill must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "fill_response");
    let payload = resp.payload.unwrap();
    assert_eq!(payload["card"]["card_number"], "4111 1111 1111 1111");
    assert_eq!(payload["card"]["cardholder_name"], "ALICE SMITH");
    assert_eq!(payload["card"]["expiry_date"], "12/29");
    // CVV never leaves the bridge on the fill path.
    assert!(payload.get("cvv").is_none(), "no top-level cvv");
    assert!(
        payload["card"].get("cvv").is_none(),
        "no cvv inside card object"
    );
    assert_eq!(payload["username"], serde_json::Value::Null);
    assert_eq!(payload["password"], serde_json::Value::Null);

    // Login fills keep the exact pre-card response shape: no "card" key.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://shop.example.com",
                "item_id": pw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    let payload = resp.payload.unwrap();
    assert_eq!(payload["password"], "hunter2");
    let mut keys: Vec<&str> = payload
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["password", "username"],
        "login fill response shape must not gain a card key"
    );

    // A non-fillable type stays rejected.
    let api_id = seed_api_key_credential(&db_path, identity_id, "API key", None).await;
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://shop.example.com",
                "item_id": api_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("api key fill must stay rejected");
    assert!(
        err.to_string().contains("unsupported_credential_type"),
        "got: {err}"
    );

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_fill_rejects_totp_credential_and_origin_mismatch() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let totp_id = seed_totp_credential(
        &db_path,
        identity_id,
        "TOTP entry",
        Some("https://example.com/totp"),
    )
    .await;
    let pw_id = seed_password_credential(
        &db_path,
        identity_id,
        "Password entry",
        Some("https://example.com/login"),
        Some("alice@example.com"),
        "hunter2",
    )
    .await;

    // Filling is only allowed for password credentials.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": totp_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("fill of a totp credential must fail");
    assert!(
        err.to_string().contains("unsupported_credential_type"),
        "got: {err}"
    );

    // Fill enforces origin binding like copy does.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "request_fill",
            serde_json::json!({
                "origin": "https://evil.com",
                "item_id": pw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("fill from a mismatched origin must fail");
    assert!(err.to_string().starts_with("origin_mismatch"), "got: {err}");

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
