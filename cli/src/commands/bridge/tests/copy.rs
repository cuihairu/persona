use super::*;

/// The clipboard probe mirrors the real preconditions: on Linux, without
/// a display variable it short-circuits false; with one it consults the
/// clipboard binaries. Windows `clip` and macOS `pbcopy` don't read
/// display variables at all, so the headless assertion only applies to
/// Linux. Either way it must terminate without panicking.
#[test]
fn clipboard_probe_handles_display_and_headless_environments() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");
        assert!(
            !clipboard_available(),
            "headless machines report no clipboard"
        );
    }

    std::env::set_var("DISPLAY", ":99");
    // The binary probe decides the verdict; both outcomes are valid.
    // (Windows/macOS ignore the variable entirely — still must not panic.)
    let _ = clipboard_available();

    std::env::remove_var("DISPLAY");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_copy_bank_card_fields_and_rejections() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
    let clip_ok = clipboard_available();

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let card_id = seed_bank_card_credential(&db_path, identity_id, "Personal card", "123").await;
    let blank_id = seed_bank_card_credential(&db_path, identity_id, "Blank cvv card", "").await;
    let pw_id = seed_password_credential(
        &db_path,
        identity_id,
        "Shop login",
        Some("https://shop.example.com"),
        Some("alice@example.com"),
        "hunter2",
    )
    .await;

    // All four card fields are copyable (cards have no URL, so any
    // origin passes origin binding).
    for field in ["card_number", "cardholder_name", "expiry_date", "cvv"] {
        let result = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://checkout.anywhere.example",
                    "item_id": card_id.to_string(),
                    "field": field,
                    "user_gesture": true
                }),
            ),
        )
        .await;
        assert_copy_outcome(result, clip_ok);
    }

    // Empty card field -> not_found, not a silent empty clipboard.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://checkout.anywhere.example",
                "item_id": blank_id.to_string(),
                "field": "cvv",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("copying an empty field must fail");
    assert!(err.to_string().contains("is empty"), "got: {err}");

    // Card fields on a password credential -> unsupported type.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://shop.example.com",
                "item_id": pw_id.to_string(),
                "field": "cvv",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("cvv copy on a non-card must fail");
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
async fn bridge_copy_success_and_error_branches() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
    let clip_ok = clipboard_available();

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let pw_id = seed_password_credential(
        &db_path,
        identity_id,
        "Copy target",
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
    // A credential with no username and no URL; metadata carries an email
    // so the username fallback can be exercised.
    let anon_id = seed_password_credential(
        &db_path,
        identity_id,
        "Anonymous entry",
        None,
        None,
        "anon-pw",
    )
    .await;
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE credentials SET metadata = ? WHERE id = ?")
        .bind(r#"{"email":"meta@example.com"}"#)
        .bind(anon_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    // Happy path: copy the username.
    let result = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "field": "username",
                "user_gesture": true
            }),
        ),
    )
    .await;
    assert_copy_outcome(result, clip_ok);

    // Happy path: copy the password (case-insensitive field name).
    let result = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "field": "PASSWORD",
                "user_gesture": true
            }),
        ),
    )
    .await;
    assert_copy_outcome(result, clip_ok);

    // Happy path: copy a TOTP code.
    let result = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": totp_id.to_string(),
                "field": "totp",
                "user_gesture": true
            }),
        ),
    )
    .await;
    assert_copy_outcome(result, clip_ok);

    // Username falls back to the metadata email.
    let result = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": anon_id.to_string(),
                "field": "username",
                "user_gesture": true
            }),
        ),
    )
    .await;
    assert_copy_outcome(result, clip_ok);

    // Clearing metadata leaves no username -> not_found (before clipboard).
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE credentials SET metadata = '{}' WHERE id = ?")
        .bind(anon_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": anon_id.to_string(),
                "field": "username",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("copy without any username must fail");
    assert!(
        err.to_string()
            .contains("not_found: username not available"),
        "got: {err}"
    );

    // Bad payload -> context error.
    let err = handle_request(&db_path, &state_dir, request("copy", serde_json::json!({})))
        .await
        .expect_err("copy without payload fields must fail");
    assert!(
        err.to_string().contains("invalid payload for copy"),
        "got: {err}"
    );

    // Missing gesture is rejected before anything else.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "field": "password"
            }),
        ),
    )
    .await
    .expect_err("copy without a gesture must fail");
    assert!(
        err.to_string().starts_with("user_gesture_required"),
        "got: {err}"
    );

    // Password field on a TOTP credential is unsupported.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": totp_id.to_string(),
                "field": "password",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("copy password of a totp credential must fail");
    assert!(
        err.to_string().contains("unsupported_credential_type"),
        "got: {err}"
    );

    // TOTP field on a password credential is unsupported.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "field": "totp",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("copy totp of a password credential must fail");
    assert!(
        err.to_string().contains("unsupported_credential_type"),
        "got: {err}"
    );

    // Origin mismatch.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://evil.com",
                "item_id": pw_id.to_string(),
                "field": "username",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("copy from a mismatched origin must fail");
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
            "copy",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "field": "username",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("copy for a foreign identity must fail");
    assert!(err.to_string().starts_with("wrong_identity"), "got: {err}");
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(identity_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[test]
fn copy_success_response_builds_wire_payload() {
    let resp = copy_success_response(
        Some("req-c".to_string()),
        "https://example.com",
        "example.com",
        "00000000-0000-0000-0000-000000000001",
        "Copy target",
        "password",
    )
    .unwrap();
    assert!(resp.ok);
    assert_eq!(resp.kind, "copy_response");
    assert_eq!(resp.request_id.as_deref(), Some("req-c"));
    assert_eq!(resp.payload.unwrap()["copied"], true);
}
