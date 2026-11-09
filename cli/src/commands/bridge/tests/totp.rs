use super::*;

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_get_totp_success_and_error_branches() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let pw_id = seed_password_credential(
        &db_path,
        identity_id,
        "Password entry",
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

    // Happy path: a six digit code for a 30s period.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": totp_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "totp must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "totp_response");
    assert_eq!(resp.request_id.as_deref(), Some("req-1"));
    let payload = resp.payload.unwrap();
    let code = payload["code"].as_str().unwrap();
    assert_eq!(code.len(), 6, "code must be six digits");
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(payload["period"], 30);
    let remaining = payload["remaining_seconds"].as_u64().unwrap();
    assert!((1..=30).contains(&remaining));

    // HOTP entry: the page-side fill path has no counter concept, so the
    // bridge refuses instead of generating a time-based code.
    let hotp_id = seed_hotp_credential(
        &db_path,
        identity_id,
        "HOTP entry",
        Some("https://example.com/hotp"),
        0,
    )
    .await;
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": hotp_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("HOTP must be refused on the bridge");
    assert!(err.to_string().contains("hotp_not_supported"), "got: {err}");

    // Bad payload -> context error.
    let err = handle_request(
        &db_path,
        &state_dir,
        request("get_totp", serde_json::json!({})),
    )
    .await
    .expect_err("get_totp without payload fields must fail");
    assert!(
        err.to_string().contains("invalid payload for get_totp"),
        "got: {err}"
    );

    // Non-UUID item id.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": "nope",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("get_totp with a non-uuid item must fail");
    assert!(
        err.to_string().starts_with("invalid item_id uuid"),
        "got: {err}"
    );

    // Ghost item.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": uuid::Uuid::new_v4().to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("get_totp of a ghost item must fail");
    assert!(err.to_string().contains("not_found"), "got: {err}");

    // TOTP on a password credential is unsupported.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("totp of a password credential must fail");
    assert!(
        err.to_string().contains("unsupported_credential_type"),
        "got: {err}"
    );

    // Type/data mismatch: row says TwoFactor but the sealed data is a
    // password. Hit through a direct store rewrite.
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE credentials SET credential_type = 'TwoFactor' WHERE id = ?")
        .bind(pw_id.to_string())
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
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("totp with mismatched data must fail");
    assert!(
        err.to_string().contains("unsupported_credential_type"),
        "got: {err}"
    );
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE credentials SET credential_type = 'Password' WHERE id = ?")
        .bind(pw_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    // A TOTP entry without a URL has no origin binding.
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE credentials SET url = NULL WHERE id = ?")
        .bind(totp_id.to_string())
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
                "origin": "https://example.com",
                "item_id": totp_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("totp without a bound URL must fail");
    assert!(
        err.to_string().starts_with("origin_binding_required"),
        "got: {err}"
    );
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE credentials SET url = 'https://example.com/totp' WHERE id = ?")
        .bind(totp_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    // Origin mismatch.
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
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": totp_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("totp for a foreign identity must fail");
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

/// GameToken 凭据走 get_totp/copy 的调度器臂：Steam Guard 出 5 位码，
/// 绑定型 provider（如未来的腾讯安全中心）必须报错而不是伪造码。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_get_totp_supports_game_token_provider() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let steam_id = seed_game_token_credential(
        &db_path,
        identity_id,
        "Steam Guard",
        Some("https://store.steampowered.com"),
        "steam_guard",
    )
    .await;
    let bound_id = seed_game_token_credential(
        &db_path,
        identity_id,
        "Vendor bound token",
        Some("https://example.com/bound"),
        "tencent_security",
    )
    .await;

    // Happy path: a five character code from the Steam alphabet, 30s period.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://store.steampowered.com",
                "item_id": steam_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "steam guard must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "totp_response");
    let payload = resp.payload.unwrap();
    let code = payload["code"].as_str().unwrap();
    assert_eq!(code.len(), 5, "steam guard code is five chars");
    assert!(
        code.bytes()
            .all(|c| b"23456789BCDFGHJKMNPQRTVWXY".contains(&c)),
        "code {code} outside the Steam alphabet"
    );
    assert_eq!(payload["period"], 30);
    let remaining = payload["remaining_seconds"].as_u64().unwrap();
    assert!((1..=30).contains(&remaining));

    // copy field "totp" resolves GameToken data through the same arm.
    let clip_ok = clipboard_available();
    let result = handle_request(
        &db_path,
        &state_dir,
        request(
            "copy",
            serde_json::json!({
                "origin": "https://store.steampowered.com",
                "item_id": steam_id.to_string(),
                "field": "totp",
                "user_gesture": true
            }),
        ),
    )
    .await;
    assert_copy_outcome(result, clip_ok);

    // A binding-based provider must error out, never fabricate a code.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": bound_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("binding-based provider must not generate offline codes");
    assert!(
        err.to_string().contains("Unsupported game token provider"),
        "got: {err}"
    );

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[test]
fn totp_helpers_match_rfc_vectors_and_clamps() {
    // RFC 4226 Appendix D reference vectors (HMAC-SHA1, 6 digits).
    let secret = decode_totp_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    assert_eq!(secret, b"12345678901234567890".to_vec());
    assert_eq!(hotp(&secret, 0, "SHA1").unwrap() % 1_000_000, 755224);
    assert_eq!(hotp(&secret, 1, "SHA1").unwrap() % 1_000_000, 287082);
    assert_eq!(hotp(&secret, 5, "SHA1").unwrap() % 1_000_000, 254676);
    assert_eq!(hotp(&secret, 9, "SHA1").unwrap() % 1_000_000, 520489);

    // HMAC-SHA256/SHA512 truncated values cross-checked against an
    // independent reference implementation (counter 1, 8 digits).
    // The 30-byte secret "123456789012345678901234567890".
    let s256 = decode_totp_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    let s512 = decode_totp_secret(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        )
        .unwrap();
    assert_eq!(hotp(&s256, 1, "SHA256").unwrap() % 100_000_000, 82366409);
    assert_eq!(hotp(&s512, 1, "SHA512").unwrap() % 100_000_000, 98063437);
    // Unknown (and lowercase) algorithms fall back to HMAC-SHA1.
    assert_eq!(hotp(&secret, 1, "sha1").unwrap() % 1_000_000, 287082);
    assert_eq!(hotp(&secret, 1, "MD5").unwrap() % 1_000_000, 287082);

    // decode_totp_secret normalizes case, whitespace, and padding.
    assert_eq!(
        decode_totp_secret("gezd gnbvGY3TQOJQ\nGEZDGNBVGY3TQOJQ").unwrap(),
        secret
    );
    assert_eq!(
        decode_totp_secret("NBSWY3DPFVZWKY3SMV2C2YLCMM======").unwrap(),
        b"hello-secret-abc".to_vec()
    );
    let err = decode_totp_secret("not!base32!").unwrap_err();
    assert!(
        err.to_string().starts_with("invalid_base32_secret"),
        "got: {err}"
    );

    // generate_totp_code_from_data: six digits, remaining within period.
    let (code, remaining, period) = generate_totp_code_from_data(&TwoFactorData {
        secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
        issuer: "Issuer".to_string(),
        account_name: "a@b.c".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        hotp: None,
        initial_counter: None,
        period: 30,
    })
    .unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!((1..=30).contains(&remaining));
    assert_eq!(period, 30);

    // Digits below 4 clamp up; a zero period becomes one second.
    let (short, remaining0, period0) = generate_totp_code_from_data(&TwoFactorData {
        secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
        issuer: "Issuer".to_string(),
        account_name: "a@b.c".to_string(),
        algorithm: "SHA256".to_string(),
        digits: 1,
        hotp: None,
        initial_counter: None,
        period: 0,
    })
    .unwrap();
    assert_eq!(short.len(), 4);
    assert_eq!(remaining0, 1, "period 1 leaves exactly one second");
    assert_eq!(period0, 1);

    // Nine digits still works...
    let (long, _, _) = generate_totp_code_from_data(&TwoFactorData {
        secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
        issuer: "Issuer".to_string(),
        account_name: "a@b.c".to_string(),
        algorithm: "SHA512".to_string(),
        digits: 9,
        hotp: None,
        initial_counter: None,
        period: 60,
    })
    .unwrap();
    assert_eq!(long.len(), 9);

    // Regression: 10 digits used to overflow `10_u32.pow(..)` (panic in
    // debug, wrapped modulus in release). The u64 path must format a full
    // 10-digit code.
    let (max_digits, _, _) = generate_totp_code_from_data(&TwoFactorData {
        secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
        issuer: "Issuer".to_string(),
        account_name: "a@b.c".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 10,
        hotp: None,
        initial_counter: None,
        period: 30,
    })
    .unwrap();
    assert_eq!(max_digits.len(), 10);
    assert!(max_digits.chars().all(|c| c.is_ascii_digit()));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_get_totp_rejects_password_credential() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let pw_id = seed_password_credential(
        &db_path,
        identity_id,
        "Password entry",
        Some("https://example.com/login"),
        Some("alice@example.com"),
        "hunter2",
    )
    .await;

    // get_totp only serves two-factor credentials.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_totp",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": pw_id.to_string(),
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("get_totp of a password credential must fail");
    assert!(
        err.to_string().contains("unsupported_credential_type"),
        "got: {err}"
    );

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
