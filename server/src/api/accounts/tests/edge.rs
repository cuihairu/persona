use super::*;

// ---- Validation and error branches: 422/404/409 shapes for each handler ----

#[test]
fn webauthn_state_default_is_empty() {
    let state = AccountWebauthnState::default();
    assert!(state.take("a", WebauthnCeremony::Register).is_none());
}

#[tokio::test]
async fn register_rejects_blank_and_oversized_username() {
    let router = router().await;
    for username in ["   ".to_owned(), "a".repeat(257)] {
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/accounts/register",
                None,
                Some("application/json"),
                &json!({"username": username}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }
}

#[tokio::test]
async fn recovery_code_verify_rejects_bad_format() {
    let router = router().await;
    let account_id = create_account(&router, "rc-bad@example.com").await;
    let url = format!("/api/v1/accounts/{account_id}/recovery-codes/verify");

    // Length is not 32 -> 422
    let (status, body) = send(
        router.clone(),
        req("POST", &url, &json!({"code": "abc"}).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // 32 chars but not hex -> 422
    let (status, body) = send(
        router.clone(),
        req("POST", &url, &json!({"code": "z".repeat(32)}).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[tokio::test]
async fn authorize_device_rejects_unknown_and_mismatched() {
    let (router, _) = setup_state().await;
    let account_id = create_account(&router, "dev-auth@example.com").await;
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
    let device_id = body["device_id"].as_str().unwrap().to_string();
    let url = format!("/api/v1/accounts/{account_id}/devices");

    // Unregistered sync device -> 422
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({"device_id": "unknown-device", "public_key": b64(&[7u8; 32])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // public_key is not valid base64 -> 422
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({"device_id": device_id, "public_key": "!!"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // public_key does not match the one at registration -> 422
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({"device_id": device_id, "public_key": b64(&[9u8; 32])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[tokio::test]
async fn revoke_device_unknown_returns_not_found() {
    let router = router().await;
    let account_id = create_account(&router, "dev-revoke@example.com").await;
    let (status, _) = send(
        router.clone(),
        request(
            "DELETE",
            &format!("/api/v1/accounts/{account_id}/devices/no-such-device"),
            Some(&format!("Bearer {TOKEN}")),
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sessions_reject_blank_srp_token_and_challengeless_assertion() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "sess-blank@example.com").await;
    let url = format!("/api/v1/accounts/{account_id}/sessions");

    // Blank srp_token -> 401
    let (status, body) = send(
        router.clone(),
        req("POST", &url, &json!({"srp_token": "   "}).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Assertion without going through login-options (no in-flight challenge to consume) -> 401
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({"passkey_assertion": {
                "credential_id": "x", "client_data_json": "e30", "origin": ORIGIN,
                "authenticator_data": "AQ", "signature": "AQ",
            }})
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_session_count(&state, &account_id).await, 0);
}

#[tokio::test]
async fn sessions_reject_malformed_assertion_fields() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "pk-badassert@example.com").await;
    let reg = register_account_passkey(&router, &account_id).await;
    let passkey_id = B64URL.encode(&reg.credential_id);
    let url = format!("/api/v1/accounts/{account_id}/sessions");

    // The challenge is consumed once, so login-options must be re-issued before each malformed payload
    async fn fresh_login_options(router: &axum::Router, account_id: &str, passkey_id: &str) {
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/login-options"),
                None,
                Some("application/json"),
                &json!({"credential_id": passkey_id}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // client_data_json is not base64 -> 422
    fresh_login_options(&router, &account_id, &passkey_id).await;
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({"passkey_assertion": {
                "credential_id": passkey_id, "client_data_json": "!!",
                "origin": ORIGIN, "authenticator_data": "AQ", "signature": "AQ",
            }})
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // authenticator_data is not base64 -> 422
    fresh_login_options(&router, &account_id, &passkey_id).await;
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({"passkey_assertion": {
                "credential_id": passkey_id,
                "client_data_json": B64URL.encode(
                    br#"{"type":"webauthn.get","challenge":"x","origin":"https://example.com"}"#,
                ),
                "origin": ORIGIN, "authenticator_data": "!!", "signature": "AQ",
            }})
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // clientData origin does not match the declared one -> parse rejects -> 401
    fresh_login_options(&router, &account_id, &passkey_id).await;
    let evil =
        r#"{"type":"webauthn.get","challenge":"x","origin":"https://evil.example"}"#.to_string();
    let (_, out) = login_options_and_assert(&router, &account_id, &reg).await;
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({"passkey_assertion": {
                "credential_id": passkey_id,
                "client_data_json": B64URL.encode(evil.as_bytes()),
                "origin": ORIGIN,
                "authenticator_data": B64URL.encode(&out.authenticator_data),
                "signature": B64URL.encode(&out.signature_der),
            }})
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_session_count(&state, &account_id).await, 0);
}
