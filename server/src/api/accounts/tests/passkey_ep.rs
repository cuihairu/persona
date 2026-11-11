use super::*;

#[tokio::test]
async fn passkey_registration_stores_attested_material() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "passkey-alice@example.com").await;
    let reg = register_account_passkey(&router, &account_id).await;

    // DB：真 COSE 公钥 + rp_id 锚点 + 计数器（不再是无密钥存根行）
    let row = sqlx::query(
        "SELECT public_key, rp_id, sign_count, transports FROM account_passkeys WHERE id = ?",
    )
    .bind(B64URL.encode(&reg.credential_id))
    .fetch_one(&state.pool)
    .await
    .unwrap();
    let public_key: Vec<u8> = row.get("public_key");
    assert_eq!(public_key, reg.public_key_cose);
    assert_eq!(row.get::<String, _>("rp_id"), RP_ID);
    assert_eq!(row.get::<i64, _>("sign_count"), 0);
    assert_eq!(row.get::<String, _>("transports"), "internal");
}

#[tokio::test]
async fn passkey_register_without_create_options_rejected() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "passkey-noch@example.com").await;

    // 没发起过 create-options：客户端自造挑战 → 401
    let client_data = create_client_data("client-made-up-challenge");
    let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/passkeys/register"),
            None,
            Some("application/json"),
            &json!({
                "attestation_response": {
                    "credentialId": B64URL.encode(&reg.credential_id),
                    "attestationObject": B64URL.encode(&reg.attestation_object),
                },
                "client_data_json": B64URL.encode(client_data.as_bytes()),
                "origin": ORIGIN,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_passkey_count(&state, &account_id).await, 0);
}

#[tokio::test]
async fn passkey_register_with_stale_challenge_rejected() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "passkey-stale@example.com").await;

    // 拿了挑战 A，却用过期/别的挑战 B 造 clientData → 401
    let _options = get_create_options(&router, &account_id).await;
    let client_data = create_client_data("b3RoZXItY2hhbGxlbmdl");
    let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/passkeys/register"),
            None,
            Some("application/json"),
            &json!({
                "attestation_response": {
                    "credentialId": B64URL.encode(&reg.credential_id),
                    "attestationObject": B64URL.encode(&reg.attestation_object),
                },
                "client_data_json": B64URL.encode(client_data.as_bytes()),
                "origin": ORIGIN,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_passkey_count(&state, &account_id).await, 0);
}

#[tokio::test]
async fn passkey_register_credential_id_mismatch_rejected() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "passkey-mism@example.com").await;

    let options = get_create_options(&router, &account_id).await;
    let client_data = create_client_data(options["challenge"].as_str().unwrap());
    let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();
    // 声称的 credentialId 与 attested 数据不一致（张冠李戴）→ 401
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/passkeys/register"),
            None,
            Some("application/json"),
            &json!({
                "attestation_response": {
                    "credentialId": B64URL.encode([9u8; 32]),
                    "attestationObject": B64URL.encode(&reg.attestation_object),
                },
                "client_data_json": B64URL.encode(client_data.as_bytes()),
                "origin": ORIGIN,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_passkey_count(&state, &account_id).await, 0);
}

// ---- passkey 登录：login-options 挑战 + sessions 断言验证 ----

#[tokio::test]
async fn create_options_rejects_invalid_user_handle() {
    let router = router().await;
    let account_id = create_account(&router, "pk-baduh@example.com").await;
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/passkeys/create-options"),
            None,
            Some("application/json"),
            &json!({"rp_id": RP_ID, "user_handle": "!!not-b64!!"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[tokio::test]
async fn passkey_register_rejects_malformed_payload() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "pk-badreg@example.com").await;
    let url = format!("/api/v1/accounts/{account_id}/passkeys/register");
    let post = |payload: serde_json::Value| {
        let router = router.clone();
        let url = url.clone();
        async move {
            send(
                router,
                request(
                    "POST",
                    &url,
                    None,
                    Some("application/json"),
                    &payload.to_string(),
                ),
            )
            .await
        }
    };

    // 缺 credentialId / 缺 attestationObject → 422（每轮都要新挑战：
    // take 一次性消费发生在字段校验之前）
    let _ = get_create_options(&router, &account_id).await;
    let (status, body) = post(json!({
        "attestation_response": {"attestationObject": "AA"},
        "client_data_json": "e30", "origin": ORIGIN,
    }))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    let _ = get_create_options(&router, &account_id).await;
    let (status, body) = post(json!({
        "attestation_response": {"credentialId": "AA"},
        "client_data_json": "e30", "origin": ORIGIN,
    }))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // attestationObject 不是合法 base64 → 422
    let _ = get_create_options(&router, &account_id).await;
    let (status, body) = post(json!({
        "attestation_response": {"credentialId": "AA", "attestationObject": "!!"},
        "client_data_json": "e30", "origin": ORIGIN,
    }))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // attestationObject 解码后超过 8 KiB → 422
    let _ = get_create_options(&router, &account_id).await;
    let (status, body) = post(json!({
        "attestation_response": {
            "credentialId": "AA",
            "attestationObject": B64URL.encode(vec![0u8; 9000]),
        },
        "client_data_json": "e30", "origin": ORIGIN,
    }))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    assert_eq!(account_passkey_count(&state, &account_id).await, 0);
}

#[tokio::test]
async fn passkey_register_duplicate_credential_conflicts() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "pk-dupcred@example.com").await;

    // 直接向 webauthn 状态 store 同一挑战两次：同一份完整可验证的
    // attestation 载荷提交两次，第二次 INSERT 撞 credential_id UNIQUE → 409
    // （挑战须是合法 base64url——软件认证器侧会校验）
    let challenge = B64URL.encode(b"fixed-duplicate-challenge");
    let client_data = create_client_data(&challenge);
    let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();
    let body = json!({
        "attestation_response": {
            "credentialId": B64URL.encode(&reg.credential_id),
            "attestationObject": B64URL.encode(&reg.attestation_object),
        },
        "client_data_json": B64URL.encode(client_data.as_bytes()),
        "origin": ORIGIN,
    })
    .to_string();
    let url = format!("/api/v1/accounts/{account_id}/passkeys/register");

    state.account_webauthn.store(
        &account_id,
        challenge.to_string(),
        RP_ID.to_string(),
        WebauthnCeremony::Register,
    );
    let (status, resp) = send(
        router.clone(),
        request("POST", &url, None, Some("application/json"), &body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    state.account_webauthn.store(
        &account_id,
        challenge.to_string(),
        RP_ID.to_string(),
        WebauthnCeremony::Register,
    );
    let (status, resp) = send(
        router.clone(),
        request("POST", &url, None, Some("application/json"), &body),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{resp}");
}

#[tokio::test]
async fn login_options_rejects_blank_and_oversized_credential_id() {
    let (router, _) = setup_state().await;
    let account_id = create_account(&router, "pk-badlogin@example.com").await;
    for credential_id in [String::new(), "x".repeat(1025)] {
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/login-options"),
                None,
                Some("application/json"),
                &json!({"credential_id": credential_id}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }
}
