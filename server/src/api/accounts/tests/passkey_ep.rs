use super::*;

#[tokio::test]
async fn passkey_registration_stores_attested_material() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "passkey-alice@example.com").await;
    let reg = register_account_passkey(&router, &account_id).await;

    // DB: a real COSE public key + rp_id anchor + counter (no longer a keyless stub row)
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

    // create-options was never issued: a client-made-up challenge -> 401
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

    // Took challenge A, but built clientData with a stale/other challenge B -> 401
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
    // The claimed credentialId does not match the attested data (identity swap) -> 401
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

// ---- Passkey login: login-options challenge + sessions assertion verification ----

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

    // Missing credentialId / missing attestationObject -> 422 (a fresh challenge is needed
    // each round: take's single-use consumption happens before field validation)
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

    // attestationObject is not valid base64 -> 422
    let _ = get_create_options(&router, &account_id).await;
    let (status, body) = post(json!({
        "attestation_response": {"credentialId": "AA", "attestationObject": "!!"},
        "client_data_json": "e30", "origin": ORIGIN,
    }))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // attestationObject exceeds 8 KiB after decoding -> 422
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

    // Store the same challenge twice directly in the webauthn state: submitting the same
    // fully verifiable attestation payload twice makes the second INSERT hit the
    // credential_id UNIQUE constraint -> 409
    // (the challenge must be valid base64url — the software-authenticator side validates it)
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
