use super::*;

#[tokio::test]
async fn account_srp_challenge_returns_real_server_public() {
    let (router, _) = setup_state().await;
    let account_id = create_account(&router, "srp-real@example.com").await;
    register_account_srp(&router, &account_id).await;

    let (_, salt, server_public) = account_srp_challenge(&router, &account_id).await;
    // 4096-bit group: B and the verifier are both on the order of 512B (511B with leading
    // zeros), no longer a verifier placeholder.
    assert!(
        (400..=512).contains(&server_public.len()),
        "server_public len = {}",
        server_public.len()
    );
    assert_eq!(salt.len(), 32);
}

#[tokio::test]
async fn account_srp_login_round_trip_verifies_client_proof() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "srp-alice@example.com").await;
    register_account_srp(&router, &account_id).await;

    let login = srp::SrpClientLogin::new().unwrap();
    let a_pub = login.public_ephemeral().to_vec();
    let (status, resp) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/srp/challenge"),
            None,
            Some("application/json"),
            &json!({"device_name": SRP_DEVICE, "client_public": b64(&a_pub)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
    let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
    let session_id = resp["session_id"].as_str().unwrap().to_owned();

    let proof = login
        .process(SRP_DEVICE, SRP_PASSWORD, &salt, &server_public)
        .unwrap();
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/srp/verify"),
            None,
            Some("application/json"),
            &json!({"session_id": session_id, "client_proof": b64(proof.client_proof())})
                .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["expires_in_secs"], 900);

    // Mutual authentication: server_proof (M2) must pass client-side verification
    let server_proof = B64.decode(body["server_proof"].as_str().unwrap()).unwrap();
    let session_key = proof.verify_server(&server_proof).unwrap();
    assert!((1..=512).contains(&session_key.len()));
    assert!(session_key.iter().any(|&b| b != 0));

    // DB: the 15min session row is persisted
    let token = body["token"].as_str().unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_sessions WHERE account_id = ? AND session_token = ?",
    )
    .bind(&account_id)
    .bind(token)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn account_srp_wrong_password_rejected_without_session() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "srp-wrong@example.com").await;
    register_account_srp(&router, &account_id).await;

    let (status, body) = attempt_account_srp_login(&router, &account_id, "wrong-password").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_session_count(&state, &account_id).await, 0);

    // One failure does not trigger lockout: the correct password still logs in
    let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn account_srp_verify_requires_client_proof_field() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "srp-fields@example.com").await;
    register_account_srp(&router, &account_id).await;
    let (session_id, _, _) = account_srp_challenge(&router, &account_id).await;

    // Missing client_proof -> 422 (serde deserialization rejection)
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/srp/verify"),
            None,
            Some("application/json"),
            &json!({"session_id": session_id}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(account_session_count(&state, &account_id).await, 0);
}

#[tokio::test]
async fn account_srp_verify_rejects_cross_account_session() {
    let (router, state) = setup_state().await;
    let a = create_account(&router, "cross-a@example.com").await;
    let b = create_account(&router, "cross-b@example.com").await;
    register_account_srp(&router, &b).await;
    // b registered SRP credentials, a did not — take b's session to a's verify path
    let login = srp::SrpClientLogin::new().unwrap();
    let a_pub = login.public_ephemeral().to_vec();
    let (status, resp) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{b}/srp/challenge"),
            None,
            Some("application/json"),
            &json!({"device_name": SRP_DEVICE, "client_public": b64(&a_pub)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
    let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
    let session_id = resp["session_id"].as_str().unwrap().to_owned();
    let proof = login
        .process(SRP_DEVICE, SRP_PASSWORD, &salt, &server_public)
        .unwrap();

    // A correct M1, but sent to a's path: the lock key prefix does not match -> 401
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{a}/srp/verify"),
            None,
            Some("application/json"),
            &json!({"session_id": session_id, "client_proof": b64(proof.client_proof())})
                .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_session_count(&state, &a).await, 0);
}

#[tokio::test]
async fn account_srp_five_failures_lock_account() {
    let (router, _) = setup_state().await;
    let account_id = create_account(&router, "srp-locked@example.com").await;
    register_account_srp(&router, &account_id).await;

    for _ in 0..5 {
        let (status, _) = attempt_account_srp_login(&router, &account_id, "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // During lockout the correct password is also 423 Locked
    let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
    assert_eq!(status, StatusCode::LOCKED, "{body}");
}

// ---- Passkey registration: real attestation verification ----

#[tokio::test]
async fn srp_register_rejects_duplicate_and_bad_fields() {
    let (router, _) = setup_state().await;
    let account_id = create_account(&router, "srp-badfields@example.com").await;
    register_account_srp(&router, &account_id).await;
    let reg = srp::register_verifier(SRP_DEVICE, SRP_PASSWORD).unwrap();
    let url = format!("/api/v1/accounts/{account_id}/srp/register");

    // Duplicate registration on the same device -> 409
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({
                "device_name": SRP_DEVICE,
                "salt": b64(&reg.salt),
                "verifier": b64(&reg.verifier),
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Blank device_name / device_name containing whitespace -> 422
    for name in ["", "de vice"] {
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &url,
                &json!({
                    "device_name": name,
                    "salt": b64(&reg.salt),
                    "verifier": b64(&reg.verifier),
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }

    // salt is not valid base64 -> 422
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({
                "device_name": "dev2",
                "salt": "!!not-b64!!",
                "verifier": b64(&reg.verifier),
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // salt exceeds 64 bytes after decoding -> 422
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &url,
            &json!({
                "device_name": "dev2",
                "salt": b64(&[0u8; 100]),
                "verifier": b64(&reg.verifier),
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}
