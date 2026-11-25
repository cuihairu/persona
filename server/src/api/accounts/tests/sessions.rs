use super::*;

#[tokio::test]
async fn create_session_with_passkey_assertion_round_trip() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "pk-login@example.com").await;
    let reg = register_account_passkey(&router, &account_id).await;
    let passkey_id = B64URL.encode(&reg.credential_id);

    let (client_data, out) = login_options_and_assert(&router, &account_id, &reg).await;
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            &assertion_body(&passkey_id, &client_data, &out),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["expires_in_secs"], 86400);

    // DB: 24h session row + last_used_at touched
    let token = body["session_token"].as_str().unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_sessions WHERE account_id = ? AND session_token = ?",
    )
    .bind(&account_id)
    .bind(token)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    let last_used: String =
        sqlx::query_scalar("SELECT last_used_at FROM account_passkeys WHERE id = ?")
            .bind(&passkey_id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert!(!last_used.is_empty());

    // Replay: after re-running login-options (a new challenge), the old assertion's
    // challenge no longer matches -> 401
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
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            &assertion_body(&passkey_id, &client_data, &out),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn create_session_rejects_tampered_signature() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "pk-tamper@example.com").await;
    let reg = register_account_passkey(&router, &account_id).await;
    let (client_data, mut out) = login_options_and_assert(&router, &account_id, &reg).await;

    // Flip the last byte of the signature
    let last = out.signature_der.len() - 1;
    out.signature_der[last] ^= 0xFF;

    let passkey_id = B64URL.encode(&reg.credential_id);
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            &assertion_body(&passkey_id, &client_data, &out),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_session_count(&state, &account_id).await, 0);
}

#[tokio::test]
async fn create_session_rejects_sign_count_regression() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "pk-count@example.com").await;
    let reg = register_account_passkey(&router, &account_id).await;
    let passkey_id = B64URL.encode(&reg.credential_id);

    // Raise the stored counter to 5: the software authenticator's assertion is always 0
    // -> regression -> 401 (clone detection)
    sqlx::query("UPDATE account_passkeys SET sign_count = 5 WHERE id = ?")
        .bind(&passkey_id)
        .execute(&state.pool)
        .await
        .unwrap();

    let (client_data, out) = login_options_and_assert(&router, &account_id, &reg).await;
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            &assertion_body(&passkey_id, &client_data, &out),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_session_count(&state, &account_id).await, 0);
}

#[tokio::test]
async fn login_options_hides_unknown_credentials() {
    let (router, _) = setup_state().await;
    let account_id = create_account(&router, "pk-unknown@example.com").await;

    // Unknown credential -> 401 (same shape as "no challenge", so credential existence is not leaked)
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/passkeys/login-options"),
            None,
            Some("application/json"),
            &json!({"credential_id": "unknown-credential-id"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

// ---- Session evidence dispatch: SRP token arm ----

#[tokio::test]
async fn create_session_with_srp_token_evidence() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "sess-srp@example.com").await;
    register_account_srp(&router, &account_id).await;
    let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let srp_token = body["token"].as_str().unwrap().to_owned();

    // A real SRP token -> 24h session
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            &json!({"srp_token": srp_token}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["expires_in_secs"], 86400);

    // A forged token -> 401
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            &json!({"srp_token": "forged-token"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Cross-account: A's token against B's path -> 401
    let other = create_account(&router, "sess-other@example.com").await;
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{other}/sessions"),
            &json!({"srp_token": srp_token}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(account_session_count(&state, &other).await, 0);
}

#[tokio::test]
async fn create_session_rejects_missing_or_double_evidence() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "sess-none@example.com").await;

    // No evidence -> 422
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            &json!({}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Both pieces of evidence given at once -> 422
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            &json!({
                "srp_token": "some-token",
                "passkey_assertion": {
                    "credential_id": "x", "client_data_json": "e30", "origin": ORIGIN,
                    "authenticator_data": "AQ", "signature": "AQ",
                },
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(account_session_count(&state, &account_id).await, 0);
}

// ---- M2 closeout: account_sessions as a token consumer (require_account_bearer) ----

/// The login exchange chain end to end: the SRP login token (15 min, an
/// account_sessions row) can itself act as the account-route Bearer — exchange it for
/// a 24h session -> the session token drives the account-management routes
/// (including activity touch) -> revoke itself (logout) -> reuse is 401.
#[tokio::test]
async fn account_session_tokens_drive_account_routes_end_to_end() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "consumer@example.com").await;
    register_account_srp(&router, &account_id).await;
    let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let srp_token = body["token"].as_str().unwrap().to_owned();

    // The 15-minute SRP token as Bearer + evidence -> a 24h account session (previously
    // this flow could not obtain a Bearer without a static token — the exchange chain
    // broke at its first step)
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/sessions"),
            Some(&format!("Bearer {srp_token}")),
            Some("application/json"),
            &json!({"srp_token": srp_token}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session_token = body["session_token"].as_str().unwrap().to_owned();

    async fn session_activity(state: &crate::state::AppState, token: &str) -> String {
        sqlx::query_scalar("SELECT last_activity_at FROM account_sessions WHERE session_token = ?")
            .bind(token)
            .fetch_one(&state.pool)
            .await
            .unwrap()
    }
    let before = session_activity(&state, &session_token).await;

    // The 24h session token drives the account-management routes + last_activity_at is touched by the consumer
    let (status, body) = send(
        router.clone(),
        request(
            "GET",
            &format!("/api/v1/accounts/{account_id}/devices"),
            Some(&format!("Bearer {session_token}")),
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["devices"].as_array().unwrap().len(), 0);
    let after = session_activity(&state, &session_token).await;
    assert!(
        after > before,
        "activity should be touched ({before} → {after})"
    );

    // Logout: the session token revokes itself -> 204; reusing the revoked token is 401
    let (status, _) = send(
        router.clone(),
        request(
            "DELETE",
            &format!("/api/v1/accounts/{account_id}/sessions/{session_token}"),
            Some(&format!("Bearer {session_token}")),
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(
        router.clone(),
        request(
            "GET",
            &format!("/api/v1/accounts/{account_id}/devices"),
            Some(&format!("Bearer {session_token}")),
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Path-ownership restriction: account A's session token against B's account path -> 401.
#[tokio::test]
async fn account_session_token_rejected_on_foreign_account_paths() {
    let (router, _) = setup_state().await;
    let owner = create_account(&router, "owner@example.com").await;
    register_account_srp(&router, &owner).await;
    let (status, body) = attempt_account_srp_login(&router, &owner, SRP_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();

    let other = create_account(&router, "foreign@example.com").await;
    let (status, _) = send(
        router.clone(),
        request(
            "GET",
            &format!("/api/v1/accounts/{other}/devices"),
            Some(&format!("Bearer {token}")),
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Expired session rows are not honored (the consumer-side TTL matches issuance/evidence verification).
#[tokio::test]
async fn expired_account_session_token_is_rejected() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "expired@example.com").await;
    sqlx::query(
        "INSERT INTO account_sessions (id, account_id, session_token, expires_at, created_at, last_activity_at)
         VALUES ('sid-expired', ?, 'expired-session-token', '2020-01-01T00:00:00+00:00',
                 '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00')",
    )
    .bind(&account_id)
    .execute(&state.pool)
    .await
    .unwrap();

    let (status, _) = send(
        router.clone(),
        request(
            "GET",
            &format!("/api/v1/accounts/{account_id}/devices"),
            Some("Bearer expired-session-token"),
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Migration 0007 boundary: account sessions are not a Bearer for sync/events —
/// require_bearer does not consult account_sessions, so no privilege escalation
/// exists outside the account routes.
#[tokio::test]
async fn account_session_token_is_not_accepted_outside_account_routes() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "isolation@example.com").await;
    let now = chrono::Utc::now().to_rfc3339();
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    sqlx::query(
        "INSERT INTO account_sessions (id, account_id, session_token, expires_at, created_at, last_activity_at)
         VALUES ('sid-live', ?, 'live-session-token', ?, ?, ?)",
    )
    .bind(&account_id)
    .bind(&future)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .unwrap();

    // An unexpired token is invalid for sync/events alike (require_bearer has no such consumer)
    for uri in ["/api/v1/sync/devices", "/api/v1/events"] {
        let (status, _) = send(
            router.clone(),
            request("GET", uri, Some("Bearer live-session-token"), None, ""),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    // The same token remains valid on its owning account's path (control group confirming the inserted row works)
    let (status, _) = send(
        router.clone(),
        request(
            "GET",
            &format!("/api/v1/accounts/{account_id}/devices"),
            Some("Bearer live-session-token"),
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
