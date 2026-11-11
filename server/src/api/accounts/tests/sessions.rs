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

    // DB：24h 会话行 + last_used_at 触达
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

    // 重放：重新 login-options（新挑战）后旧断言的挑战已不匹配 → 401
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

    // 翻转签名尾字节
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

    // 存量计数器抬到 5：软件认证器断言恒为 0 → 回退 → 401（克隆检测）
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

    // 未知凭据 → 401（与"无挑战"同形，不泄露凭据存在性）
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

// ---- sessions 证据分派：SRP token 臂 ----

#[tokio::test]
async fn create_session_with_srp_token_evidence() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "sess-srp@example.com").await;
    register_account_srp(&router, &account_id).await;
    let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let srp_token = body["token"].as_str().unwrap().to_owned();

    // 真 SRP token → 24h 会话
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

    // 假 token → 401
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

    // 跨账号：A 的 token 打到 B 的路径 → 401
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

    // 无证据 → 422
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

    // 两种证据同给 → 422
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

// ---- M2 收口：account_sessions 令牌消费方（require_account_bearer） ----

/// 登录兑换链端到端：SRP 登录令牌（15min，account_sessions 行）本身
/// 即可作账号路由 Bearer——兑换 24h 会话 → 会话令牌驱动账号管理路由
/// （含活跃触达）→ 吊销自身（登出）→ 再用即 401。
#[tokio::test]
async fn account_session_tokens_drive_account_routes_end_to_end() {
    let (router, state) = setup_state().await;
    let account_id = create_account(&router, "consumer@example.com").await;
    register_account_srp(&router, &account_id).await;
    let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let srp_token = body["token"].as_str().unwrap().to_owned();

    // 15 分钟 SRP 令牌作 Bearer + 证据 → 24h 账号会话（此前该流程在
    // 没有静态令牌的客户端上拿不到 Bearer，兑换链断在第一步）
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

    // 24h 会话令牌驱动账号管理路由 + last_activity_at 被消费方触达
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

    // 登出：会话令牌吊销自己 → 204；被吊销的令牌再用即 401
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

/// 路径归属限定：账号 A 的会话令牌打 B 的账号路径 → 401。
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

/// 过期会话行不认（消费侧 TTL 与签发/证据核验同口径）。
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

/// 迁移 0007 边界：账号会话不作 sync/events 的 Bearer——require_bearer
/// 不查 account_sessions，账号路由之外的提权不存在。
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

    // 未过期令牌对 sync/events 均无效（require_bearer 无此消费方）
    for uri in ["/api/v1/sync/devices", "/api/v1/events"] {
        let (status, _) = send(
            router.clone(),
            request("GET", uri, Some("Bearer live-session-token"), None, ""),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    // 同一令牌在其归属账号路径上仍然有效（对照组，确认插入的行可用）
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
