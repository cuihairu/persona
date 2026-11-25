use super::*;

#[tokio::test]
async fn identity_scoped_token_sees_only_its_identity_and_answers_empty_for_others() {
    let fx = fixture().await;
    let other = add_identity(&fx, "personal").await;
    let other_cred = add_credential(
        &fx,
        other,
        "personal-login",
        CredentialType::Password,
        password_data(),
    )
    .await;
    let scoped = mint_token(&fx, "work-only", read_scope(vec![fx.identity_id], vec![])).await;
    let auth = auth_header(&scoped);

    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK);
    let titles: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, vec!["login"], "scope 外身份的条目不得出现在列表");

    // An out-of-scope item = a 404 indistinguishable from nonexistent (no 403 to
    // leak scope boundaries, anti-probing)
    let missing = format!("/api/v1/connect/items/{}", other_cred);
    let (status, body) = send(fx.router.clone(), "GET", &missing, &auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    let unknown = format!("/api/v1/connect/items/{}", Uuid::new_v4());
    let (unknown_status, unknown_body) = send(fx.router.clone(), "GET", &unknown, &auth).await;
    assert_eq!(
        (status, &body["error"]["code"]),
        (unknown_status, &unknown_body["error"]["code"]),
        "越权与不存在必须同形"
    );

    // Explicitly requesting an out-of-scope identity: 200 with an empty list,
    // not 403/404
    let query = format!("/api/v1/connect/items?identity={other}");
    let (status, body) = send(fx.router.clone(), "GET", &query, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    let query = format!("/api/v1/connect/items?identity={}", fx.identity_id);
    let (status, body) = send(fx.router.clone(), "GET", &query, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    // The identity list is narrowed by scope as well
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/identities",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);

    // Control group: an all-scope token sees both identities
    let all = auth_header(&fx.token);
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &all).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 2);
    let (status, _) = send(fx.router, "GET", &missing, &all).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn type_scoped_token_hides_other_types_on_every_endpoint() {
    let fx = fixture().await;
    let totp_id = add_credential(
        &fx,
        fx.identity_id,
        "2fa",
        CredentialType::TwoFactor,
        totp_data(),
    )
    .await;
    let scoped = mint_token(
        &fx,
        "password-only",
        read_scope(vec![], vec![ConnectItemType::Password]),
    )
    .await;
    let auth = auth_header(&scoped);

    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    let totp_path = format!("/api/v1/connect/items/{}", totp_id);
    let (status, body) = send(fx.router.clone(), "GET", &totp_path, &auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    let totp_post = format!("/api/v1/connect/items/{}/totp", totp_id);
    let (status, body) = send(fx.router.clone(), "POST", &totp_post, &auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    // The filter itself must not leak out-of-scope data either
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items?type=totp",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn sensitive_types_stay_invisible_even_for_an_all_scope_token() {
    let fx = fixture().await;
    let ssh = add_credential(
        &fx,
        fx.identity_id,
        "bastion-key",
        CredentialType::SshKey,
        CredentialData::SshKey(SshKeyData {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        }),
    )
    .await;
    let wallet = add_credential(
        &fx,
        fx.identity_id,
        "cold-wallet",
        CredentialType::CryptoWallet,
        CredentialData::Raw(vec![1, 2, 3]),
    )
    .await;
    let custom = add_credential(
        &fx,
        fx.identity_id,
        "legacy-card",
        CredentialType::Custom("card".to_string()),
        CredentialData::Raw(vec![4, 5, 6]),
    )
    .await;
    let auth = auth_header(&fx.token);

    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK);
    let titles: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, vec!["login"], "敏感类型恒不可授权：{titles:?}");
    for id in [ssh, wallet, custom] {
        let path = format!("/api/v1/connect/items/{}", id);
        let (status, body) = send(fx.router.clone(), "GET", &path, &auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{id} 泄漏");
        assert_eq!(body["error"]["code"], "not_found");
    }
}

#[tokio::test]
async fn archived_credential_leaves_the_connect_surface() {
    let fx = fixture().await;
    {
        let guard = fx.state.service.lock().await;
        let service = guard.as_ref().unwrap();
        let mut cred = service
            .get_credential(&fx.cred_id)
            .await
            .unwrap()
            .expect("fixture 条目存在");
        cred.is_active = false;
        service.update_credential(&cred).await.unwrap();
    }
    let auth = auth_header(&fx.token);
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"].as_array().unwrap().len(),
        0,
        "归档条目不进列表"
    );
    let path = format!("/api/v1/connect/items/{}", fx.cred_id);
    let (status, body) = send(fx.router.clone(), "GET", &path, &auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    let totp = format!("/api/v1/connect/items/{}/totp", fx.cred_id);
    let (status, _) = send(fx.router, "POST", &totp, &auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn totp_endpoint_serves_the_current_code_for_a_scoped_twofactor_item() {
    let fx = fixture().await;
    let totp_id = add_credential(
        &fx,
        fx.identity_id,
        "2fa",
        CredentialType::TwoFactor,
        totp_data(),
    )
    .await;
    let auth = auth_header(&fx.token);
    let path = format!("/api/v1/connect/items/{}/totp", totp_id);
    let (status, body) = send(fx.router.clone(), "POST", &path, &auth).await;
    assert_eq!(status, StatusCode::OK);
    let code = body["data"]["code"].as_str().unwrap_or_default();
    assert_eq!(code.len(), 6, "TOTP 码应为 6 位: {code:?}");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "TOTP 码必须是数字: {code:?}"
    );
    let remaining = body["data"]["remaining_seconds"].as_u64().unwrap();
    assert!((1..=30).contains(&remaining), "剩余秒越界: {remaining}");
    // Two requests within the same period return the same code (no assertion
    // near the period boundary, avoiding flakiness)
    if remaining > 5 {
        let (_, second) = send(fx.router.clone(), "POST", &path, &auth).await;
        assert_eq!(second["data"]["code"], code, "同一周期内码不该变");
    }
    // In the metadata list the item is labeled totp per the scope vocabulary
    let (status, body) = send(fx.router, "GET", "/api/v1/connect/items?type=totp", &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"][0]["type"], "totp");
}

#[tokio::test]
async fn query_and_path_filters_are_exact_and_reject_malformed_input() {
    let fx = fixture().await;
    let auth = auth_header(&fx.token);
    // Combined filters
    let q = format!(
        "/api/v1/connect/items?identity={}&type=password&title=login",
        fx.identity_id
    );
    let (status, body) = send(fx.router.clone(), "GET", &q, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    // title matches exactly (case-sensitive), not as a substring
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items?title=Log",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    // Malformed parameters: 4xx rather than 500 (DB/parsing details must not
    // become server errors)
    for path in [
        "/api/v1/connect/items?identity=not-a-uuid",
        "/api/v1/connect/items?type=bogus",
        "/api/v1/connect/items/not-a-uuid",
    ] {
        let (status, _, _) =
            send_capture(fx.router.clone(), "GET", path, &host_and_auth(&fx.token)).await;
        assert!(
            status.is_client_error() && status != StatusCode::UNAUTHORIZED,
            "{path} 应折成请求侧 4xx，实为 {status}"
        );
    }
}

/// Reading a broken row inside an endpoint -> 500 `internal` (the
/// `internal_or_locked` non-locked arm, reached at each handler's call site).
/// This is the only entry point where that arm can be driven deterministically:
/// locking the vault after the guard is a race, whereas a corrupt row is a real
/// failure (truncated vault file / half-finished key rotation).
#[tokio::test]
async fn rows_the_endpoint_cannot_read_are_500_internal_without_leaking_the_cause() {
    let fx = fixture().await;
    let totp_id = add_credential(
        &fx,
        fx.identity_id,
        "2fa",
        CredentialType::TwoFactor,
        totp_data(),
    )
    .await;
    let broken_list = add_credential(
        &fx,
        fx.identity_id,
        "junk",
        CredentialType::Password,
        password_data(),
    )
    .await;
    let auth = auth_header(&fx.token);

    // (1) Corrupt the identity row's timestamp column -> row mapping fails ->
    // the identities endpoint errors.
    fx.db
        .execute(&format!(
            "UPDATE identities SET updated_at = 'not-a-timestamp' WHERE id = '{}'",
            fx.identity_id
        ))
        .await
        .unwrap();
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/identities",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "internal");
    assert_eq!(body["error"]["message"], "internal error");

    // (2) Flip a mid-ciphertext byte (length preserved, so only AEAD
    // authentication fails) -> reading a single item errors.
    for id in [fx.cred_id, totp_id] {
        for (num, den, byte) in [(1u32, 3u32, "5a"), (2, 3, "a5")] {
            fx.db
                .execute(&format!(
                    "UPDATE credentials SET encrypted_data =                          substr(encrypted_data, 1, length(encrypted_data)*{num}/{den})                          || X'{byte}'                          || substr(encrypted_data, length(encrypted_data)*{num}/{den} + 2)                          WHERE id = '{id}'"
                ))
                .await
                .unwrap();
        }
    }
    let path = format!("/api/v1/connect/items/{}", fx.cred_id);
    let (status, body) = send(fx.router.clone(), "GET", &path, &auth).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "解密失败不能折成 404（消费者会误判条目被删）"
    );
    assert_eq!(body["error"]["code"], "internal");
    let totp_path = format!("/api/v1/connect/items/{}/totp", totp_id);
    let (status, body) = send(fx.router.clone(), "POST", &totp_path, &auth).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "internal");

    // (3) If any row in the list cannot be read, the whole list is a 500 (no
    // silently dropping items).
    fx.db
        .execute(&format!(
            "UPDATE credentials SET updated_at = 'not-a-timestamp' WHERE id = '{broken_list}'"
        ))
        .await
        .unwrap();
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "internal");

    // None of the three kinds of internal detail may reach the response body (they
    // belong only in the tracing log).
    let leaked = body.to_string().to_lowercase();
    for forbidden in [
        "decrypt",
        "invalid",
        "updated_at",
        "timestamp",
        "sql",
        "not-a",
        "credential",
        "gcm",
        "bincode",
    ] {
        assert!(
            !leaked.contains(forbidden),
            "500 响应外泄内部细节: {leaked}"
        );
    }
    // health is unaffected by DB corruption (it does not touch the DB); the
    // liveness probe must still answer.
    let (status, _) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::OK);
}

// Note: the `locked_response()` branches in the four handlers (the service slot
// becomes None after the guard checked is_unlocked but before entering the
// handler) cannot be triggered deterministically through the router -- that is a
// pure race, and it fails in the safe direction (503 rather than a 5xx leak). So
// no test is fabricated for it; instead
// `ok_err_and_locked_envelopes_match_the_documented_shape` pins
// `locked_response()`'s status code and error code directly, and the call sites
// stay as defense in depth.

#[tokio::test]
async fn unknown_routes_and_methods_404_405_after_authentication() {
    let fx = fixture().await;
    let (status, _, body) = send_capture(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/nonexistent",
        &host_and_auth(&fx.token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found", "路由未命中也走统一包络");
    let (status, headers, body) = send_capture(
        fx.router.clone(),
        "DELETE",
        "/api/v1/connect/items",
        &host_and_auth(&fx.token),
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "method_not_allowed");
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "框架 405 同样带 no-store（4xx 默认可缓存）"
    );
    // The 405 Allow header is preserved (method negotiation is useful for
    // debugging)
    assert!(
        headers.get("allow").is_some(),
        "axum 默认 405 的 Allow 头必须保留"
    );
    // health accepts GET only: the unauthenticated exemption is not a routing
    // exemption (so health does not become a catch-all); the early-return path
    // is normalized too -- being unauthenticated does not exempt it from the
    // envelope
    let (status, headers, body) = send_capture(
        fx.router.clone(),
        "POST",
        "/api/v1/connect/health",
        &[("host", "127.0.0.1:17000".to_string())],
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "method_not_allowed");
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    // The TOTP endpoint accepts POST only
    let path = format!("/api/v1/connect/items/{}/totp", fx.cred_id);
    let (status, _, body) =
        send_capture(fx.router.clone(), "GET", &path, &host_and_auth(&fx.token)).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "method_not_allowed");
}

// -------------------------------------------------------------------
// Envelope/mapping pure functions and listener lifecycle
// -------------------------------------------------------------------
