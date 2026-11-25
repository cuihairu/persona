use super::*;

#[tokio::test]
async fn health_is_unauthenticated_and_free_of_vault_info() {
    let fx = fixture().await;
    let (status, body) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["service"], "persona-connect");
    // Zero vault information: no fields beyond item counts/identity names/lock state
    assert!(body["data"].get("items").is_none());
}

#[tokio::test]
async fn missing_malformed_and_unknown_tokens_are_401_same_shape() {
    let fx = fixture().await;
    // Missing
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
    // Malformed (not Bearer)
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items",
        &[("authorization", "Basic dXNlcjpwYXNz".to_string())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
    // pconn_ -prefixed bogus value (same shape as missing)
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items",
        &auth_header("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn foreign_host_is_421_even_with_valid_token() {
    let fx = fixture().await;
    let builder = HttpRequest::builder()
        .method("GET")
        .uri("/api/v1/connect/items")
        .header("host", "evil.example.com")
        .header("authorization", format!("Bearer {}", fx.token));
    let req = builder.body(Body::empty()).unwrap();
    let response = fx.router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn origin_header_is_403_even_with_valid_token() {
    let fx = fixture().await;
    let (status, body) = send(
        fx.router,
        "GET",
        "/api/v1/connect/items",
        &[
            ("origin", "https://evil.example.com".to_string()),
            ("authorization", format!("Bearer {}", fx.token)),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "origin_forbidden");
}

#[tokio::test]
async fn data_plane_serves_envelope_for_all_endpoints() {
    let fx = fixture().await;
    let auth = auth_header(&fx.token);

    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/identities",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"][0]["name"], "work");

    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"][0]["id"], fx.cred_id.to_string());
    assert_eq!(body["data"][0]["title"], "login");
    assert_eq!(body["data"][0]["type"], "password");

    // Exact title filter
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items?title=login",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items?title=nope",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);

    let path = format!("/api/v1/connect/items/{}", fx.cred_id);
    let (status, body) = send(fx.router.clone(), "GET", &path, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["title"], "login");
    // Full fields include decrypted data (the plaintext password sits in the
    // response body -- the consumer's responsibility, documented as a warning).
    // data is CredentialData's native serde shape: an externally tagged enum
    // {"Password": {...}} (variant names in PascalCase).
    assert_eq!(body["data"]["data"]["Password"]["password"], "secret");

    // Nonexistent item -> the same-shaped 404
    let missing = format!("/api/v1/connect/items/{}", Uuid::new_v4());
    let (status, body) = send(fx.router.clone(), "GET", &missing, &auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    // TOTP against a non-TwoFactor item -> the same-shaped 404
    let totp_path = format!("/api/v1/connect/items/{}/totp", fx.cred_id);
    let (status, body) = send(fx.router, "POST", &totp_path, &auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn revoked_token_is_401_immediately() {
    let fx = fixture().await;
    {
        let guard = fx.state.service.lock().await;
        guard
            .as_ref()
            .unwrap()
            .revoke_connect_token(&fx.token_row_id)
            .await
            .unwrap();
    }
    let (status, body) = send(
        fx.router,
        "GET",
        "/api/v1/connect/items",
        &auth_header(&fx.token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

/// Expired token (batch 2 migration 019): a 401 shaped like revocation --
/// an automated caller must not be able to read data from token plaintext
/// alone; expiry revokes access just like revocation does (the difference
/// between the two is never leaked).
#[tokio::test]
async fn expired_token_is_401_same_shape_as_revoked() {
    let fx = fixture().await;
    sqlx::query("UPDATE connect_tokens SET expires_at = ? WHERE id = ?")
        .bind((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339())
        .bind(fx.token_row_id.to_string())
        .execute(fx.db.pool())
        .await
        .unwrap();

    let (status, body) = send(
        fx.router,
        "GET",
        "/api/v1/connect/items",
        &auth_header(&fx.token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

/// A pure use-verb token (batch 2): signing/code-emitting style authorization
/// confers no read capability -- data-plane endpoints uniformly return
/// same-shaped empty lists or 404s (no existence leak); adding read to the same
/// scope makes it readable, proving the rejection comes from the verb set, not
/// the identity or type dimension.
#[tokio::test]
async fn use_only_token_reads_nothing_on_any_endpoint() {
    let fx = fixture().await;
    let use_scope = ConnectTokenScope {
        identities: vec![],
        item_types: vec![],
        verbs: vec![ConnectVerb::Use],
    };
    let use_token = mint_token(&fx, "use-only", use_scope.clone()).await;
    let read_use_token = mint_token(
        &fx,
        "read-use",
        ConnectTokenScope {
            verbs: vec![ConnectVerb::Read, ConnectVerb::Use],
            ..use_scope
        },
    )
    .await;
    let use_auth = auth_header(&use_token);
    let read_auth = auth_header(&read_use_token);

    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/identities",
        &use_auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["data"].as_array().unwrap().is_empty(),
        "use token 不得读身份列表"
    );
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/identities",
        &read_auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1, "read+use 可读");

    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &use_auth).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["data"].as_array().unwrap().is_empty(),
        "use token 不得读条目列表"
    );

    // Single item read: a use token gets the same-shaped 404 (no existence leak).
    let path = format!("/api/v1/connect/items/{}", fx.cred_id);
    let (status, body) = send(fx.router.clone(), "GET", &path, &use_auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "use token 不得读单条");
    assert_eq!(body["error"]["code"], "not_found");
    let (status, _) = send(fx.router, "GET", &path, &read_auth).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn locked_vault_is_503_and_does_not_consume_rate() {
    let fx = fixture().await;
    {
        let mut guard = fx.state.service.lock().await;
        guard.as_mut().unwrap().lock();
    }
    let auth = auth_header(&fx.token);
    // While locked, repeated requests all get 503 vault_locked
    for _ in 0..5 {
        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "vault_locked");
    }
    // Recovery by unlocking (lock() cleared the in-memory key; re-unlock with the
    // salt): requests made while locked do not consume quota -- the full 120
    // requests are still available
    {
        let mut guard = fx.state.service.lock().await;
        guard
            .as_mut()
            .unwrap()
            .unlock("test_password", &fx.salt)
            .unwrap();
    }
    for _ in 0..RATE_LIMIT_PER_MINUTE {
        let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, body) = send(fx.router, "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn health_does_not_consume_rate_limit() {
    let fx = fixture().await;
    let auth = auth_header(&fx.token);
    // health is unauthenticated and consumes no token quota either: after any number
    // of requests the data plane is still at full capacity
    for _ in 0..RATE_LIMIT_PER_MINUTE {
        let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/health", &[]).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = send(fx.router, "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK);
}

// -------------------------------------------------------------------
// Line-of-defense ordering and response hygiene
// -------------------------------------------------------------------

#[tokio::test]
async fn every_response_carries_no_store_and_json_content_type() {
    let fx = fixture().await;
    // Success, data-plane, and **error** responses must all carry no-store: once
    // a TOTP code / field plaintext has reached an intermediate cache, we cannot
    // rely on the 2xx side remembering to send the header.
    // This only covers **responses we generate**. Extractor rejections and
    // unmatched routes fall through to axum's default response (no envelope, no
    // no-store); their shape is pinned separately in
    // `unknown_routes_...`/`query_and_path_filters_...`.
    let missing = Uuid::new_v4().to_string();
    // Third element = whether a valid token is sent (no token means 401, which is
    // also our envelope).
    type Case = (&'static str, String, bool);
    let cases: Vec<Case> = vec![
        ("GET", "/api/v1/connect/health".to_string(), false),
        ("GET", "/api/v1/connect/items".to_string(), true),
        ("GET", "/api/v1/connect/items".to_string(), false),
        ("GET", format!("/api/v1/connect/items/{missing}"), true),
        (
            "POST",
            format!("/api/v1/connect/items/{missing}/totp"),
            true,
        ),
    ];
    for (method, path, with_auth) in cases {
        let mut all: Vec<(&str, String)> = vec![("host", "127.0.0.1:17000".to_string())];
        if with_auth {
            all.extend(auth_header(&fx.token));
        }
        let (status, resp_headers, _) = send_capture(fx.router.clone(), method, &path, &all).await;
        let cache = resp_headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(cache, "no-store", "{method} {path} → {status} 缺 no-store");
        let ctype = resp_headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ctype.starts_with("application/json"),
            "{method} {path} → {status} content-type 应为 JSON，实为 {ctype:?}"
        );
    }
}

#[tokio::test]
async fn absent_host_header_is_421_even_for_health() {
    let fx = fixture().await;
    // health is unauthenticated but not exempt from the Host allowlist -- line of
    // defense 1 comes before every exemption.
    // send_capture does not fill in Host -> this request has no Host header at all.
    let (status, _, body) =
        send_capture(fx.router.clone(), "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(body["error"]["code"], "bad_host");
}

#[tokio::test]
async fn lookalike_hosts_are_421_and_never_treated_as_loopback() {
    let fx = fixture().await;
    // All carry a valid token: this proves the rejection comes from Host rather
    // than from missing authentication. Prefix/suffix splicing is the classic
    // wrongful-allow point besides DNS rebinding (`starts_with("127.0.0.1")`
    // would let 127.0.0.1.evil.com through).
    for host in [
        "127.0.0.1.evil.com",
        "127.0.0.1.evil.com:17000",
        "localhost.evil.com",
        "evil-localhost",
        "notlocal",
        "",
        "127.0.0.2",
        // IPv6 literals in the authority must be bracketed (RFC 9110 §4.1.2);
        // a bare "::1" is invalid in its bracketless form, and after port
        // splitting on ':' an empty string remains -> rejected.
        // (Bracketed forms "[::1]"/"[::1]:port" being allowed are covered by
        // the alias test.)
        "::1",
    ] {
        let (status, _, body) = send_capture(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items",
            &[
                ("host", host.to_string()),
                ("authorization", format!("Bearer {}", fx.token)),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST, "host={host:?}");
        assert_eq!(body["error"]["code"], "bad_host", "host={host:?}");
    }
}

#[tokio::test]
async fn loopback_host_aliases_pass_the_host_guard() {
    let fx = fixture().await;
    // No token -> 401 rather than 421, i.e. the Host gate already passed (both the
    // port and the IPv6 bracket form must be stripped before comparing).
    for host in [
        "127.0.0.1",
        "127.0.0.1:17000",
        "localhost",
        "localhost:17000",
        "[::1]:17000",
        // Bracketed IPv6 with an omitted port (trailing ']'): cannot split the port
        // on ':', otherwise "[::1]" is left as "[::" and wrongly rejected -- the
        // allowlist says ::1, so it must be allowed through
        "[::1]",
    ] {
        let (status, _, body) = send_capture(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items",
            &[("host", host.to_string())],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "host={host:?}");
        assert_eq!(body["error"]["code"], "unauthorized", "host={host:?}");
    }
}

#[tokio::test]
async fn defenses_are_ordered_host_then_origin_then_auth_then_health() {
    let fx = fixture().await;
    // Line of defense 2 comes before the health exemption: /health with an Origin
    // is a 403, not an unexamined 200.
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/health",
        &[("origin", "http://localhost:3000".to_string())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "origin_forbidden");
    // Line of defense 1 comes before line of defense 2: bad Host + Origin reports
    // bad_host (421) rather than 403.
    let (status, _, body) = send_capture(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/health",
        &[
            ("host", "evil.example.com".to_string()),
            ("origin", "http://localhost:3000".to_string()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(body["error"]["code"], "bad_host");
    // Line of defense 3 comes before routing: an unknown path while unauthenticated
    // is a 401, so the route table is never leaked.
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/nonexistent", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn empty_and_non_bearer_credentials_are_401_shaped_like_unknown_tokens() {
    let fx = fixture().await;
    for value in [
        "Bearer ",
        "Bearer    ",
        "Bearer",
        "bearer pconn_abc",
        "Token pconn_abc",
        "pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items",
            &[("authorization", value.to_string())],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "value={value:?}");
        assert_eq!(body["error"]["code"], "unauthorized", "value={value:?}");
        // The message has only two variants: malformed (missing/malformed) and no such
        // token. Neither reveals "this token exists but was revoked", nor does it
        // distinguish a case-typo'd scheme.
        let msg = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg == "missing or malformed bearer token" || msg == "invalid token",
            "value={value:?} message={msg:?}"
        );
    }
}

#[tokio::test]
async fn empty_service_slot_is_503_vault_locked_while_health_stays_up() {
    // The host has not initialized the DB (service slot None): the data plane is
    // handled with locked semantics, and health stays available (a liveness probe
    // should not be dragged into a 5xx by DB state).
    let state = ConnectServerState::new(Arc::new(TokioMutex::new(None)));
    let router = build_router(state.clone());
    let (status, body) = send(
        router.clone(),
        "GET",
        "/api/v1/connect/items",
        &auth_header("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "vault_locked");
    let (status, body) = send(router, "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["service"], "persona-connect");
    // No token row to account for -> the rate table must stay empty (otherwise a
    // probe could exhaust memory)
    assert!(state.rates.lock().unwrap().is_empty());
}

#[tokio::test]
async fn database_failure_is_500_and_leaks_nothing_from_the_cause() {
    let fx = fixture().await;
    let auth = auth_header(&fx.token);
    let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK, "失败注入前数据面可用");

    fx.db.pool().close().await;

    // An authentication DB lookup failure goes through the guard's 500 branch --
    // internal, not 401; otherwise a DB wobble would be read as token expiry and
    // trigger a re-mint by the consumer.
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "internal");
    assert_eq!(body["error"]["message"], "authentication failed");
    let leaked = body.to_string().to_lowercase();
    for forbidden in ["sqlx", "sqlite", "pool", "closed", "memory"] {
        assert!(
            !leaked.contains(forbidden),
            "500 响应外泄了内部细节: {leaked}"
        );
    }
    // Under the same DB failure path health still returns 200 (unauthenticated,
    // does not touch the DB).
    let (status, _) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::OK);
}

// -------------------------------------------------------------------
// Rate limit: fixed-window semantics
// -------------------------------------------------------------------
