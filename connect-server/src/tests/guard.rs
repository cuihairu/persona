use super::*;

#[tokio::test]
async fn health_is_unauthenticated_and_free_of_vault_info() {
    let fx = fixture().await;
    let (status, body) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["service"], "persona-connect");
    // 零库信息:无条目数/身份名/锁定状态之外的字段
    assert!(body["data"].get("items").is_none());
}

#[tokio::test]
async fn missing_malformed_and_unknown_tokens_are_401_same_shape() {
    let fx = fixture().await;
    // 缺失
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
    // 畸形(非 Bearer)
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items",
        &[("authorization", "Basic dXNlcjpwYXNz".to_string())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
    // pconn_ 前缀假值(与缺失同形)
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

    // title 精确过滤
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
    // 全字段含解密 data(明文密码在响应体内——消费者责任,文档警示)。
    // data 是 CredentialData 原生 serde 形状:外部标签枚举
    // {"Password": {…}}(变体名 PascalCase)。
    assert_eq!(body["data"]["data"]["Password"]["password"], "secret");

    // 不存在的条目 → 404 同形
    let missing = format!("/api/v1/connect/items/{}", Uuid::new_v4());
    let (status, body) = send(fx.router.clone(), "GET", &missing, &auth).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    // TOTP 对非 TwoFactor 条目 → 404 同形
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

/// 过期 token（批2 迁移 019）：与吊销同形 401——自动化调用方不能
/// 仅凭 token 明文读数据，过期与吊销同等失效（不泄漏二者差异）。
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

/// 纯 use 动词 token（批2）：签名/出码类授权不带来读取能力——数据面
/// 端点一律同形空列表或 404（不泄漏存在性）；同 scope 加 read 即可读，
/// 证明拒绝来自动词集而非身份或类型维度。
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

    // 单条读取：use token 404 同形（不泄漏存在性）。
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
    // 锁定期间反复请求都是 503 vault_locked
    for _ in 0..5 {
        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "vault_locked");
    }
    // 解锁恢复（lock() 清了内存密钥，用盐重新解锁）：锁定期间的请求
    // 不消耗限额——完整 120 次仍可用
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
    // health 免认证也不占 token 限额:任意多次后数据面仍全额可用
    for _ in 0..RATE_LIMIT_PER_MINUTE {
        let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/health", &[]).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = send(fx.router, "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK);
}

// -------------------------------------------------------------------
// 防线顺序与响应卫生
// -------------------------------------------------------------------

#[tokio::test]
async fn every_response_carries_no_store_and_json_content_type() {
    let fx = fixture().await;
    // 成功、数据面、以及**错误**响应都必须带 no-store：TOTP 码/字段明文
    // 一旦进了中间缓存就不该再指望 2xx 那侧记得带头。
    // 只覆盖**我们生成的**响应。提取器拒绝/路由未命中走 axum 默认响应
    // （无包络、无 no-store），形状在
    // `unknown_routes_...`/`query_and_path_filters_...` 里单独钉住。
    let missing = Uuid::new_v4().to_string();
    // 第三元 = 是否带合法 token（不带即 401，也是我们的包络）。
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
    // health 免认证，但不免 Host 白名单——防线 1 在所有例外之前。
    // send_capture 不补 Host → 这条请求根本没有 Host 头。
    let (status, _, body) =
        send_capture(fx.router.clone(), "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(body["error"]["code"], "bad_host");
}

#[tokio::test]
async fn lookalike_hosts_are_421_and_never_treated_as_loopback() {
    let fx = fixture().await;
    // 全部带合法 token：证明拒绝来自 Host 而不是缺认证。前缀/后缀拼是
    // DNS rebinding 之外的典型误放行点（`starts_with("127.0.0.1")` 会放过
    // 127.0.0.1.evil.com）。
    for host in [
        "127.0.0.1.evil.com",
        "127.0.0.1.evil.com:17000",
        "localhost.evil.com",
        "evil-localhost",
        "notlocal",
        "",
        "127.0.0.2",
        // IPv6 字面量在 authority 里必须带方括号（RFC 9110 §4.1.2）；
        // 裸 "::1" 缺括号形式非法，按 ':' 切端口后剩空串 → 拒绝。
        // （括号形式 "[::1]"/"[::1]:port" 的放行见 alias 测试。）
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
    // 不带 token → 401 而不是 421，即 Host 这关已经过了（端口与 IPv6
    // 方括号形式都必须剥掉再比对）。
    for host in [
        "127.0.0.1",
        "127.0.0.1:17000",
        "localhost",
        "localhost:17000",
        "[::1]:17000",
        // 省略端口的括号 IPv6（段尾 ']'）：不能按 ':' 切端口，否则
        // "[::1]" 剩 "[::" 被误拒——白名单写着 ::1 就该放行
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
    // 防线 2 先于 health 例外：带 Origin 的 /health 是 403，不是免检 200。
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/health",
        &[("origin", "http://localhost:3000".to_string())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "origin_forbidden");
    // 防线 1 先于防线 2：坏 Host + Origin 报 bad_host（421）而非 403。
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
    // 防线 3 先于路由：不存在的路径未认证时是 401，不泄露路由表。
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
        // message 只有两类：格式不合法（缺/畸形）与查无此 token。既不
        // 泄露「token 存在但被吊销」，也不区分大小写笔误的 scheme。
        let msg = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg == "missing or malformed bearer token" || msg == "invalid token",
            "value={value:?} message={msg:?}"
        );
    }
}

#[tokio::test]
async fn empty_service_slot_is_503_vault_locked_while_health_stays_up() {
    // 宿主尚未初始化库（service 槽位 None）：数据面按锁定语义处理，
    // health 仍可用（存活探测不该被库状态拖成 5xx）。
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
    // 没有 token 行可记账 → 限额表必须保持空（否则探测能占满内存）
    assert!(state.rates.lock().unwrap().is_empty());
}

#[tokio::test]
async fn database_failure_is_500_and_leaks_nothing_from_the_cause() {
    let fx = fixture().await;
    let auth = auth_header(&fx.token);
    let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::OK, "失败注入前数据面可用");

    fx.db.pool().close().await;

    // 鉴权自身查库失败走 guard 的 500 分支——是 internal 不是 401，
    // 否则 DB 抖动会被消费者当成 token 失效去重签。
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
    // 同一条 DB 故障路径下 health 仍 200（免鉴权、不落库）。
    let (status, _) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::OK);
}

// -------------------------------------------------------------------
// 限额：固定窗语义
// -------------------------------------------------------------------
