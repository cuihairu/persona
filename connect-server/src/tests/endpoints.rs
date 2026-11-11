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

    // scope 外条目 = 与不存在同形的 404（不区分 403，防探测）
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

    // 显式请求 scope 外的身份：200 空列表，而不是 403/404
    let query = format!("/api/v1/connect/items?identity={other}");
    let (status, body) = send(fx.router.clone(), "GET", &query, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    let query = format!("/api/v1/connect/items?identity={}", fx.identity_id);
    let (status, body) = send(fx.router.clone(), "GET", &query, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    // 身份列表同样按 scope 收敛
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/identities",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);

    // 对照组：全 scope token 两条身份都看得见
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
    // 过滤器本身也不给越权数据
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
    // 同一周期内两次取码相同（周期边界附近不做断言，避免抖动）
    if remaining > 5 {
        let (_, second) = send(fx.router.clone(), "POST", &path, &auth).await;
        assert_eq!(second["data"]["code"], code, "同一周期内码不该变");
    }
    // 元数据列表里该条目按 scope 词汇表标成 totp
    let (status, body) = send(fx.router, "GET", "/api/v1/connect/items?type=totp", &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"][0]["type"], "totp");
}

#[tokio::test]
async fn query_and_path_filters_are_exact_and_reject_malformed_input() {
    let fx = fixture().await;
    let auth = auth_header(&fx.token);
    // 组合过滤
    let q = format!(
        "/api/v1/connect/items?identity={}&type=password&title=login",
        fx.identity_id
    );
    let (status, body) = send(fx.router.clone(), "GET", &q, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    // title 是精确匹配（大小写敏感），不是子串
    let (status, body) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items?title=Log",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    // 畸形参数：4xx 而不是 500（不能把库/解析细节变成服务器错误）
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

/// 端点内读到坏行 → 500 `internal`（`internal_or_locked` 的非锁定臂在
/// 各 handler 的调用点）。这是那条臂唯一能确定性驱动的入口：guard 之后
/// 再锁库是竞态，而损坏的行是真实故障（vault 文件被截断/密钥轮换半途）。
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

    // ① 身份行的时间戳列坏掉 → 行映射失败 → identities 端点 Err。
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

    // ② 密文中间字节翻掉（长度不变，只让 AEAD 校验失败）→ 单条读取 Err。
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

    // ③ 列表里任一行读不出来 → 整个列表 500（不静默丢条目）。
    fx.db
        .execute(&format!(
            "UPDATE credentials SET updated_at = 'not-a-timestamp' WHERE id = '{broken_list}'"
        ))
        .await
        .unwrap();
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "internal");

    // 三类内部细节都不许进响应体（只进 tracing 日志）。
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
    // health 不受库损坏影响（不落库），存活探测必须还活着。
    let (status, _) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
    assert_eq!(status, StatusCode::OK);
}

// 说明：四个 handler 里的 `locked_response()` 分支（service 槽位在 guard
// 查过 is_unlocked 之后、进 handler 之前变成 None）经路由不可确定性触发
// ——那是纯竞态，且方向安全（503 而非 5xx 泄漏）。故不为其伪造测试，改由
// `ok_err_and_locked_envelopes_match_the_documented_shape` 直接钉住
// `locked_response()` 的状态码与错误码，调用点保持纵深防御原样。

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
    // 405 的 Allow 头保留（方法协商对调试有价值）
    assert!(
        headers.get("allow").is_some(),
        "axum 默认 405 的 Allow 头必须保留"
    );
    // health 只认 GET：免认证例外不是免路由（防止 health 变成通配口）；
    // 早退路径同样经归一化——免认证不豁免包络
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
    // TOTP 端点只认 POST
    let path = format!("/api/v1/connect/items/{}/totp", fx.cred_id);
    let (status, _, body) =
        send_capture(fx.router.clone(), "GET", &path, &host_and_auth(&fx.token)).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "method_not_allowed");
}

// -------------------------------------------------------------------
// 包络/映射纯函数与 listener 生命周期
// -------------------------------------------------------------------
