use super::*;

#[test]
fn is_vault_locked_walks_the_whole_cause_chain() {
    let direct: anyhow::Error = PersonaError::VaultLocked("locked".to_string()).into();
    assert!(is_vault_locked(&direct));
    let nested = direct.context("connect endpoint").context("outer wrap");
    assert!(is_vault_locked(&nested), "锁定态可能被多层 context 包住");
    assert!(!is_vault_locked(&anyhow::Error::from(
        PersonaError::Database("no such table".to_string())
    )));
    assert!(!is_vault_locked(&anyhow::anyhow!("plain failure")));
}

#[tokio::test]
async fn internal_or_locked_maps_locked_to_503_and_other_errors_to_500() {
    // 这两个臂经路由不可达：guard 已在鉴权后查过 is_unlocked，鉴权自身
    // 失败又是另一个 500。作为纵深防御保留，故直调纯函数覆盖。
    let locked = anyhow::Error::from(PersonaError::VaultLocked("vault locked".to_string()))
        .context("connect endpoint");
    let (status, body) = response_parts(internal_or_locked(&locked)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "vault_locked");

    let boom = anyhow::anyhow!("sqlite PoolClosed: /home/user/.persona/vault.db");
    let (status, body) = response_parts(internal_or_locked(&boom)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "internal");
    assert_eq!(body["error"]["message"], "internal error");
    let leaked = body.to_string().to_lowercase();
    for forbidden in ["sqlite", "poolclosed", "vault.db", "/home/"] {
        assert!(!leaked.contains(forbidden), "内部错误文本外泄: {leaked}");
    }
}

#[tokio::test]
async fn ok_err_and_locked_envelopes_match_the_documented_shape() {
    let response = ok_json(json!({ "x": 1 }));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        body_json(response).await,
        json!({ "ok": true, "data": { "x": 1 } })
    );

    let response = err_json(StatusCode::NOT_FOUND, "not_found", "item not found");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(response).await,
        json!({ "ok": false, "error": { "code": "not_found", "message": "item not found" } })
    );

    let (status, body) = response_parts(locked_response()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "vault_locked");
}

#[tokio::test]
async fn item_type_slug_is_the_scope_vocabulary_with_a_null_floor() {
    let fx = fixture().await;
    let base = {
        let guard = fx.state.service.lock().await;
        guard
            .as_ref()
            .unwrap()
            .get_credential(&fx.cred_id)
            .await
            .unwrap()
            .unwrap()
    };
    let mut cred = base.clone();
    cred.credential_type = CredentialType::Password;
    assert_eq!(item_type_slug(&cred), json!("password"));
    cred.credential_type = CredentialType::TwoFactor;
    assert_eq!(item_type_slug(&cred), json!("totp"));
    cred.credential_type = CredentialType::SecureNote;
    assert_eq!(item_type_slug(&cred), json!("note"));
    // 不可映射类型走 null 兜底（scope 过滤已挡住，这里防的是将来漏过滤）
    for ty in [
        CredentialType::SshKey,
        CredentialType::CryptoWallet,
        CredentialType::Custom("card".to_string()),
    ] {
        cred.credential_type = ty.clone();
        assert_eq!(item_type_slug(&cred), serde_json::Value::Null, "{ty:?}");
    }

    let meta = item_meta_json(&base);
    assert_eq!(meta["id"], fx.cred_id.to_string());
    assert_eq!(meta["title"], "login");
    assert_eq!(meta["type"], "password");
    assert_eq!(
        meta["urls"].as_array().unwrap().len(),
        0,
        "无 url 时 urls 仍是数组（不是 null），消费者可无脑迭代"
    );
    assert_eq!(meta["updated_at"], json!(base.updated_at.to_rfc3339()));
    let mut with_url = base.clone();
    with_url.url = Some("https://example.com".to_string());
    assert_eq!(
        item_meta_json(&with_url)["urls"],
        json!(["https://example.com"])
    );
}
