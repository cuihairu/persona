use super::*;

#[tokio::test]
async fn connect_token_requires_unlocked_vault() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let service = PersonaService::new(db).await.unwrap();
    assert!(!service.is_unlocked());

    // 锁定态管理面被拒:敏感门禁先于解锁门禁触发,按 SERVICE_LOCKED
    // 语义报认证失败(桌面据此回解锁屏);数据面的 VaultLocked/503
    // 语义由 connect_hides_archived_items_and_gates_when_locked 覆盖。
    let err = service
        .create_connect_token("t".into(), connect_read_scope(), None, None)
        .await
        .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<PersonaError>(),
        Some(PersonaError::AuthenticationFailed(_))
    ));
    assert_vault_locked_but_auth_gate_first_free(service.list_connect_tokens().await.unwrap_err());
}

#[tokio::test]
async fn connect_token_lifecycle_hash_only_storage_and_revocation() {
    let (service, db) = connect_fixture().await;

    let (presented, row) = service
        .create_connect_token("  ci runner  ".into(), connect_read_scope(), None, None)
        .await
        .unwrap();
    // 明文形态:前缀 + 32B base64url(43 字符),哈希/指纹与呈现值一致
    assert!(presented.starts_with("pconn_"));
    assert_eq!(presented.len(), "pconn_".len() + 43);
    assert_eq!(row.label, "ci runner");
    assert_eq!(row.hash, crate::connect::hash_token(&presented).unwrap());
    assert_eq!(
        row.fingerprint,
        crate::connect::fingerprint_from_hash(&row.hash)
    );
    assert!(row.last_used_at.is_none() && row.revoked_at.is_none());

    // 库里只有哈希(64 hex)与指纹,绝无呈现值明文
    let raw = sqlx::query("SELECT hash, fingerprint FROM connect_tokens")
        .fetch_all(db.pool())
        .await
        .unwrap();
    assert_eq!(raw.len(), 1);
    let stored_hash: String = raw[0].get("hash");
    assert_eq!(stored_hash, row.hash);
    assert_eq!(stored_hash.len(), 64);
    assert!(!stored_hash.contains("pconn_"));

    // 鉴权命中 + last_used 落库
    assert!(service
        .connect_authenticate(&presented)
        .await
        .unwrap()
        .is_some());
    let listed = service.list_connect_tokens().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].last_used_at.is_some());

    // 吊销即时生效;重复吊销幂等返回 false
    assert!(service.revoke_connect_token(&row.id).await.unwrap());
    assert!(!service.revoke_connect_token(&row.id).await.unwrap());
    assert!(service
        .connect_authenticate(&presented)
        .await
        .unwrap()
        .is_none());

    // 未知/畸形 token 一律 None(同形,防探测)
    assert!(service
        .connect_authenticate("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .await
        .unwrap()
        .is_none());
    assert!(service
        .connect_authenticate("garbage-without-prefix")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn connect_data_plane_filters_by_scope() {
    let (service, _db) = connect_fixture().await;
    let id_a = service
        .create_identity("A".into(), IdentityType::Personal)
        .await
        .unwrap();
    let id_b = service
        .create_identity("B".into(), IdentityType::Personal)
        .await
        .unwrap();

    let pwd = CredentialData::Password(PasswordCredentialData {
        password: "p1".into(),
        email: None,
        security_questions: vec![],
    });
    let card = CredentialData::BankCard(crate::models::credential::BankCardData {
        card_number: "4111 1111 1111 1111".into(),
        cardholder_name: "ALICE SMITH".into(),
        expiry_date: "12/29".into(),
        cvv: "123".into(),
        bank_name: "Example Bank".into(),
        card_type: "visa".into(),
    });
    let totp_data = CredentialData::TwoFactor(crate::models::credential::TwoFactorData {
        secret_key: "JBSWY3DPEHPK3PXP".into(),
        issuer: "Example".into(),
        account_name: "alice".into(),
        algorithm: "SHA1".into(),
        digits: 6,
        hotp: None,
        initial_counter: None,
        period: 30,
    });

    let cred_a = service
        .create_credential(
            id_a.id,
            "A login".into(),
            CredentialType::Password,
            SecurityLevel::High,
            &pwd,
        )
        .await
        .unwrap();
    let cred_b = service
        .create_credential(
            id_b.id,
            "B card".into(),
            CredentialType::BankCard,
            SecurityLevel::High,
            &card,
        )
        .await
        .unwrap();
    let cred_totp = service
        .create_credential(
            id_a.id,
            "A totp".into(),
            CredentialType::TwoFactor,
            SecurityLevel::Medium,
            &totp_data,
        )
        .await
        .unwrap();

    // 全量 scope:全部身份/条目可见
    let all = connect_read_scope();
    assert_eq!(
        service
            .connect_list_identities(&token_of(&all))
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        service
            .connect_list_items(&token_of(&all), None, None, None)
            .await
            .unwrap()
            .len(),
        3
    );

    // identities 限定 [A]:B 的条目不可见;显式 identity=B 参数 → 空列表(防探测)
    let only_a = ConnectTokenScope {
        identities: vec![id_a.id],
        ..connect_read_scope()
    };
    assert_eq!(
        service
            .connect_list_identities(&token_of(&only_a))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        service
            .connect_list_items(&token_of(&only_a), None, None, None)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(service
        .connect_list_items(&token_of(&only_a), Some(id_b.id), None, None)
        .await
        .unwrap()
        .is_empty());

    // item_types 限定 Password:卡与 TOTP 不在列
    let pwd_only = ConnectTokenScope {
        item_types: vec![ConnectItemType::Password],
        ..connect_read_scope()
    };
    let items = service
        .connect_list_items(&token_of(&pwd_only), None, None, None)
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, cred_a.id);

    // 单条读取:scope 外与不存在同形 None
    assert!(service
        .connect_get_item_data(&token_of(&only_a), &cred_b.id)
        .await
        .unwrap()
        .is_none());
    assert!(service
        .connect_get_item_data(&token_of(&all), &Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
    let (cred, data) = service
        .connect_get_item_data(&token_of(&all), &cred_a.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cred.id, cred_a.id);
    assert!(matches!(data, CredentialData::Password(_)));

    // TOTP:TwoFactor 项出码,密码项 None
    let code = service
        .connect_totp(&token_of(&all), &cred_totp.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code.code.len(), 6);
    assert!(service
        .connect_totp(&token_of(&all), &cred_a.id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn connect_hides_archived_items_and_gates_when_locked() {
    let (mut service, _db) = connect_fixture().await;
    let identity = service
        .create_identity("A".into(), IdentityType::Personal)
        .await
        .unwrap();
    let pwd = CredentialData::Password(PasswordCredentialData {
        password: "p1".into(),
        email: None,
        security_questions: vec![],
    });
    let cred = service
        .create_credential(
            identity.id,
            "login".into(),
            CredentialType::Password,
            SecurityLevel::High,
            &pwd,
        )
        .await
        .unwrap();
    let all = connect_read_scope();
    assert!(service
        .connect_get_item_data(&token_of(&all), &cred.id)
        .await
        .unwrap()
        .is_some());

    // 归档后对 Connect 数据面不可见
    let mut archived = service.get_credential(&cred.id).await.unwrap().unwrap();
    archived.is_active = false;
    service.update_credential(&archived).await.unwrap();
    assert!(service
        .connect_get_item_data(&token_of(&all), &cred.id)
        .await
        .unwrap()
        .is_none());
    let items = service
        .connect_list_items(&token_of(&all), None, None, None)
        .await
        .unwrap();
    assert!(items.iter().all(|c| c.id != cred.id));

    // 锁定后数据面/管理面全部 503 语义(VaultLocked)
    service.lock();
    let err = service
        .connect_get_item_data(&token_of(&all), &cred.id)
        .await
        .unwrap_err();
    assert_vault_locked(err);
    assert_vault_locked(
        service
            .connect_list_items(&token_of(&all), None, None, None)
            .await
            .unwrap_err(),
    );
    // authenticate 本身无锁定门禁:DR-4 的 503 由宿主层在鉴权之前拦截,
    // core 层的 token 验证只读 connect_tokens 表(不涉解密)。
    assert!(service
        .connect_authenticate("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .await
        .unwrap()
        .is_none());
}

/// create_connect_token 的标签防御臂：trim 后为空与超 128 字符一律拒绝。
#[tokio::test]
async fn connect_token_label_boundaries_are_rejected() {
    let (service, _db) = connect_fixture().await;

    let blank = service
        .create_connect_token("   ".into(), connect_read_scope(), None, None)
        .await
        .unwrap_err();
    assert!(blank.to_string().contains("1..=128"), "{blank}");

    let long = service
        .create_connect_token("x".repeat(129), connect_read_scope(), None, None)
        .await
        .unwrap_err();
    assert!(long.to_string().contains("1..=128"), "{long}");
}

/// 无 Read verb 的 scope：四个读端点一律空结果（同形，不泄露存在性）。
#[tokio::test]
async fn connect_endpoints_without_read_verb_return_empty() {
    let (service, _db) = connect_fixture().await;
    let no_read = ConnectTokenScope {
        identities: vec![],
        item_types: vec![],
        verbs: vec![],
    };

    assert!(service
        .connect_list_identities(&token_of(&no_read))
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .connect_list_items(&token_of(&no_read), None, None, None)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .connect_get_item_data(&token_of(&no_read), &Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
    assert!(service
        .connect_totp(&token_of(&no_read), &Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
}

/// use 动词 token（批2）：签名/出码类授权不带来读取能力——纯 use
/// scope 在四个数据面端点一律同形空/None；同 scope 加 read 即可读，
/// 证明拒绝来自动词集而非身份或类型维度。
#[tokio::test]
async fn connect_use_verb_token_cannot_read_data_plane() {
    let (service, _db) = connect_fixture().await;
    let identity = service
        .create_identity("work".into(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = service
        .create_credential(
            identity.id,
            "login".into(),
            CredentialType::Password,
            SecurityLevel::Medium,
            &CredentialData::Password(PasswordCredentialData {
                password: "pw".to_string(),
                email: None,
                security_questions: Vec::new(),
            }),
        )
        .await
        .unwrap();

    let use_only = ConnectTokenScope {
        identities: vec![identity.id],
        item_types: vec![],
        verbs: vec![ConnectVerb::Use],
    };
    assert!(
        use_only.validate().is_ok(),
        "use-only scope is a legal grant"
    );
    let token = token_of(&use_only);
    assert!(service
        .connect_list_identities(&token)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .connect_list_items(&token, None, None, None)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .connect_get_item_data(&token, &cred.id)
        .await
        .unwrap()
        .is_none());
    assert!(service
        .connect_totp(&token, &cred.id)
        .await
        .unwrap()
        .is_none());

    let read_use = ConnectTokenScope {
        verbs: vec![ConnectVerb::Read, ConnectVerb::Use],
        ..use_only.clone()
    };
    let full = token_of(&read_use);
    assert_eq!(
        service.connect_list_identities(&full).await.unwrap().len(),
        1
    );
    assert_eq!(
        service
            .connect_list_items(&full, None, None, None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(service
        .connect_get_item_data(&full, &cred.id)
        .await
        .unwrap()
        .is_some());
}

/// unknown:{指纹} 节流表有界（audit 批2 #7）：每个随机伪造 token 的指纹
/// 都不同，无上限时可被反复携带随机 token 的请求无界撑大内存。超限后
/// 新 key 丢弃（false = 不写审计），表长封顶；窗口内已有 key 的节流
/// 语义不受洪水影响。
#[tokio::test]
async fn connect_throttle_marks_table_is_bounded() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let service = PersonaService::new(db).await.unwrap();
    let max = PersonaService::CONNECT_THROTTLE_MARKS_MAX;

    for i in 0..max {
        assert!(
            service.connect_throttle_should_write(&format!("unknown:fill-{i}")),
            "cap 内的 key 都应放行写入"
        );
    }
    assert_eq!(
        service.connect_audit_marks.lock().unwrap().len(),
        max,
        "表长恰好到上限"
    );

    // 洪水期新 key 被丢弃，表长不再增长。
    assert!(!service.connect_throttle_should_write("unknown:overflow"));
    assert!(!service.connect_throttle_should_write(&format!("unknown:fill-{max}")));
    assert_eq!(service.connect_audit_marks.lock().unwrap().len(), max);

    // 窗口内已有 key 维持节流（false，不重写不扩容）。
    assert!(!service.connect_throttle_should_write("unknown:fill-0"));
}

/// 过期与主体绑定（迁移 019）：未到期 token 鉴权放行；已过期的
/// 同形拒绝（与吊销同形）并记失败审计。创建期拒绝过去时刻。
#[tokio::test]
async fn connect_authenticate_rejects_expired_token() {
    let (service, db) = connect_fixture().await;

    let (presented, row) = service
        .create_connect_token(
            "valid".into(),
            connect_read_scope(),
            Some("browser-extension".into()),
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .await
        .unwrap();
    assert_eq!(row.principal.as_deref(), Some("browser-extension"));
    assert!(service
        .connect_authenticate(&presented)
        .await
        .unwrap()
        .is_some());

    // 创建期：过去/现在时刻直接拒绝。
    let past = service
        .create_connect_token(
            "past".into(),
            connect_read_scope(),
            None,
            Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
        )
        .await
        .unwrap_err();
    assert!(past.to_string().contains("expiry must be in the future"));

    // 运行中过期：直接落库为过去时刻，authenticate 拒绝并节流记审计。
    let (stale, stale_row) = service
        .create_connect_token(
            "stale".into(),
            connect_read_scope(),
            None,
            Some(chrono::Utc::now() + chrono::Duration::seconds(60)),
        )
        .await
        .unwrap();
    sqlx::query("UPDATE connect_tokens SET expires_at = ? WHERE id = ?")
        .bind((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339())
        .bind(stale_row.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    assert!(service
        .connect_authenticate(&stale)
        .await
        .unwrap()
        .is_none());

    let audit_repo = AuditLogRepository::new(db);
    let used = audit_repo
        .find_by_action(&AuditAction::ConnectTokenUsed)
        .await
        .unwrap();
    assert!(
        used.iter().any(|a| !a.success
            && a.error_message
                .as_deref()
                .is_some_and(|m| m.contains("expired"))),
        "expiry denial must be audited: {used:?}"
    );
}

/// scope 拒绝写审计（架构校正批2）：此前 scope 拒绝零审计。scope 外
/// 的单条读取返回 None（防探测）同时记一条 UnauthorizedAccess。
#[tokio::test]
async fn connect_scope_denial_writes_unauthorized_access_audit() {
    let (service, db) = connect_fixture().await;
    let id_a = service
        .create_identity("A".into(), IdentityType::Personal)
        .await
        .unwrap();
    let id_b = service
        .create_identity("B".into(), IdentityType::Personal)
        .await
        .unwrap();
    let cred_b = service
        .create_credential(
            id_b.id,
            "B login".into(),
            CredentialType::Password,
            SecurityLevel::Medium,
            &CredentialData::Password(PasswordCredentialData {
                password: "pw".to_string(),
                email: None,
                security_questions: Vec::new(),
            }),
        )
        .await
        .unwrap();

    let mut scope = connect_read_scope();
    scope.identities = vec![id_a.id];
    let token = token_of(&scope);

    // 越 scope 的单条读取：None + 恰好一条 UnauthorizedAccess。
    assert!(service
        .connect_get_item_data(&token, &cred_b.id)
        .await
        .unwrap()
        .is_none());
    let audit_repo = AuditLogRepository::new(db);
    let denials = audit_repo
        .find_by_action(&AuditAction::UnauthorizedAccess)
        .await
        .unwrap();
    assert_eq!(denials.len(), 1, "exactly one scope denial audited");
    assert!(!denials[0].success);
    assert!(
        denials[0]
            .error_message
            .as_deref()
            .is_some_and(|m| m.contains("outside scope")),
        "denial audit must name the reject point: {:?}",
        denials[0].error_message
    );

    // scope 内读取不写拒绝审计。
    assert!(service
        .connect_get_item_data(&token_of(&connect_read_scope()), &cred_b.id)
        .await
        .unwrap()
        .is_some());
    let after = audit_repo
        .find_by_action(&AuditAction::UnauthorizedAccess)
        .await
        .unwrap();
    assert_eq!(after.len(), 1, "granted read must not add a denial audit");
}

/// connect_totp 的 scope/存在性防御臂：未知 id、scope 外身份、
/// 未授权 Totp 条目类型一律 None（与列表 404 同形）。
#[tokio::test]
async fn connect_totp_gates_unknown_identity_and_unscoped_type() {
    let (service, _db) = connect_fixture().await;
    let id_a = service
        .create_identity("A".into(), IdentityType::Personal)
        .await
        .unwrap();
    let totp_data = CredentialData::TwoFactor(crate::models::credential::TwoFactorData {
        secret_key: "JBSWY3DPEHPK3PXP".into(),
        issuer: "Example".into(),
        account_name: "alice".into(),
        algorithm: "SHA1".into(),
        digits: 6,
        hotp: None,
        initial_counter: None,
        period: 30,
    });
    let cred = service
        .create_credential(
            id_a.id,
            "A totp".into(),
            CredentialType::TwoFactor,
            SecurityLevel::Medium,
            &totp_data,
        )
        .await
        .unwrap();

    // 未知 id → None
    assert!(service
        .connect_totp(&token_of(&connect_read_scope()), &Uuid::new_v4())
        .await
        .unwrap()
        .is_none());

    // scope 限定到别的身份 → None（防探测同形）
    let other_only = ConnectTokenScope {
        identities: vec![Uuid::new_v4()],
        ..connect_read_scope()
    };
    assert!(service
        .connect_totp(&token_of(&other_only), &cred.id)
        .await
        .unwrap()
        .is_none());

    // item_types 未授权 Totp → None
    let no_totp = ConnectTokenScope {
        item_types: vec![ConnectItemType::Password],
        ..connect_read_scope()
    };
    assert!(service
        .connect_totp(&token_of(&no_totp), &cred.id)
        .await
        .unwrap()
        .is_none());
}

/// list_items 的 item_type 过滤分支：显式条目类型只回同型条目。
#[tokio::test]
async fn connect_list_items_filters_by_item_type() {
    let (service, _db) = connect_fixture().await;
    let id_a = service
        .create_identity("A".into(), IdentityType::Personal)
        .await
        .unwrap();
    let pwd = CredentialData::Password(PasswordCredentialData {
        password: "p1".into(),
        email: None,
        security_questions: vec![],
    });
    let card = CredentialData::BankCard(crate::models::credential::BankCardData {
        card_number: "4111 1111 1111 1111".into(),
        cardholder_name: "ALICE SMITH".into(),
        expiry_date: "12/29".into(),
        cvv: "123".into(),
        bank_name: "Example Bank".into(),
        card_type: "visa".into(),
    });
    service
        .create_credential(
            id_a.id,
            "A login".into(),
            CredentialType::Password,
            SecurityLevel::High,
            &pwd,
        )
        .await
        .unwrap();
    service
        .create_credential(
            id_a.id,
            "A card".into(),
            CredentialType::BankCard,
            SecurityLevel::High,
            &card,
        )
        .await
        .unwrap();

    let logins = service
        .connect_list_items(
            &token_of(&connect_read_scope()),
            None,
            Some(ConnectItemType::Password),
            None,
        )
        .await
        .unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].credential_type, CredentialType::Password);
}
