use super::*;

#[tokio::test]
async fn connect_token_requires_unlocked_vault() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let service = PersonaService::new(db).await.unwrap();
    assert!(!service.is_unlocked());

    // A locked vault rejects the admin surface: the sensitive gate fires before the unlock gate and
    // reports an authentication failure per the SERVICE_LOCKED semantics (the desktop returns to the
    // unlock screen on this); the data plane's VaultLocked/503 semantics are covered by
    // connect_hides_archived_items_and_gates_when_locked.
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
    // Plaintext shape: prefix + 32B base64url (43 chars); the hash/fingerprint match the presented value
    assert!(presented.starts_with("pconn_"));
    assert_eq!(presented.len(), "pconn_".len() + 43);
    assert_eq!(row.label, "ci runner");
    assert_eq!(row.hash, crate::connect::hash_token(&presented).unwrap());
    assert_eq!(
        row.fingerprint,
        crate::connect::fingerprint_from_hash(&row.hash)
    );
    assert!(row.last_used_at.is_none() && row.revoked_at.is_none());

    // The database holds only the hash (64 hex) and the fingerprint; the presented plaintext is never stored
    let raw = sqlx::query("SELECT hash, fingerprint FROM connect_tokens")
        .fetch_all(db.pool())
        .await
        .unwrap();
    assert_eq!(raw.len(), 1);
    let stored_hash: String = raw[0].get("hash");
    assert_eq!(stored_hash, row.hash);
    assert_eq!(stored_hash.len(), 64);
    assert!(!stored_hash.contains("pconn_"));

    // Auth hit + last_used persisted
    assert!(service
        .connect_authenticate(&presented)
        .await
        .unwrap()
        .is_some());
    let listed = service.list_connect_tokens().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].last_used_at.is_some());

    // Revocation takes effect immediately; a repeat revocation is idempotent and returns false
    assert!(service.revoke_connect_token(&row.id).await.unwrap());
    assert!(!service.revoke_connect_token(&row.id).await.unwrap());
    assert!(service
        .connect_authenticate(&presented)
        .await
        .unwrap()
        .is_none());

    // Unknown/malformed tokens are always None (same shape, anti-probing)
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

    // Full scope: all identities/items visible
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

    // identities limited to [A]: B's items are invisible; an explicit identity=B parameter -> empty list (anti-probing)
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

    // item_types limited to Password: cards and TOTP are not listed
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

    // Single read: out-of-scope and nonexistent are the same-shape None
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

    // TOTP: a TwoFactor item yields a code, a password item yields None
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

    // After archiving, the item is invisible to the Connect data plane
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

    // When locked, both data plane and admin surface follow the 503 semantics (VaultLocked)
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
    // authenticate itself has no lock gate: DR-4's 503 is intercepted by the host layer before auth,
    // and core-level token validation only reads the connect_tokens table (no decryption involved).
    assert!(service
        .connect_authenticate("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .await
        .unwrap()
        .is_none());
}

/// Label defence arm of create_connect_token: blank after trimming and longer than 128 chars are always rejected.
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

/// A scope without the Read verb: all four read endpoints return empty results (uniform shape, no existence leakage).
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

/// use-verb token (batch 2): signing/code-generation grants carry no read ability -- a pure use
/// scope returns uniformly empty/None on the four data-plane endpoints; adding read to the same
/// scope makes them readable, proving the denial comes from the verb set and not the identity
/// or item-type dimension.
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

/// Boundedness of the unknown:{fingerprint} throttle table (audit batch 2 #7): every randomly
/// forged token has a distinct fingerprint, so without a cap requests replaying random tokens
/// could blow memory up without bound. Past the cap, new keys are dropped (false = no audit
/// written) and the table length stays capped; the throttling semantics of keys already in the
/// window are unaffected by the flood.
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

    // During the flood new keys are dropped and the table length stops growing.
    assert!(!service.connect_throttle_should_write("unknown:overflow"));
    assert!(!service.connect_throttle_should_write(&format!("unknown:fill-{max}")));
    assert_eq!(service.connect_audit_marks.lock().unwrap().len(), max);

    // A key already in the window keeps being throttled (false, no rewrite, no growth).
    assert!(!service.connect_throttle_should_write("unknown:fill-0"));
}

/// Expiry bound to the principal (migration 019): a token not yet expired authenticates; an
/// expired one gets the same-shaped denial (same shape as revocation) plus a failure audit.
/// At creation time, past timestamps are rejected.
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

    // At creation: past/present timestamps are rejected outright.
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

    // Expiry mid-flight: write a past timestamp straight to the database; authenticate denies and records a throttled audit.
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

/// Out-of-scope denials write an audit (architecture correction batch 2): previously scope denials
/// produced zero audits. An out-of-scope single-item read returns None (anti-probing) while also
/// recording an UnauthorizedAccess entry.
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

    // An out-of-scope single-item read: None plus exactly one UnauthorizedAccess.
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

    // In-scope reads write no denial audit.
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

/// scope/existence defence arms of connect_totp: an unknown id, an out-of-scope identity, and an
/// unauthorized Totp item type all return None (same shape as the list 404).
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

    // Unknown id -> None
    assert!(service
        .connect_totp(&token_of(&connect_read_scope()), &Uuid::new_v4())
        .await
        .unwrap()
        .is_none());

    // Scope restricted to a different identity -> None (same anti-probing shape)
    let other_only = ConnectTokenScope {
        identities: vec![Uuid::new_v4()],
        ..connect_read_scope()
    };
    assert!(service
        .connect_totp(&token_of(&other_only), &cred.id)
        .await
        .unwrap()
        .is_none());

    // item_types not authorized for Totp -> None
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

/// The item_type filter branch of list_items: an explicit item type only returns items of that type.
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
