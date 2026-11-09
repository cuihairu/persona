use super::*;

#[tokio::test]
async fn test_passkey_lifecycle() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let mut service = PersonaService::new(db.clone()).await.unwrap();
    let salt = service.generate_salt();
    service.unlock("test_password", &salt).unwrap();

    let identity = service
        .create_identity("Passkey Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // registration through the service; client data mimics an RP challenge
    let create_client_data =
        br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#;
    let passkey = service
        .create_passkey(
            identity.id,
            "example.com".to_string(),
            "https://example.com",
            create_client_data,
            None,
            Some("alice@example.com".to_string()),
            Some("Alice".to_string()),
            true,
        )
        .await
        .unwrap();
    assert_eq!(passkey.rp_id, "example.com");
    assert_eq!(passkey.user_handle.len(), 32);
    assert_eq!(passkey.alg, -7);

    let listed = service.list_passkeys(&identity.id).await.unwrap();
    assert_eq!(listed.len(), 1);

    // self-test: sign locally, verify against the stored public key
    service.passkey_self_test(&passkey.id).await.unwrap();

    // assertion updates last_used_at and returns RP-ready artifacts
    let get_client_data =
        br#"{"type":"webauthn.get","challenge":"YXNzZXJ0aW9u","origin":"https://example.com"}"#;
    let assertion = service
        .passkey_assertion(
            &passkey.id,
            "https://example.com",
            get_client_data,
            true,
            "extension",
        )
        .await
        .unwrap();
    assert_eq!(assertion.credential_id, passkey.credential_id);
    assert_eq!(assertion.user_handle, passkey.user_handle);

    let reloaded = service.get_passkey(&passkey.id).await.unwrap().unwrap();
    assert!(reloaded.last_used_at.is_some());

    // 审计抽查：断言事件携带 via 来源元数据（P4.4 的 core 半边）。
    let audit_repo = AuditLogRepository::new(db);
    let asserted = audit_repo
        .find_by_action(&AuditAction::PasskeyAsserted)
        .await
        .unwrap();
    assert_eq!(asserted.len(), 1, "exactly one assertion audited");
    assert_eq!(
        asserted[0].metadata.get("via").map(String::as_str),
        Some("extension"),
        "audit must record the assertion trust path"
    );

    assert!(service.delete_passkey(&passkey.id).await.unwrap());
    assert!(!service.delete_passkey(&passkey.id).await.unwrap());
    assert!(service.get_passkey(&passkey.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_passkey_error_paths_and_export() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let mut service = PersonaService::new(db.clone()).await.unwrap();
    let salt = service.generate_salt();
    service.unlock("test_password", &salt).unwrap();

    let identity = service
        .create_identity("Passkey Errors".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let create_client_data =
        br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#;
    let passkey = service
        .create_passkey(
            identity.id,
            "example.com".to_string(),
            "https://example.com",
            create_client_data,
            None,
            Some("alice@example.com".to_string()),
            Some("Alice".to_string()),
            true,
        )
        .await
        .unwrap();

    // ---- export: disabled flag, unknown id, then the happy path ----
    service
        .passkey_repo
        .update(&PasskeyItem {
            export_allowed: false,
            ..passkey.clone()
        })
        .await
        .unwrap();
    let err = service
        .export_passkey_private_key(&passkey.id)
        .await
        .expect_err("non-exportable passkey must be refused");
    assert!(err.to_string().contains("export is disabled"));

    let unknown = uuid::Uuid::new_v4();
    let err = service
        .export_passkey_private_key(&unknown)
        .await
        .expect_err("unknown passkey export must fail");
    assert!(err.to_string().contains("not found"));

    service
        .passkey_repo
        .update(&PasskeyItem {
            export_allowed: true,
            ..passkey.clone()
        })
        .await
        .unwrap();
    let exported = service
        .export_passkey_private_key(&passkey.id)
        .await
        .unwrap();
    assert_eq!(exported.len(), 32);
    // the exported scalar must match the stored key's public point
    let key = p256::ecdsa::SigningKey::from_slice(&exported).unwrap();
    let cose = crate::crypto::cose_public_key(key.verifying_key()).unwrap();
    assert_eq!(cose, passkey.public_key_cose);

    // ---- assertion: origin must match the passkey's rp_id ----
    let get_client_data =
        br#"{"type":"webauthn.get","challenge":"YXNzZXJ0aW9u","origin":"https://evil.example"}"#;
    let err = service
        .passkey_assertion(
            &passkey.id,
            "https://evil.example",
            get_client_data,
            true,
            "extension",
        )
        .await
        .expect_err("mismatched origin must be rejected");
    assert!(err.to_string().contains("does not match rp_id"));

    // ---- corrupted sealed key: unsealing must surface a crypto error ----
    // A validly-sealed envelope whose plaintext is not a valid P-256
    // scalar (zero) — AEAD decrypts fine, key reconstruction must fail.
    let hierarchy =
        crate::crypto::KeyHierarchy::new(service.get_master_encryption_service().unwrap());
    let envelope = hierarchy.encrypt_with_new_item_key(&[0u8; 32]).unwrap();
    sqlx::query("UPDATE passkeys SET encrypted_private_key = ?, wrapped_item_key = ? WHERE id = ?")
        .bind(&envelope.ciphertext)
        .bind(&envelope.wrapped_key)
        .bind(passkey.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    let err = service
        .passkey_self_test(&passkey.id)
        .await
        .expect_err("corrupted sealed key must fail");
    assert!(err.to_string().contains("Invalid stored passkey key"));

    // ---- restore the sealed key, then break rp_id / public key ----
    sqlx::query("UPDATE passkeys SET encrypted_private_key = ?, wrapped_item_key = ? WHERE id = ?")
        .bind(&passkey.encrypted_private_key)
        .bind(&passkey.wrapped_item_key)
        .bind(passkey.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();

    // a rp_id that is not a hostname makes the self-test's own assertion fail
    sqlx::query("UPDATE passkeys SET rp_id = 'bad rp' WHERE id = ?")
        .bind(passkey.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    let err = service
        .passkey_self_test(&passkey.id)
        .await
        .expect_err("invalid rp_id must fail the self-test");
    assert!(err.to_string().contains("rp_id"));

    // a public key from another key pair makes the final RP-check fail
    let foreign =
        crate::crypto::cose_public_key(crate::crypto::generate_signing_key().verifying_key())
            .unwrap();
    sqlx::query("UPDATE passkeys SET rp_id = 'example.com', public_key_cose = ? WHERE id = ?")
        .bind(&foreign)
        .bind(passkey.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    let err = service
        .passkey_self_test(&passkey.id)
        .await
        .expect_err("mismatched public key must fail the self-test");
    assert!(
        err.to_string().contains("signature invalid")
            || err.to_string().contains("Assertion signature invalid")
    );
}
