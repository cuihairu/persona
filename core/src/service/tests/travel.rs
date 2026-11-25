use super::*;

#[tokio::test]
async fn travel_round_trip_moves_secrets_out_and_back() {
    let (dir, db, mut service) = travel_fixture().await;
    let db_path = dir.path().join("identities.db");

    let work = service
        .create_identity("work".to_string(), IdentityType::Work)
        .await
        .unwrap();
    let personal = service
        .create_identity("personal".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, work.id, "GitHub", CredentialType::Password).await;
    service.set_travel_marked(&work.id, true).await.unwrap();

    // Attachments (sealed blob written to disk) + passkey + the wallet family (rows created via raw SQL)
    let att_dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(att_dir.path(), db.clone())
        .await
        .unwrap();
    let src = att_dir.path().join("doc.txt");
    std::fs::write(&src, b"sealed attachment bytes").unwrap();
    let att = service.attach_file(cred.id, &src, false).await.unwrap();
    let passkey = service
            .create_passkey(
                work.id,
                "example.com".to_string(),
                "https://example.com",
                br#"{"type":"webauthn.create","origin":"https://example.com","challenge":"Y2hhbGxlbmdl"}"#,
                Some(vec![1, 2]),
                None,
                None,
                false,
            )
            .await
            .unwrap();
    let wallet_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO crypto_wallets (id, identity_id, name, network, wallet_type, \
             encrypted_private_key, watch_only, security_level, created_at, updated_at) \
             VALUES (?, ?, 'w', 'ethereum', 'hd', x'0102', 0, 'High', ?, ?)",
    )
    .bind(wallet_id.to_string())
    .bind(work.id.to_string())
    .bind(now)
    .bind(now)
    .execute(db.pool())
    .await
    .unwrap();
    sqlx::query(
            "INSERT INTO wallet_addresses (id, wallet_id, address, address_type, \
             \"index\", used, metadata, created_at) VALUES (?, ?, '0xabc', 'receive', 0, 0, '{}', ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(wallet_id.to_string())
        .bind(now)
        .execute(db.pool())
        .await
        .unwrap();

    // The workspace active pointer targets the identity being removed (cleared by enter, restored by exit)
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(work.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();

    // Baseline before enter: sealed bytes, history rows, audit rows carrying FK references
    let (wrapped_before, enc_before): (Vec<u8>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT wrapped_item_key, encrypted_data FROM credentials WHERE id = ?")
            .bind(cred.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    let history_before: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM change_history")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let audit_fk_before: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE identity_id = ?")
            .bind(work.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(
        audit_fk_before >= 1,
        "fixture must have FK-bearing audit rows"
    );

    let status = service.travel_status(&db_path).await.unwrap();
    assert!(!status.active && !status.sidecar_exists && !status.inconsistent);

    let counts = service
        .enter_travel_mode(&db_path, "travel-secret")
        .await
        .unwrap();
    assert!(counts.identities >= 1);
    assert!(counts.credentials >= 1);
    assert!(counts.attachments >= 1);
    assert!(counts.passkeys >= 1);
    assert!(counts.wallets >= 1);
    assert!(counts.history_rows >= 1);
    assert_eq!(counts.files, 1);

    // Zero trace in the primary database: the marked identity and all of its dependent rows are gone, unmarked identities intact
    assert!(service
        .identity_repo
        .find_by_id(&work.id)
        .await
        .unwrap()
        .is_none());
    assert!(service
        .identity_repo
        .find_by_id(&personal.id)
        .await
        .unwrap()
        .is_some());
    let wallet_left: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM crypto_wallets WHERE identity_id = ?")
            .bind(work.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(wallet_left, 0);

    let status = service.travel_status(&db_path).await.unwrap();
    assert!(status.active && status.sidecar_exists && !status.inconsistent);
    assert!(status.entered_at.is_some());

    // The active pointer has been cleared
    let active: Option<String> =
        sqlx::query_scalar("SELECT active_identity_id FROM workspaces LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(active, None);

    // Audit FK stripping: the reference columns are emptied while the audit row itself survives (resource_id still preserves the evidence)
    let audit_fk_after: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE identity_id = ?")
            .bind(work.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(audit_fk_after, 0);
    let audit_kept: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE resource_id = ?")
            .bind(work.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(audit_kept >= 1, "audit rows survive with resource_id only");

    // A password change during travel is refused (the wrapped key in the sidecar is wrapped by the old master key)
    let err = service
        .change_master_password("master-pin", "rotated-pin")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Travel mode is active"), "{err}");

    // ---- exit: a wrong passphrase keeps the sidecar, and the rows are still missing ----
    let err = service
        .exit_travel_mode(&db_path, "wrong-passphrase")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("passphrase is wrong"), "{err}");
    assert!(crate::travel::sidecar_path(&db_path).exists());
    assert!(service
        .identity_repo
        .find_by_id(&work.id)
        .await
        .unwrap()
        .is_none());

    // ---- exit: the correct passphrase restores as-is ----
    let counts = service
        .exit_travel_mode(&db_path, "travel-secret")
        .await
        .unwrap();
    assert_eq!(counts.identities, 1);

    // Rows are byte-equal (wrapped_item_key/encrypted_data unchanged)
    let (wrapped_after, enc_after): (Vec<u8>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT wrapped_item_key, encrypted_data FROM credentials WHERE id = ?")
            .bind(cred.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(wrapped_after, wrapped_before);
    assert_eq!(enc_after, enc_before);

    // The original master password still decrypts
    match service
        .get_credential_data(&cred.id)
        .await
        .unwrap()
        .expect("credential restored")
    {
        CredentialData::Password(p) => assert_eq!(p.password, "pw"),
        other => panic!("unexpected credential data: {other:?}"),
    }

    // Attachment files and rows restored: decrypts back to the original bytes
    assert_eq!(
        service.retrieve_attachment(&att, false).await.unwrap(),
        b"sealed attachment bytes"
    );

    // Passkey and wallet family restored
    assert!(service.get_passkey(&passkey.id).await.unwrap().is_some());
    let wallets_back: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM crypto_wallets WHERE identity_id = ?")
            .bind(work.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(wallets_back, 1);
    let addresses_back: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM wallet_addresses WHERE wallet_id = ?")
            .bind(wallet_id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(addresses_back, 1);

    // change_history rode along with the rows and came back; the total count is unchanged
    let history_after: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM change_history")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(history_after, history_before);

    // The active pointer is restored, the sidecar is deleted, and the flag is reset
    let active: Option<String> =
        sqlx::query_scalar("SELECT active_identity_id FROM workspaces LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(active.as_deref(), Some(work.id.to_string().as_str()));
    assert!(!crate::travel::sidecar_path(&db_path).exists());
    let status = service.travel_status(&db_path).await.unwrap();
    assert!(!status.active && status.entered_at.is_none() && !status.inconsistent);
}

#[tokio::test]
async fn travel_enter_rejects_unready_states() {
    let (dir, _db, service) = travel_fixture().await;
    let db_path = dir.path().join("identities.db");
    let identity = service
        .create_identity("a".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // No marked identity
    let err = service.enter_travel_mode(&db_path, "pw").await.unwrap_err();
    assert!(
        err.to_string().contains("no identities are marked"),
        "{err}"
    );

    // Empty passphrase
    service.set_travel_marked(&identity.id, true).await.unwrap();
    let err = service.enter_travel_mode(&db_path, "").await.unwrap_err();
    assert!(
        err.to_string().contains("passphrase must not be empty"),
        "{err}"
    );

    // The sidecar already exists (a crash-window-1 leftover): refused without overwriting
    std::fs::write(crate::travel::sidecar_path(&db_path), b"leftover").unwrap();
    let err = service.enter_travel_mode(&db_path, "pw").await.unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(
        std::fs::read(crate::travel::sidecar_path(&db_path)).unwrap(),
        b"leftover"
    );
    std::fs::remove_file(crate::travel::sidecar_path(&db_path)).unwrap();

    // Already active
    service.enter_travel_mode(&db_path, "pw").await.unwrap();
    let err = service.enter_travel_mode(&db_path, "pw").await.unwrap_err();
    assert!(err.to_string().contains("Travel mode is active"), "{err}");
}

#[tokio::test]
async fn travel_set_marked_is_idempotent_and_audited() {
    let (_dir, db, service) = travel_fixture().await;
    let identity = service
        .create_identity("m".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    service.set_travel_marked(&identity.id, true).await.unwrap();
    // Marking the same state again: succeeds idempotently and writes no further audit
    service.set_travel_marked(&identity.id, true).await.unwrap();
    let fetched = service
        .identity_repo
        .find_by_id(&identity.id)
        .await
        .unwrap()
        .unwrap();
    assert!(fetched.travel_marked);

    service
        .set_travel_marked(&identity.id, false)
        .await
        .unwrap();
    let fetched = service
        .identity_repo
        .find_by_id(&identity.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!fetched.travel_marked);

    let audits: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE action = 'travel_mark_changed'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(audits, 2, "only actual flips are audited");

    let err = service
        .set_travel_marked(&Uuid::new_v4(), true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}

#[tokio::test]
async fn travel_mode_blocks_master_password_change_until_exit() {
    let (dir, _db, mut service) = travel_fixture().await;
    let db_path = dir.path().join("identities.db");

    // Not-active control case: a password change proceeds normally
    service
        .change_master_password("master-pin", "master-pin-2")
        .await
        .unwrap();
    service
        .change_master_password("master-pin-2", "master-pin")
        .await
        .unwrap();

    let identity = service
        .create_identity("t".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    service.set_travel_marked(&identity.id, true).await.unwrap();
    service.enter_travel_mode(&db_path, "pw").await.unwrap();

    let err = service
        .change_master_password("master-pin", "rotated")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Travel mode is active"), "{err}");

    service.exit_travel_mode(&db_path, "pw").await.unwrap();
    service
        .change_master_password("master-pin", "rotated")
        .await
        .unwrap();
}

#[tokio::test]
async fn travel_status_reports_inconsistent_when_sidecar_removed() {
    let (dir, _db, service) = travel_fixture().await;
    let db_path = dir.path().join("identities.db");
    let identity = service
        .create_identity("t".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    service.set_travel_marked(&identity.id, true).await.unwrap();

    // When not active, a missing sidecar is the normal state
    let status = service.travel_status(&db_path).await.unwrap();
    assert!(!status.active && !status.sidecar_exists && !status.inconsistent);

    service.enter_travel_mode(&db_path, "pw").await.unwrap();
    std::fs::remove_file(crate::travel::sidecar_path(&db_path)).unwrap();
    let status = service.travel_status(&db_path).await.unwrap();
    assert!(
        status.active && !status.sidecar_exists && status.inconsistent,
        "flag says active but the only copy of the data is gone"
    );
}

/// exit with no sidecar (never entered or already cleaned up): NotFound reports the exact path
/// instead of swallowing it as a no-op.
#[tokio::test]
async fn travel_exit_without_sidecar_reports_missing_path() {
    let (dir, _db, service) = travel_fixture().await;
    let db_path = dir.path().join("identities.db");

    let err = service.exit_travel_mode(&db_path, "pw").await.unwrap_err();
    assert!(
        err.to_string().contains("travel sidecar not found"),
        "{err}"
    );
}

/// A sidecar deletion failure (other than NotFound) only warns and does not roll back: the rows
/// are already restored, so exit still succeeds (unix-only: EACCES is induced by making the
/// directory read-only; unpacking and restoration are unaffected).
#[cfg(unix)]
#[tokio::test]
async fn travel_exit_survives_unremovable_sidecar() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, _db, service) = travel_fixture().await;
    let db_path = dir.path().join("identities.db");

    let work = service
        .create_identity("work".into(), IdentityType::Work)
        .await
        .unwrap();
    service.set_travel_marked(&work.id, true).await.unwrap();
    service.enter_travel_mode(&db_path, "pw").await.unwrap();

    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(dir.path(), perms).unwrap();

    let counts = service.exit_travel_mode(&db_path, "pw").await.unwrap();
    assert_eq!(counts.identities, 1);

    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(dir.path(), perms).unwrap();
}

/// In favicon_cache, hosts referenced only by removed credentials are cleared by enter; hosts still
/// referenced by retained credentials (or by several credentials on the same host) are kept.
#[cfg(feature = "favicon")]
#[tokio::test]
async fn travel_enter_prunes_favicon_hosts_only_when_unreferenced() {
    let (dir, db, service) = travel_fixture().await;
    let db_path = dir.path().join("identities.db");

    let marked_i = service
        .create_identity("rm".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let kept_i = service
        .create_identity("keep".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    let doomed = seed_credential(&service, marked_i.id, "doomed", CredentialType::Password).await;
    let mut doomed = doomed;
    doomed.url = Some("https://doomed.example.com/login".to_string());
    service.update_credential(&doomed).await.unwrap();
    // A second credential on the removed identity shares a host with a retained credential: the kept host must survive
    let alt = seed_credential(&service, marked_i.id, "alt", CredentialType::Password).await;
    let mut alt = alt;
    alt.url = Some("https://kept.example.com/alt".to_string());
    service.update_credential(&alt).await.unwrap();
    let kept = seed_credential(&service, kept_i.id, "kept", CredentialType::Password).await;
    let mut kept = kept;
    kept.url = Some("https://kept.example.com/".to_string());
    service.update_credential(&kept).await.unwrap();

    for host in ["doomed.example.com", "kept.example.com"] {
        sqlx::query(
            "INSERT INTO favicon_cache (host, mime_type, data, created_at, updated_at) \
                 VALUES (?, 'image/png', x'89504e47', '2026-01-01', '2026-01-01')",
        )
        .bind(host)
        .execute(db.pool())
        .await
        .unwrap();
    }

    service.set_travel_marked(&marked_i.id, true).await.unwrap();
    service.enter_travel_mode(&db_path, "pw").await.unwrap();

    let doomed_left: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM favicon_cache WHERE host = 'doomed.example.com'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let kept_left: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM favicon_cache WHERE host = 'kept.example.com'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(doomed_left, 0, "unreferenced host must be pruned");
    assert_eq!(
        kept_left, 1,
        "host still referenced by kept credentials stays"
    );
}
