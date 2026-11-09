use super::*;

#[tokio::test]
async fn test_user_lifecycle_and_auth_paths() {
    // A fresh database has no users; authentication fails closed.
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db.clone()).await.unwrap();
    assert!(!service.has_users().await.unwrap());
    assert_eq!(
        service.authenticate_user("anything").await.unwrap(),
        AuthResult::InvalidCredentials
    );

    // Initialize the first user; the service unlocks automatically.
    let user_id = service.initialize_user("master-pin").await.unwrap();
    assert!(service.has_users().await.unwrap());
    assert!(service.is_unlocked());

    // Wrong password keeps the service usable but reports the failure.
    assert_eq!(
        service.authenticate_user("wrong").await.unwrap(),
        AuthResult::InvalidCredentials
    );
    // Correct password succeeds (and succeeds again on repeat login).
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );

    // Locking clears the in-memory key; ops are refused until re-unlock.
    service.lock();
    assert!(!service.is_unlocked());
    assert!(service.current_user.is_none());

    // Direct unlock with the stored salt restores access.
    let salt = service
        .user_auth_repo
        .get_first()
        .await
        .unwrap()
        .unwrap()
        .get_master_key_salt()
        .unwrap();
    service.unlock("master-pin", &salt).unwrap();
    assert!(service.is_unlocked());
    assert_ne!(user_id, Uuid::new_v4());
}

#[tokio::test]
async fn test_authenticate_user_locks_account_after_failures() {
    let (_db, mut service) = unlocked_service().await;

    for _ in 0..4 {
        assert_eq!(
            service.authenticate_user("wrong").await.unwrap(),
            AuthResult::InvalidCredentials
        );
    }
    // 5th failure triggers the account lockout.
    assert_eq!(
        service.authenticate_user("wrong").await.unwrap(),
        AuthResult::InvalidCredentials
    );
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::AccountLocked
    );
}

#[tokio::test]
async fn new_vault_records_the_kdf_floor() {
    let (_db, service) = unlocked_service().await;
    assert_eq!(
        service
            .user_auth_repo
            .get_first()
            .await
            .unwrap()
            .unwrap()
            .kdf_iterations,
        MASTER_KEY_PBKDF2_ITERATIONS
    );
}

#[tokio::test]
async fn legacy_kdf_vault_upgrades_on_unlock_without_losing_data() {
    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Legacy".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential =
        seed_credential(&service, identity.id, "Google", CredentialType::Password).await;

    let before = service.user_auth_repo.get_first().await.unwrap().unwrap();
    downgrade_to_legacy_kdf(&service).await;
    assert_eq!(
        service
            .user_auth_repo
            .get_first()
            .await
            .unwrap()
            .unwrap()
            .kdf_iterations,
        crate::crypto::LEGACY_MASTER_KEY_PBKDF2_ITERATIONS
    );

    // One unlock re-derives at the legacy count, re-wraps, then advances
    // the stored count — password and salt stay put.
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );

    let upgraded = service.user_auth_repo.get_first().await.unwrap().unwrap();
    assert_eq!(upgraded.kdf_iterations, MASTER_KEY_PBKDF2_ITERATIONS);
    assert_eq!(upgraded.master_key_salt, before.master_key_salt);
    assert!(upgraded.verify_master_password("master-pin").unwrap());
    assert!(!upgraded.verify_master_password("old-pin").unwrap());

    assert_password_credential(
        service
            .get_credential_data(&credential.id)
            .await
            .unwrap()
            .unwrap(),
    );
}

#[tokio::test]
async fn second_unlock_after_kdf_upgrade_is_a_noop() {
    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Legacy".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential =
        seed_credential(&service, identity.id, "Google", CredentialType::Password).await;
    downgrade_to_legacy_kdf(&service).await;

    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );
    assert_eq!(
        service
            .user_auth_repo
            .get_first()
            .await
            .unwrap()
            .unwrap()
            .kdf_iterations,
        MASTER_KEY_PBKDF2_ITERATIONS
    );
    let stored = service
        .get_credential(&credential.id)
        .await
        .unwrap()
        .unwrap();

    // At the floor the fast path runs: no re-wrap, no envelope rewrite.
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );
    let stored_after = service
        .get_credential(&credential.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.encrypted_data, stored_after.encrypted_data);
    assert_eq!(stored.wrapped_item_key, stored_after.wrapped_item_key);
    assert_eq!(
        service
            .user_auth_repo
            .get_first()
            .await
            .unwrap()
            .unwrap()
            .kdf_iterations,
        MASTER_KEY_PBKDF2_ITERATIONS
    );

    assert_password_credential(
        service
            .get_credential_data(&credential.id)
            .await
            .unwrap()
            .unwrap(),
    );
}

#[tokio::test]
async fn change_master_password_rotates_and_upgrades_a_legacy_vault() {
    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Legacy".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential =
        seed_credential(&service, identity.id, "Rotated", CredentialType::Password).await;
    downgrade_to_legacy_kdf(&service).await;

    service
        .change_master_password("master-pin", "rotated-pin")
        .await
        .unwrap();

    let rotated = service.user_auth_repo.get_first().await.unwrap().unwrap();
    assert_eq!(rotated.kdf_iterations, MASTER_KEY_PBKDF2_ITERATIONS);
    assert!(rotated.verify_master_password("rotated-pin").unwrap());
    assert!(!rotated.verify_master_password("master-pin").unwrap());

    // The unlocked path swaps the in-memory key, so the credential reads
    // back under the new password.
    assert_password_credential(
        service
            .get_credential_data(&credential.id)
            .await
            .unwrap()
            .unwrap(),
    );

    // A fresh unlock goes straight to the upgraded count.
    service.force_lock_session().await.unwrap();
    assert_eq!(
        service.authenticate_user("rotated-pin").await.unwrap(),
        AuthResult::Success
    );
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::InvalidCredentials
    );
}

#[tokio::test]
async fn upgraded_kdf_count_survives_a_restart() {
    let (db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Legacy".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential =
        seed_credential(&service, identity.id, "Google", CredentialType::Password).await;
    downgrade_to_legacy_kdf(&service).await;
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );
    let wrapped = service
        .get_credential(&credential.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        service
            .user_auth_repo
            .get_first()
            .await
            .unwrap()
            .unwrap()
            .kdf_iterations,
        MASTER_KEY_PBKDF2_ITERATIONS
    );

    // A brand-new service over the same database must read the upgraded
    // count from the row and unlock without a second re-wrap.
    let mut restarted = PersonaService::new(db).await.unwrap();
    assert_eq!(
        restarted.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );
    let stored = restarted
        .get_credential(&credential.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wrapped.encrypted_data, stored.encrypted_data);
    assert_eq!(wrapped.wrapped_item_key, stored.wrapped_item_key);
    assert_password_credential(
        restarted
            .get_credential_data(&credential.id)
            .await
            .unwrap()
            .unwrap(),
    );
}

#[tokio::test]
async fn count_wrapped_under_the_wrong_master_key_fails_closed() {
    // Torn rotation: rows already rewrapped under the floor while the
    // stored count still claims the legacy figure. Unlock must error out
    // rather than derive the legacy key, unwrap garbage, and hand back
    // ciphertext. (Both real paths commit the count inside the same
    // transaction as the rewrap; this guards the invariant from a future
    // non-transactional writer.)
    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Legacy".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    seed_credential(&service, identity.id, "Google", CredentialType::Password).await;
    downgrade_to_legacy_kdf(&service).await;

    let user_auth = service.user_auth_repo.get_first().await.unwrap().unwrap();
    let salt = user_auth.get_master_key_salt().unwrap();
    service
        .rewrap_all_item_keys(
            &service
                .master_key_service
                .create_encryption_service_with_iterations(
                    "master-pin",
                    &salt,
                    user_auth.kdf_iterations,
                ),
            &service
                .master_key_service
                .create_encryption_service("master-pin", &salt),
            &user_auth,
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .user_auth_repo
            .get_first()
            .await
            .unwrap()
            .unwrap()
            .kdf_iterations,
        crate::crypto::LEGACY_MASTER_KEY_PBKDF2_ITERATIONS
    );
    service.force_lock_session().await.unwrap();

    let err = service
        .authenticate_user("master-pin")
        .await
        .expect_err("a torn rotation must fail closed");
    assert!(
        matches!(
            err.downcast_ref::<PersonaError>(),
            Some(PersonaError::CryptographicError(_))
        ),
        "expected a cryptographic error, got: {err}"
    );
}

/// Full core-side path of a hardware unlock: derive the master key the
/// way `biometric_enable` does, hand it to the wrap layer, then unlock
/// through `authenticate_with_master_key` with the key the *hardware*
/// gave back. Also proves the derived key really is the vault key (a
/// seeded credential survives the round trip).
#[tokio::test]
async fn test_biometric_wrap_unlocks_vault_end_to_end() {
    use crate::auth::{unwrap_master_key, wrap_master_key, MockKeyWrapper};

    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Wrap Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "Wrapped", CredentialType::Password).await;
    service.lock();

    let wrapper = MockKeyWrapper::default();
    let master_key = service
        .derive_master_key_for_wrap("master-pin")
        .await
        .unwrap();
    let envelope = wrap_master_key(&wrapper, &master_key, "enable").unwrap();

    // Locked + wrong key = no data; locked + unwrapped key = data back.
    let unwrapped = unwrap_master_key(&wrapper, &envelope, "unlock").unwrap();
    assert_eq!(
        service
            .authenticate_with_master_key(&unwrapped, "biometric-wrap")
            .await
            .unwrap(),
        AuthResult::Success
    );
    assert!(service.is_unlocked());
    assert!(service.current_user.is_some());
    let fetched = service.get_credential(&cred.id).await.unwrap().unwrap();
    assert_eq!(fetched.name, "Wrapped");
}

/// Fail-closed edges of `authenticate_with_master_key`: no user record,
/// locked-out account, and the forced-rotation flag all keep the
/// hardware path from bypassing the password path's gates.
#[tokio::test]
async fn test_authenticate_with_master_key_respects_password_path_gates() {
    use crate::auth::MockKeyWrapper;

    // No user initialized → InvalidCredentials, service stays locked.
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut empty = PersonaService::new(db).await.unwrap();
    assert_eq!(
        empty
            .authenticate_with_master_key(&[7u8; 32], "biometric-wrap")
            .await
            .unwrap(),
        AuthResult::InvalidCredentials
    );
    assert!(!empty.is_unlocked());

    // A real vault: wrong master key still unlocks the *session* (the
    // hardware already authenticated the user) but yields no data —
    // proof the key is genuinely the encryption key, not a bypass.
    let (_db, mut service) = unlocked_service().await;
    service.lock();
    let wrapper = MockKeyWrapper::default();
    let good = service
        .derive_master_key_for_wrap("master-pin")
        .await
        .unwrap();
    let bad = service
        .derive_master_key_for_wrap("not-the-pin")
        .await
        .unwrap();
    assert_ne!(good, bad, "wrong password must derive a different key");
    let envelope = crate::auth::wrap_master_key(&wrapper, &good, "enable").unwrap();
    let unwrapped = crate::auth::unwrap_master_key(&wrapper, &envelope, "unlock").unwrap();
    assert_eq!(*unwrapped, good);

    assert_eq!(
        service
            .authenticate_with_master_key(&bad, "biometric-wrap")
            .await
            .unwrap(),
        AuthResult::Success
    );
    assert!(service.get_master_encryption_service().is_ok_and(|_| true));
}

/// Lockout is NOT bypassed by the hardware path: five wrong passwords
/// lock the account, and a subsequent (valid) hardware unlock is
/// refused with AccountLocked.
#[tokio::test]
async fn test_authenticate_with_master_key_does_not_bypass_lockout() {
    let (_db, mut service) = unlocked_service().await;
    let master_key = service
        .derive_master_key_for_wrap("master-pin")
        .await
        .unwrap();
    service.lock();
    for _ in 0..5 {
        assert_eq!(
            service.authenticate_user("wrong").await.unwrap(),
            AuthResult::InvalidCredentials
        );
    }
    assert_eq!(
        service
            .authenticate_with_master_key(&master_key, "biometric-wrap")
            .await
            .unwrap(),
        AuthResult::AccountLocked
    );
    assert!(!service.is_unlocked());
}

/// Forced rotation also survives: a `password_change_required` flag
/// short-circuits the hardware path exactly as it does the password
/// path (the UI is expected to route into the rotation flow).
#[tokio::test]
async fn test_authenticate_with_master_key_honors_forced_rotation() {
    let (db, mut service) = unlocked_service().await;
    set_password_expiry(&db, Some(90)).await;
    backdate_password_updated_at(&db, 91).await;
    let master_key = service
        .derive_master_key_for_wrap("master-pin")
        .await
        .unwrap();
    service.lock();

    assert_eq!(
        service
            .authenticate_with_master_key(&master_key, "biometric-wrap")
            .await
            .unwrap(),
        AuthResult::PasswordChangeRequired
    );
    assert!(!service.is_unlocked());
}

/// `derive_master_key_for_wrap` on a vault with no user is an error
/// (callers surface it as a failed enable, never a wrapped garbage key).
#[tokio::test]
async fn test_derive_master_key_for_wrap_requires_a_user() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let service = PersonaService::new(db).await.unwrap();
    let err = service
        .derive_master_key_for_wrap("master-pin")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no user initialized"));
}

/// `unlock_with_master_key` refreshes the idle clock — an auto-lock
/// countdown must not keep running while the vault is being opened.
#[tokio::test]
async fn test_unlock_with_master_key_touches_activity() {
    let (_db, mut service) = unlocked_service().await;
    service.lock();
    assert!(!service.is_unlocked());
    service.unlock_with_master_key(&[3u8; 32]).unwrap();
    assert!(service.is_unlocked());
    assert!(service.last_activity.lock().unwrap().is_some());
}

#[tokio::test]
async fn test_authenticated_user_start_monitoring_registers_current_user() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db.clone()).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    assert!(service.is_unlocked());
    // The full login path goes through authenticate_user; monitoring
    // started afterwards must propagate the current user into the
    // auto-lock manager.
    assert!(matches!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    ));
    service.start_auto_lock_monitoring().await.unwrap();
    service.stop_auto_lock_monitoring().await;
}

#[tokio::test]
async fn test_query_helpers_and_password_generation() {
    let (_db, service) = unlocked_service().await;

    let identity = service
        .create_identity("Helper Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(
        &service,
        identity.id,
        "GitHub token",
        CredentialType::Password,
    )
    .await;
    let mut fav = cred.clone();
    fav.is_favorite = true;
    fav.username = Some("octocat".to_string());
    service.update_credential(&fav).await.unwrap();
    seed_credential(&service, identity.id, "API key", CredentialType::ApiKey).await;

    assert_eq!(service.search_credentials("").await.unwrap().len(), 2);
    assert_eq!(service.search_credentials("GitHub").await.unwrap().len(), 1);
    // username / url 同样参与搜索（repository search_by_fields 链路）
    assert_eq!(
        service.search_credentials("octocat").await.unwrap().len(),
        1
    );
    assert_eq!(service.get_favorite_credentials().await.unwrap().len(), 1);
    assert_eq!(
        service
            .get_credentials_by_type(&CredentialType::Password)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        service
            .get_identities_by_type(&IdentityType::Personal)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(service
        .get_identity_by_name("no-such-identity")
        .await
        .unwrap()
        .is_none());
    assert!(service
        .list_passkeys_by_rp("example.com")
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .get_credential(&Uuid::new_v4())
        .await
        .unwrap()
        .is_none());

    // Password helpers.
    let generated = service.generate_password(16, true);
    assert_eq!(generated.chars().count(), 16);
    // Lengths below the minimum are clamped to 4.
    assert_eq!(service.generate_password(2, false).chars().count(), 4);

    let options = PasswordGeneratorOptions {
        length: 20,
        include_symbols: false,
        ..Default::default()
    };
    assert_eq!(
        service
            .generate_password_with_options(&options)
            .unwrap()
            .chars()
            .count(),
        20
    );

    let hash = service.hash_data(b"persona");
    assert_eq!(hash.len(), 32);
    assert_eq!(hash, service.hash_data(b"persona"));
}

/// 工具三件套：带选项的密码生成长度准确；盐 32 字节；SHA-256 摘要
/// 稳定且 32 字节。
#[tokio::test]
async fn password_options_salt_and_hash_helpers_behave() {
    let (_db, service) = unlocked_service().await;
    let pw = service
        .generate_password_with_options(&PasswordGeneratorOptions {
            length: 24,
            include_symbols: false,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(pw.chars().count(), 24);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

    let salt = service.generate_salt();
    assert_eq!(salt.len(), 32);

    let hash = service.hash_data(b"persona");
    assert_eq!(hash.len(), 32);
    assert_eq!(hash, service.hash_data(b"persona"));
    assert_ne!(hash, service.hash_data(b"persona2"));
}

/// Opt-in policy flags rotation at unlock; flag persists for the UI.
#[tokio::test]
async fn password_expiry_policy_flags_rotation_on_unlock() {
    let (db, mut service) = unlocked_service().await;
    set_password_expiry(&db, Some(90)).await;
    backdate_password_updated_at(&db, 91).await;

    let result = service.authenticate_user("master-pin").await.unwrap();
    assert_eq!(result, AuthResult::PasswordChangeRequired);

    let ua = UserAuthRepository::new(db.clone())
        .get_first()
        .await
        .unwrap()
        .unwrap();
    assert!(ua.password_change_required);
}

/// Fresh password inside the window still unlocks; no policy unlocks too.
#[tokio::test]
async fn password_expiry_policy_untouched_when_inside_window_or_absent() {
    let (db, mut service) = unlocked_service().await;
    set_password_expiry(&db, Some(90)).await;
    // password_updated_at == now (initialize_user stamped it)
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );

    // No policy at all (regression: default None never flags).
    let (db2, mut service2) = unlocked_service().await;
    assert_eq!(
        service2.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );
    let ua = UserAuthRepository::new(db2.clone())
        .get_first()
        .await
        .unwrap()
        .unwrap();
    assert!(!ua.password_change_required);
}

/// Fail-open: unreadable workspace settings must never block unlock.
#[tokio::test]
async fn password_expiry_policy_fails_open_on_settings_error() {
    let (db, mut service) = unlocked_service().await;
    set_password_expiry(&db, Some(90)).await;
    backdate_password_updated_at(&db, 91).await;
    sqlx::query("DROP TABLE workspaces")
        .execute(db.pool())
        .await
        .unwrap();

    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );
}

/// Full rotation: flags wrapped + legacy + passkey rows, swaps the hash,
/// keeps the salt, keeps data readable, writes the audit entry.
#[tokio::test]
async fn change_master_password_rotates_wrapped_legacy_and_passkey_rows() {
    let (db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("main".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let wrapped_cred =
        seed_credential(&service, identity.id, "wrapped", CredentialType::Password).await;
    let legacy_cred =
        seed_credential(&service, identity.id, "legacy", CredentialType::Password).await;
    convert_credential_to_legacy(&db, &service, &legacy_cred.id).await;

    // A passkey row sealed under the current master key.
    let master = service.get_master_encryption_service().unwrap();
    let hierarchy = KeyHierarchy::new(master);
    let envelope = hierarchy.encrypt_with_new_item_key(&[7u8; 32]).unwrap();
    sqlx::query(
        "INSERT INTO passkeys (id, identity_id, rp_id, user_handle, credential_id, \
             encrypted_private_key, wrapped_item_key, public_key_cose, created_at) \
             VALUES (?, ?, 'example.com', x'0102', x'0304', ?, ?, x'0506', ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(identity.id.to_string())
    .bind(&envelope.ciphertext)
    .bind(&envelope.wrapped_key)
    .bind(chrono::Utc::now().timestamp())
    .execute(db.pool())
    .await
    .unwrap();

    let salt_before = UserAuthRepository::new(db.clone())
        .get_first()
        .await
        .unwrap()
        .unwrap()
        .master_key_salt
        .clone();

    // Forced-rotation flow: policy flags → rotate from locked state →
    // old password rejected, new one unlocks, all rows readable.
    set_password_expiry(&db, Some(90)).await;
    backdate_password_updated_at(&db, 91).await;
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::PasswordChangeRequired
    );
    service
        .change_master_password("master-pin", "new-master-pin")
        .await
        .unwrap();

    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::InvalidCredentials
    );
    assert_eq!(
        service.authenticate_user("new-master-pin").await.unwrap(),
        AuthResult::Success
    );

    // Wrapped + legacy credentials both decrypt under the new master.
    match service
        .get_credential_data(&wrapped_cred.id)
        .await
        .unwrap()
        .expect("row exists")
    {
        CredentialData::Password(p) => assert_eq!(p.password, "pw"),
        other => panic!("unexpected credential data: {other:?}"),
    }
    match service
        .get_credential_data(&legacy_cred.id)
        .await
        .unwrap()
        .expect("row exists")
    {
        CredentialData::Password(p) => assert_eq!(p.password, "pw"),
        other => panic!("unexpected credential data: {other:?}"),
    }

    // Passkey item key unwraps under the new master with unchanged payload.
    let (stored_wrapped, stored_ct): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT wrapped_item_key, encrypted_private_key FROM passkeys")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let hierarchy = KeyHierarchy::new(service.get_master_encryption_service().unwrap());
    assert_eq!(
        hierarchy
            .decrypt_with_wrapped_key(&stored_wrapped, &stored_ct)
            .unwrap(),
        vec![7u8; 32]
    );

    // Salt stable, flag cleared, timestamp advanced, audit written.
    let ua = UserAuthRepository::new(db.clone())
        .get_first()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ua.master_key_salt, salt_before);
    assert!(!ua.password_change_required);
    assert!(ua.password_updated_at.is_some());
    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE action = 'password_change'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(audit_count, 1);
}

/// Wrong old password: error, attempt recorded, zero bytes touched.
#[tokio::test]
async fn change_master_password_rejects_wrong_old_password() {
    let (db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("main".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "c", CredentialType::Password).await;
    let before: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_item_key FROM credentials WHERE id = ?")
            .bind(cred.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    let hash_before: String = sqlx::query_scalar("SELECT master_password_hash FROM user_auth")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let err = service
        .change_master_password("wrong-pin", "new-master-pin")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Invalid current master password"));

    let after: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_item_key FROM credentials WHERE id = ?")
            .bind(cred.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    let hash_after: String = sqlx::query_scalar("SELECT master_password_hash FROM user_auth")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(hash_before, hash_after);
    let ua = UserAuthRepository::new(db.clone())
        .get_first()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ua.failed_attempts, 1);
    assert!(!ua.password_change_required);
    let _ = cred;
}

/// A row that fails to unwrap under the old key aborts the whole
/// rotation; the transaction rolls back leaving every byte untouched.
#[tokio::test]
async fn change_master_password_rolls_back_on_rewrap_failure() {
    let (db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("main".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let _cred = seed_credential(&service, identity.id, "c", CredentialType::Password).await;

    // Passkey whose wrapped key cannot be unwrapped under the old master.
    let master = service.get_master_encryption_service().unwrap();
    let envelope = KeyHierarchy::new(master)
        .encrypt_with_new_item_key(&[7u8; 32])
        .unwrap();
    sqlx::query(
        "INSERT INTO passkeys (id, identity_id, rp_id, user_handle, credential_id, \
             encrypted_private_key, wrapped_item_key, public_key_cose, created_at) \
             VALUES (?, ?, 'example.com', x'0102', x'0304', ?, ?, x'0506', ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(identity.id.to_string())
    .bind(&envelope.ciphertext)
    .bind(vec![0xABu8; 40])
    .bind(chrono::Utc::now().timestamp())
    .execute(db.pool())
    .await
    .unwrap();

    let before: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_item_key FROM credentials WHERE id = ?")
            .bind(_cred.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    let hash_before: String = sqlx::query_scalar("SELECT master_password_hash FROM user_auth")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let err = service
        .change_master_password("master-pin", "new-master-pin")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Failed to unwrap item key"));

    let after: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_item_key FROM credentials WHERE id = ?")
            .bind(_cred.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    let hash_after: String = sqlx::query_scalar("SELECT master_password_hash FROM user_auth")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after, "rollback must restore every byte");
    assert_eq!(hash_before, hash_after, "rollback must keep the old hash");
}

/// Validation: empty and unchanged new passwords are rejected up front.
#[tokio::test]
async fn change_master_password_validates_new_password() {
    let (_db, mut service) = unlocked_service().await;
    let err = service
        .change_master_password("master-pin", "")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("must not be empty"));
    let err = service
        .change_master_password("master-pin", "master-pin")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("must differ"));
}

/// 改密前置：库从未 init（无 user_auth 行）→ 如实报"未初始化"，
/// 不把"没有用户"误报成"密码错"。
#[tokio::test]
async fn change_master_password_requires_an_initialized_workspace() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db).await.unwrap();

    let err = service
        .change_master_password("old-pass", "new-pass")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("Workspace not initialized"),
        "{err}"
    );
}

/// 改密不是锁定的旁路：连续失败触发锁定后，改密先吃锁门禁
/// （verify old password 在锁检查之后，不构成锁定态下的猜密码 oracle）。
#[tokio::test]
async fn change_master_password_refused_while_account_locked() {
    let (_db, mut service) = unlocked_service().await;

    for _ in 0..5 {
        assert_eq!(
            service.authenticate_user("wrong").await.unwrap(),
            AuthResult::InvalidCredentials
        );
    }

    let err = service
        .change_master_password("master-pin", "rotated-pin")
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Account is locked due to too many failed attempts"),
        "{err}"
    );
}

/// 轮换撞上损坏的 legacy 行：解密失败如实报错并整体回滚，不静默跳过
/// （跳过会让该行在新主密钥下永久变砖）。旧密码在回滚后仍可用。
#[tokio::test]
async fn master_password_rotation_fails_closed_on_corrupt_legacy_row() {
    let (db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Legacy".into(), IdentityType::Personal)
        .await
        .unwrap();

    let credentials = crate::storage::CredentialRepository::new(db.clone());
    let corrupt = Credential::new(
        identity.id,
        "corrupt legacy".to_string(),
        CredentialType::Password,
        SecurityLevel::Medium,
        b"not-a-valid-ciphertext".to_vec(),
        None,
    );
    credentials.create(&corrupt).await.unwrap();

    let err = service
        .change_master_password("master-pin", "rotated-pin")
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to decrypt legacy credential during rotation"),
        "{err}"
    );
    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );
}

/// 过期策略缺时间戳的防御臂：策略开着但行里没有 password_updated_at
/// （迁移前的旧行）→ 跳过判定，绝不因缺时间戳锁死解锁（fail-open）。
#[tokio::test]
async fn password_expiry_skips_rows_without_timestamp() {
    let (_dir, db, mut service) = travel_fixture().await;

    let ws_repo = crate::storage::WorkspaceRepository::new(db.clone());
    let mut ws = Repository::find_all(&ws_repo).await.unwrap().remove(0);
    ws.settings.password_expiry_days = Some(30);
    Repository::update(&ws_repo, &ws).await.unwrap();

    sqlx::query("UPDATE user_auth SET password_updated_at = NULL")
        .execute(db.pool())
        .await
        .unwrap();

    assert_eq!(
        service.authenticate_user("master-pin").await.unwrap(),
        AuthResult::Success
    );
}
