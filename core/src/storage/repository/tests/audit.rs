use super::*;

use chrono::Duration;

#[tokio::test]
async fn audit_log_repository_crud_and_filters() {
    let db = test_db().await;
    insert_audit_user(&db).await;

    // audit_logs carries FKs to identities/credentials; seed both parents.
    let identities = IdentityRepository::new(db.clone());
    identities
        .create(&sample_identity("audit owner"))
        .await
        .unwrap();
    let identity_id = identities.find_all().await.unwrap()[0].id;
    let credentials = CredentialRepository::new(db.clone());
    credentials
        .create(&sample_credential(identity_id, "audit cred"))
        .await
        .unwrap();
    let credential_id = credentials.find_all().await.unwrap()[0].id;

    let repo = AuditLogRepository::new(db.clone());

    let mut ok_login = audit_log(AuditAction::Login)
        .with_identity_id(Some(identity_id))
        .with_session_id(Some("sess-1".to_string()));
    ok_login.metadata.insert("k".to_string(), "v".to_string());
    repo.create(&ok_login).await.unwrap();

    let mut failed = AuditLog::new(AuditAction::LoginFailed, ResourceType::User, false)
        .with_user_id(Some("tester".to_string()))
        .with_credential_id(Some(credential_id))
        .with_error_message(Some("bad password".to_string()));
    failed.ip_address = Some("10.0.0.7".to_string());
    repo.create(&failed).await.unwrap();

    repo.create(&audit_log(AuditAction::PasswordChange))
        .await
        .unwrap();

    // find_by_id / find_all / update
    let stored = repo.find_by_id(&ok_login.id).await.unwrap().unwrap();
    assert_eq!(stored.session_id.as_deref(), Some("sess-1"));
    assert_eq!(stored.metadata.get("k").map(String::as_str), Some("v"));
    assert_eq!(repo.find_all().await.unwrap().len(), 3);

    let mut edited = stored.clone();
    edited.success = false;
    repo.update(&edited).await.unwrap();
    assert!(
        !repo
            .find_by_id(&ok_login.id)
            .await
            .unwrap()
            .unwrap()
            .success
    );

    // Filters
    assert_eq!(repo.find_by_user("tester").await.unwrap().len(), 3);
    assert_eq!(repo.find_by_identity(&identity_id).await.unwrap().len(), 1);
    assert_eq!(
        repo.find_by_action(&AuditAction::LoginFailed)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(repo.find_failures().await.unwrap().len(), 2);
    let sensitive = repo.find_security_sensitive().await.unwrap();
    assert_eq!(sensitive.len(), 3);
    assert_eq!(repo.find_by_ip("10.0.0.7").await.unwrap().len(), 1);

    let now = chrono::Utc::now();
    assert_eq!(
        repo.find_by_time_range(now - Duration::hours(1), now + Duration::hours(1))
            .await
            .unwrap()
            .len(),
        3
    );
    assert!(repo
        .find_by_time_range(now + Duration::hours(2), now + Duration::hours(3))
        .await
        .unwrap()
        .is_empty());

    // Statistics
    let stats = repo.get_statistics().await.unwrap();
    assert_eq!(stats.total_logs, 3);
    assert_eq!(stats.failed_operations, 2);
    assert_eq!(stats.recent_login_attempts, 2);
    assert_eq!(stats.active_users_last_week, 1);

    // Cleanup only removes rows older than the cutoff.
    assert_eq!(repo.cleanup_old_logs(7).await.unwrap(), 0);
    assert_eq!(repo.cleanup_old_logs(0).await.unwrap(), 3);
    assert_eq!(repo.find_all().await.unwrap().len(), 0);

    // Delete trait method.
    let keep = audit_log(AuditAction::Logout);
    repo.create(&keep).await.unwrap();
    assert!(repo.delete(&keep.id).await.unwrap());
    assert!(!repo.delete(&keep.id).await.unwrap());
}

#[tokio::test]
async fn audit_log_clear_identity_and_credential_references() {
    let db = test_db().await;
    insert_audit_user(&db).await;

    let identities = IdentityRepository::new(db.clone());
    identities
        .create(&sample_identity("detach owner"))
        .await
        .unwrap();
    let identity_id = identities.find_all().await.unwrap()[0].id;
    let credentials = CredentialRepository::new(db.clone());
    credentials
        .create(&sample_credential(identity_id, "detach cred"))
        .await
        .unwrap();
    let credential_id = credentials.find_all().await.unwrap()[0].id;

    let repo = AuditLogRepository::new(db.clone());
    repo.create(
        &audit_log(AuditAction::Login)
            .with_identity_id(Some(identity_id))
            .with_credential_id(Some(credential_id)),
    )
    .await
    .unwrap();
    repo.create(&audit_log(AuditAction::Logout).with_identity_id(Some(identity_id)))
        .await
        .unwrap();
    // A third log without references must not be counted or touched.
    repo.create(&audit_log(AuditAction::PasswordChange))
        .await
        .unwrap();

    assert_eq!(
        repo.clear_credential_reference(&credential_id)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        repo.clear_identity_reference(&identity_id).await.unwrap(),
        2
    );
    // Clearing again is a no-op with a zero count.
    assert_eq!(
        repo.clear_identity_reference(&identity_id).await.unwrap(),
        0
    );

    // The referenced rows can now be deleted (that is the point of the
    // detaching helpers), while the audit trail survives with NULL refs.
    assert!(credentials.delete(&credential_id).await.unwrap());
    assert!(identities.delete(&identity_id).await.unwrap());

    let survivors = repo.find_all().await.unwrap();
    assert_eq!(survivors.len(), 3);
    assert!(survivors.iter().all(|log| log.identity_id.is_none()));
    assert!(survivors.iter().all(|log| log.credential_id.is_none()));
}

#[tokio::test]
async fn audit_log_update_persists_credential_reference() {
    let db = test_db().await;
    insert_audit_user(&db).await;

    // audit_logs carries FKs to identities/credentials; seed both parents.
    let identities = IdentityRepository::new(db.clone());
    identities
        .create(&sample_identity("audit updater"))
        .await
        .unwrap();
    let identity_id = identities.find_all().await.unwrap()[0].id;
    let credentials = CredentialRepository::new(db.clone());
    credentials
        .create(&sample_credential(identity_id, "updated cred"))
        .await
        .unwrap();
    let credential_id = credentials.find_all().await.unwrap()[0].id;

    let repo = AuditLogRepository::new(db);
    let log = audit_log(AuditAction::Login).with_credential_id(Some(credential_id));
    repo.create(&log).await.unwrap();

    // The update path serializes the credential reference as well.
    let updated = log.clone().with_identity_id(Some(identity_id));
    repo.update(&updated).await.unwrap();

    let fetched = repo.find_by_id(&log.id).await.unwrap().unwrap();
    assert_eq!(fetched.credential_id, Some(credential_id));
    assert_eq!(fetched.identity_id, Some(identity_id));
}
