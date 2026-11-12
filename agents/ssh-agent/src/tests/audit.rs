use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn audit_sign_with_digest_writes_log_inside_runtime() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    std::env::set_var("PERSONA_DB_PATH", &db_path);

    // audit_logs has FKs to identities/credentials: seed real rows first.
    let db = persona_core::Database::from_file(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let identity_repo = persona_core::storage::IdentityRepository::new(db.clone());
    let identity = persona_core::models::Identity::new(
        "audit-owner".to_string(),
        persona_core::models::IdentityType::Personal,
    );
    identity_repo.create(&identity).await.unwrap();
    // credential_id also carries an FK to credentials: seed that row too.
    use persona_core::models::{Credential, CredentialType, SecurityLevel};
    let mut cred = Credential::new(
        identity.id,
        "audit-key".to_string(),
        CredentialType::SshKey,
        SecurityLevel::High,
        vec![7u8; 32],
        None,
    );
    cred.encrypted_data = vec![7u8; 32];
    let credential_repo = persona_core::storage::CredentialRepository::new(db.clone());
    credential_repo.create(&cred).await.unwrap();
    let credential = cred.id;
    drop(db);

    audit_sign_with_digest(&identity.id, &credential, b"signed-bytes").unwrap();

    // The audit write is spawned in the background; poll briefly for it.
    let mut found = false;
    let mut last_err = String::new();
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        match persona_core::Database::from_file(&db_path).await {
            Ok(db) => match db.migrate().await {
                Ok(()) => {
                    let repo = persona_core::storage::AuditLogRepository::new(db.clone());
                    match repo
                        .find_by_action(&persona_core::models::AuditAction::Custom(
                            "ssh_sign".to_string(),
                        ))
                        .await
                    {
                        Ok(logs) if !logs.is_empty() => {
                            found = true;
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => last_err = format!("find: {e}"),
                    }
                }
                Err(e) => last_err = format!("migrate: {e}"),
            },
            Err(e) => last_err = format!("open: {e}"),
        }
    }
    std::env::remove_var("PERSONA_DB_PATH");
    assert!(
        found,
        "ssh_sign audit entry should be persisted; last_err={last_err}"
    );
}

/// audit_sign 复用加载期打开的连接（audit 批2 #9）：Agent 带着已迁移的
/// Database 时不再每次签名新开 DB + 跑 migrate（热路径锁竞争）。判别器：
/// 把 PERSONA_DB_PATH 指到垃圾路径——若回落到开库路径会写不进、审计行
/// 永不出现；走缓存连接则正常落库。
#[tokio::test(flavor = "multi_thread")]
async fn audit_sign_reuses_loaded_database_connection() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("audit.db");

    let db = persona_core::Database::from_file(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let identity_repo = persona_core::storage::IdentityRepository::new(db.clone());
    let identity = persona_core::models::Identity::new(
        "cached-owner".to_string(),
        persona_core::models::IdentityType::Personal,
    );
    identity_repo.create(&identity).await.unwrap();
    use persona_core::models::{Credential, CredentialType, SecurityLevel};
    let mut cred = Credential::new(
        identity.id,
        "cached-key".to_string(),
        CredentialType::SshKey,
        SecurityLevel::High,
        vec![3u8; 32],
        None,
    );
    cred.encrypted_data = vec![3u8; 32];
    persona_core::storage::CredentialRepository::new(db.clone())
        .create(&cred)
        .await
        .unwrap();

    // 垃圾路径：若实现回落 resolve_persona_db_path 开库，写不进。
    let garbage = dir.path().join("garbage");
    std::fs::create_dir(&garbage).unwrap();
    std::env::set_var("PERSONA_DB_PATH", &garbage);

    let mut agent = Agent::new();
    agent.audit_db = Arc::new(Some(db.clone()));
    agent
        .audit_sign(&identity.id, &cred.id, b"cached-bytes")
        .unwrap();

    // 后台写轮询：走缓存连接才会出现 ssh_sign 行。
    let mut found = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let repo = persona_core::storage::AuditLogRepository::new(db.clone());
        match repo
            .find_by_action(&persona_core::models::AuditAction::Custom(
                "ssh_sign".to_string(),
            ))
            .await
        {
            Ok(logs) if !logs.is_empty() => {
                found = true;
                break;
            }
            _ => {}
        }
    }
    std::env::remove_var("PERSONA_DB_PATH");
    assert!(found, "audit 必须复用已加载连接写入，而非每次重开 DB");
}

#[test]
fn audit_sign_with_digest_sync_fallback_builds_runtime() {
    // Outside any tokio runtime this exercises the synchronous fallback
    // path that spins up its own current-thread runtime.
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("audit-sync.db");
    std::env::set_var("PERSONA_DB_PATH", &db_path);

    // Seed the FK rows synchronously.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let identity_id = rt.block_on(async {
        let db = persona_core::Database::from_file(&db_path).await.unwrap();
        db.migrate().await.unwrap();
        let identity_repo = persona_core::storage::IdentityRepository::new(db.clone());
        let identity = persona_core::models::Identity::new(
            "sync-audit".to_string(),
            persona_core::models::IdentityType::Personal,
        );
        identity_repo.create(&identity).await.unwrap();
        use persona_core::models::{Credential, CredentialType, SecurityLevel};
        let mut cred = Credential::new(
            identity.id,
            "sync-key".to_string(),
            CredentialType::SshKey,
            SecurityLevel::High,
            vec![9u8; 32],
            None,
        );
        cred.encrypted_data = vec![9u8; 32];
        let credential_repo = persona_core::storage::CredentialRepository::new(db.clone());
        credential_repo.create(&cred).await.unwrap();
        (identity.id, cred.id)
    });

    let result = std::thread::spawn(move || {
        audit_sign_with_digest(&identity_id.0, &identity_id.1, b"sync-payload")
    })
    .join()
    .unwrap();
    result.unwrap();
    std::env::remove_var("PERSONA_DB_PATH");
}
