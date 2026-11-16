use crate::auth::auto_lock_cached::CachedAutoLockManager;
use crate::auth::{EnhancedAutoLockConfig, Session};
use crate::models::auto_lock_policy::{AutoLockPolicy, AutoLockSecurityLevel};
use crate::storage::AutoLockPolicyRepository;
use crate::storage::Database;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

async fn policy_repository() -> Arc<AutoLockPolicyRepository> {
    let db = Database::in_memory().await.expect("in-memory database");
    db.migrate().await.expect("migrate");
    Arc::new(AutoLockPolicyRepository::new(Arc::new(db)))
}

#[tokio::test]
async fn test_user_policy_from_repository_governs_sessions() {
    let repo = policy_repository().await;
    let user = Uuid::new_v4();
    let policy = repo
        .create(&AutoLockPolicy::new(
            "Strict".to_string(),
            AutoLockSecurityLevel::Maximum, // max_concurrent_sessions: 1
            3600,
        ))
        .await
        .unwrap();
    repo.assign_to_user(&policy.id, &user).await.unwrap();

    let manager =
        CachedAutoLockManager::new(EnhancedAutoLockConfig::default()).with_policy_repository(repo);

    // The first add resolves the policy from the repository (and caches it).
    let s1 = Session::new(user.to_string(), Duration::from_secs(3600));
    manager.add_session(s1).await.unwrap();

    // The policy's single-session limit rejects the second add.
    let s2 = Session::new(user.to_string(), Duration::from_secs(3600));
    let err = manager.add_session(s2).await.unwrap_err();
    assert!(err.contains("Maximum concurrent sessions"), "got: {err}");
}

#[tokio::test]
async fn test_default_policy_fallback_for_unassigned_users() {
    let repo = policy_repository().await;
    let default = repo
        .create(&AutoLockPolicy::new(
            "Company Default".to_string(),
            AutoLockSecurityLevel::Low, // max_concurrent_sessions: 10
            1800,
        ))
        .await
        .unwrap();
    repo.set_as_default(&default.id).await.unwrap();

    let manager =
        CachedAutoLockManager::new(EnhancedAutoLockConfig::default()).with_policy_repository(repo);

    // Neither user has an assignment, so both resolve through the default
    // policy. Its limit is 10 — past the config default of 5 — proving the
    // policy (not the config) governs.
    for user in [Uuid::new_v4(), Uuid::new_v4()] {
        for _ in 0..6 {
            let session = Session::new(user.to_string(), Duration::from_secs(3600));
            manager.add_session(session).await.unwrap();
        }
    }

    // The 11th session for one user finally trips the default policy.
    let extra = Session::new(Uuid::new_v4().to_string(), Duration::from_secs(3600));
    manager.add_session(extra).await.unwrap(); // still fine for a third user

    let busy = Uuid::new_v4();
    for _ in 0..10 {
        let session = Session::new(busy.to_string(), Duration::from_secs(3600));
        manager.add_session(session).await.unwrap();
    }
    let one_too_many = Session::new(busy.to_string(), Duration::from_secs(3600));
    assert!(manager.add_session(one_too_many).await.is_err());
}

#[tokio::test]
async fn test_compliance_recheck_enforces_policy_inactivity() {
    let repo = policy_repository().await;
    let user = Uuid::new_v4();
    let policy = repo
        .create(&AutoLockPolicy::new(
            "Idle Lock".to_string(),
            AutoLockSecurityLevel::Low, // absolute 7200: never trips here
            1,                          // inactivity timeout: 1 second
        ))
        .await
        .unwrap();
    repo.assign_to_user(&policy.id, &user).await.unwrap();

    // A zero cache TTL forces the compliance recheck on every validation.
    let manager = CachedAutoLockManager::with_cache_config(
        EnhancedAutoLockConfig::default(),
        Duration::from_secs(0),
        1000,
    )
    .with_policy_repository(repo);

    let session = Session::new(user.to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    // Fresh session: the policy check passes.
    assert!(manager.is_session_valid(&session_id).await);

    // Past the policy's inactivity timeout the recheck fails it.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!manager.is_session_valid(&session_id).await);
}

#[tokio::test]
async fn test_uuid_user_without_repository_falls_back_to_session_validity() {
    // A UUID-shaped user on a repository-less manager resolves through
    // the no-policy tail instead of the non-UUID early return.
    let manager = CachedAutoLockManager::with_cache_config(
        EnhancedAutoLockConfig::default(),
        Duration::from_secs(0), // force the compliance recheck
        1000,
    );

    let session = Session::new(Uuid::new_v4().to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    // No policy governs the session, so the recheck falls back to plain
    // session validity.
    assert!(manager.is_session_valid(&session_id).await);
}

#[tokio::test]
async fn test_policy_repository_error_surfaces() {
    let db = Database::in_memory().await.expect("in-memory database");
    db.migrate().await.expect("migrate");
    let pool = db.pool().clone();
    let repo = Arc::new(AutoLockPolicyRepository::new(Arc::new(db)));

    let manager =
        CachedAutoLockManager::new(EnhancedAutoLockConfig::default()).with_policy_repository(repo);

    // Closing the underlying pool makes the policy lookup fail; the
    // error must surface instead of being swallowed into a default.
    pool.close().await;
    let session = Session::new(Uuid::new_v4().to_string(), Duration::from_secs(3600));
    let err = manager.add_session(session).await.unwrap_err();
    assert!(err.contains("Failed to fetch policy"), "got: {err}");
}

#[tokio::test]
async fn test_compliance_recheck_enforces_policy_absolute_timeout() {
    let repo = policy_repository().await;
    let user = Uuid::new_v4();
    let mut policy = AutoLockPolicy::new(
        "Flash".to_string(),
        AutoLockSecurityLevel::Low,
        3600, // inactivity: never trips within the test's lifetime
    );
    // A one-second lifetime so only the absolute-timeout check can fail.
    policy.absolute_timeout_secs = 1;
    let policy = repo.create(&policy).await.unwrap();
    repo.assign_to_user(&policy.id, &user).await.unwrap();

    let manager = CachedAutoLockManager::with_cache_config(
        EnhancedAutoLockConfig::default(),
        Duration::from_secs(0), // force the compliance recheck
        1000,
    )
    .with_policy_repository(repo);

    let session = Session::new(user.to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    // Fresh session: the lifetime check passes.
    assert!(manager.is_session_valid(&session_id).await);

    // Past the one-second absolute timeout the recheck fails it (the
    // lifetime is measured in whole seconds, so wait past two).
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(!manager.is_session_valid(&session_id).await);
}
