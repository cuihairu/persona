use super::*;

#[tokio::test]
async fn test_sensitive_activity_timeout() {
    let mut config = EnhancedAutoLockConfig::default();
    config.base.sensitive_operation_timeout_secs = 1;
    config.force_lock_sensitive = true;

    let manager = AutoLockManager::new(config);

    let mut session = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();

    // First perform a sensitive operation to set the timestamp
    session.touch_sensitive();
    manager.add_session(session).await.unwrap();

    // Wait for sensitive timeout
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Sensitive activity should now fail
    assert!(manager
        .update_sensitive_activity(&session_id)
        .await
        .is_err());
    assert!(!manager.is_session_valid(&session_id).await);
}

#[tokio::test]
async fn test_requires_sensitive_auth_flag() {
    let base = AutoLockConfig {
        require_reauth_sensitive: true,
        sensitive_operation_timeout_secs: 1,
        ..Default::default()
    };
    let config = EnhancedAutoLockConfig {
        base,
        ..Default::default()
    };

    let manager = AutoLockManager::new(config);
    let session = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();

    manager.add_session(session).await.unwrap();

    // Without any sensitive activity recorded we should require re-auth.
    assert!(manager.requires_sensitive_auth(&session_id).await);

    // Update sensitive activity to reset timer.
    manager
        .update_sensitive_activity(&session_id)
        .await
        .unwrap();
    assert!(!manager.requires_sensitive_auth(&session_id).await);

    // Wait past the sensitive timeout to trigger re-auth again.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(manager.requires_sensitive_auth(&session_id).await);
}

#[tokio::test]
async fn test_requires_sensitive_auth_disabled_and_unknown() {
    // Flag off -> short-circuit false.
    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default());
    assert!(!manager.requires_sensitive_auth("missing").await);

    // Flag on + unknown session -> require auth.
    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            require_reauth_sensitive: true,
            sensitive_operation_timeout_secs: 300,
            ..Default::default()
        },
        ..Default::default()
    };
    let manager = AutoLockManager::new(config);
    assert!(manager.requires_sensitive_auth("missing").await);
}

#[tokio::test]
async fn test_update_sensitive_activity_unknown_session() {
    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default());
    assert_eq!(
        manager
            .update_sensitive_activity("missing")
            .await
            .unwrap_err(),
        "Session not found"
    );
}

#[tokio::test]
async fn test_force_lock_sensitive_within_timeout_refreshes_timer() {
    // force_lock_sensitive with a fresh sensitive timestamp: the inner
    // lock branch is skipped and the timer is merely refreshed.
    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            sensitive_operation_timeout_secs: 3600,
            ..Default::default()
        },
        force_lock_sensitive: true,
        ..Default::default()
    };

    let manager = AutoLockManager::new(config);
    let mut session = Session::new("u".to_string(), Duration::from_secs(3600));
    session.touch_sensitive();
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    assert!(manager.update_sensitive_activity(&session_id).await.is_ok());
    assert!(manager.is_session_valid(&session_id).await);
}

#[tokio::test]
async fn test_force_lock_sensitive_fresh_session_first_touch_does_not_lock() {
    // force_lock_sensitive must not treat a session with no sensitive
    // history (freshly unlocked) as timed out: the first sensitive
    // operation refreshes the timer instead of locking the session.
    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            sensitive_operation_timeout_secs: 0,
            ..Default::default()
        },
        force_lock_sensitive: true,
        ..Default::default()
    };

    let manager = AutoLockManager::new(config);
    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    assert!(manager.update_sensitive_activity(&session_id).await.is_ok());
    assert!(manager.is_session_valid(&session_id).await);
    assert!(
        !manager
            .get_session(&session_id)
            .await
            .expect("session exists")
            .locked
    );
}
