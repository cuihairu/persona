use super::*;

#[tokio::test]
async fn test_lock_unlock_unknown_session_errors() {
    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default());
    assert_eq!(
        manager.lock_session("missing").await.unwrap_err(),
        "Session not found"
    );
    assert_eq!(
        manager.unlock_session("missing").await.unwrap_err(),
        "Session not found"
    );
}

#[tokio::test]
async fn test_is_session_valid_checks_both_timeouts_when_fresh() {
    // inactivity enabled but not yet idle, absolute enabled but not yet
    // exceeded: both checks run and neither trips.
    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            inactivity_timeout_secs: 60,
            absolute_timeout_secs: 3600,
            ..Default::default()
        },
        ..Default::default()
    };
    let manager = AutoLockManager::new(config);
    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();
    assert!(manager.is_session_valid(&session_id).await);

    // Same with the absolute timeout disabled: neither check trips.
    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            inactivity_timeout_secs: 60,
            absolute_timeout_secs: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let manager = AutoLockManager::new(config);
    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();
    assert!(manager.is_session_valid(&session_id).await);
}

#[tokio::test]
async fn test_is_session_valid_inactivity_timeout_locks() {
    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            inactivity_timeout_secs: 1,
            absolute_timeout_secs: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let manager = AutoLockManager::new(config);
    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!manager.is_session_valid(&session_id).await);
}

#[tokio::test]
async fn test_is_session_valid_absolute_timeout_locks() {
    // The session itself is not expired (3600s validity), so is_valid
    // cannot short-circuit: the absolute-timeout check must trip.
    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            inactivity_timeout_secs: 0,
            absolute_timeout_secs: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let manager = AutoLockManager::new(config);
    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();
    // get_lifetime_seconds truncates to whole seconds, so the 1s timeout
    // needs a full extra second of headroom.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(!manager.is_session_valid(&session_id).await);
}
