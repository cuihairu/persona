use super::*;

#[tokio::test]
async fn test_auto_lock_manager_creation() {
    let config = AutoLockConfig::default();
    let manager = AutoLockManager::with_basic_config(config);

    let stats = manager.get_statistics().await;
    assert_eq!(stats.total_sessions, 0);
    assert_eq!(stats.active_sessions, 0);
}

#[tokio::test]
async fn test_session_management() {
    let config = AutoLockConfig::default();
    let manager = AutoLockManager::with_basic_config(config);

    let session = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();

    // Add session
    assert!(manager.add_session(session).await.is_ok());
    assert!(manager.is_session_valid(&session_id).await);

    // Update activity
    assert!(manager.update_activity(&session_id).await.is_ok());

    // Lock session
    assert!(manager.lock_session(&session_id).await.is_ok());
    assert!(!manager.is_session_valid(&session_id).await);

    // Unlock session
    assert!(manager.unlock_session(&session_id).await.is_ok());
    assert!(manager.is_session_valid(&session_id).await);

    // Remove session
    manager.remove_session(&session_id).await;
    assert!(!manager.is_session_valid(&session_id).await);
}

#[tokio::test]
async fn test_callback_registration() {
    let config = AutoLockConfig::default();
    let manager = AutoLockManager::with_basic_config(config);

    let callback_count = Arc::new(AtomicU32::new(0));
    let callback_count_clone = callback_count.clone();

    let callback: AutoLockCallback = Arc::new(move |_| {
        callback_count_clone.fetch_add(1, Ordering::Relaxed);
    });

    manager.register_callback(callback).await;

    let session = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();

    manager.add_session(session).await.unwrap();
    manager.lock_session(&session_id).await.unwrap();

    // Give some time for async callbacks
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(callback_count.load(Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn test_concurrent_session_limit() {
    let config = EnhancedAutoLockConfig {
        max_concurrent_sessions: 2,
        ..Default::default()
    };

    let manager = AutoLockManager::new(config);

    let session1 = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session2 = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session3 = Session::new("user123".to_string(), Duration::from_secs(3600));

    // Should be able to add 2 sessions
    assert!(manager.add_session(session1).await.is_ok());
    assert!(manager.add_session(session2).await.is_ok());

    // Third session should fail
    assert!(manager.add_session(session3).await.is_err());
}

#[tokio::test]
async fn test_get_session_and_user_sessions() {
    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default());

    let alice = Session::new("alice".to_string(), Duration::from_secs(3600));
    let bob = Session::new("bob".to_string(), Duration::from_secs(3600));
    let alice_id = alice.id.clone();
    manager.add_session(alice).await.unwrap();
    manager.add_session(bob).await.unwrap();

    assert_eq!(manager.get_session(&alice_id).await.unwrap().id, alice_id);
    assert!(manager.get_session("missing").await.is_none());

    assert_eq!(manager.get_user_sessions("alice").await.len(), 1);
    assert_eq!(manager.get_user_sessions("bob").await.len(), 1);
    assert!(manager.get_user_sessions("carol").await.is_empty());
}

#[tokio::test]
async fn test_get_statistics_counts() {
    let manager = AutoLockManager::with_basic_config(AutoLockConfig {
        inactivity_timeout_secs: 1,
        absolute_timeout_secs: 0,
        ..Default::default()
    });

    let s1 = Session::new("u".to_string(), Duration::from_secs(3600));
    let s2 = Session::new("u".to_string(), Duration::from_secs(3600));
    let s1_id = s1.id.clone();
    manager.add_session(s1).await.unwrap();
    manager.add_session(s2).await.unwrap();
    manager.lock_session(&s1_id).await.unwrap();

    // Let both sessions become idle (locked one no longer counts as valid).
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let stats = manager.get_statistics().await;
    assert_eq!(stats.total_sessions, 2);
    assert_eq!(stats.locked_sessions, 1);
    assert_eq!(stats.active_sessions, 1);
    assert_eq!(stats.idle_sessions, 1);
    assert_eq!(stats.max_concurrent_sessions, 5);
}

#[tokio::test]
async fn test_cleanup_expired_sessions() {
    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default());

    let short = Session::new("u".to_string(), Duration::from_secs(1));
    let long = Session::new("u".to_string(), Duration::from_secs(3600));
    manager.add_session(short).await.unwrap();
    manager.add_session(long).await.unwrap();

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let removed = manager.cleanup_expired_sessions().await;
    assert_eq!(removed, 1);
    assert_eq!(manager.get_statistics().await.total_sessions, 1);
}

#[tokio::test]
async fn test_stop_background_monitoring_without_start_is_noop() {
    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default());
    manager.stop_background_monitoring().await;
}

/// `update_base_config` flips the sensitive-operation re-authentication gate
/// in place (the propagation path from the service layer's
/// configure_auto_lock), without rebuilding the manager.
#[tokio::test]
async fn update_base_config_toggles_sensitive_reauth_gate_in_place() {
    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default());
    let session = Session::new("gate-user".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    // The default config leaves the gate off.
    assert!(!manager.requires_sensitive_auth(&session_id).await);

    // Turn the gate on in place: a session with no sensitive history is
    // immediately required to re-authenticate.
    manager.update_base_config(AutoLockConfig {
        require_reauth_sensitive: true,
        sensitive_operation_timeout_secs: 0,
        ..AutoLockConfig::default()
    });
    assert!(manager.requires_sensitive_auth(&session_id).await);

    // timeout = 0 → even freshly recorded sensitive activity counts as
    // expired (elapsed > 0 is always true).
    manager
        .update_sensitive_activity(&session_id)
        .await
        .unwrap();
    assert!(manager.requires_sensitive_auth(&session_id).await);

    // Turning the gate back off also takes effect in place, and the session
    // is still tracked.
    manager.update_base_config(AutoLockConfig::default());
    assert!(!manager.requires_sensitive_auth(&session_id).await);
    assert!(manager.get_session(&session_id).await.is_some());
}
