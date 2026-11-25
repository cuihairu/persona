use super::*;

#[test]
fn test_enhanced_config_serde_defaults() {
    let config: EnhancedAutoLockConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(config.warning_time_secs, 60);
    assert_eq!(config.max_concurrent_sessions, 5);
    assert!(!config.enable_warnings);
    // Secure by default: force locking after sensitive operations is
    // tightened to on by the serde default.
    assert!(config.force_lock_sensitive);
    assert_eq!(config.activity_grace_period_secs, 5);
    assert_eq!(config.background_check_interval_secs, 30);

    // From<AutoLockConfig> keeps the base and applies the defaults.
    let from_base: EnhancedAutoLockConfig = AutoLockConfig::default().into();
    assert_eq!(from_base.base.inactivity_timeout_secs, 900);
    assert_eq!(from_base.warning_time_secs, 60);
}

#[tokio::test]
async fn test_update_activity_unknown_session() {
    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default());
    assert_eq!(
        manager.update_activity("missing").await.unwrap_err(),
        "Session not found"
    );
}

#[tokio::test]
async fn test_update_activity_grace_period_skips_emit() {
    let config = EnhancedAutoLockConfig::default(); // grace period 5s
    let manager = AutoLockManager::new(config);

    let activity_count = Arc::new(AtomicU32::new(0));
    let counter = activity_count.clone();
    manager
        .register_callback(Arc::new(move |event| {
            if matches!(event, AutoLockEvent::Activity { .. }) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }))
        .await;

    let session = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(activity_count.load(Ordering::Relaxed), 1);

    // Second call inside the grace period updates nothing and emits no event.
    manager.update_activity(&session_id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(activity_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_update_activity_past_zero_grace_touches_and_emits() {
    // A zero grace period disables the rapid-call short circuit, so every
    // update_activity call touches the session and emits Activity again.
    let config = EnhancedAutoLockConfig {
        activity_grace_period_secs: 0,
        ..Default::default()
    };
    let manager = AutoLockManager::new(config);

    let activity_count = Arc::new(AtomicU32::new(0));
    let counter = activity_count.clone();
    manager
        .register_callback(Arc::new(move |event| {
            if matches!(event, AutoLockEvent::Activity { .. }) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }))
        .await;

    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(activity_count.load(Ordering::Relaxed), 1);

    manager.update_activity(&session_id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(activity_count.load(Ordering::Relaxed), 2);
}
