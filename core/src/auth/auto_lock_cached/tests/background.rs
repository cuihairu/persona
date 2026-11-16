use crate::auth::auto_lock::{AutoLockEvent, LockReason};
use crate::auth::auto_lock_cached::CachedAutoLockManager;
use crate::auth::{EnhancedAutoLockConfig, Session};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_background_monitoring_locks_expired_sessions() {
    let config = EnhancedAutoLockConfig {
        base: crate::auth::AutoLockConfig {
            inactivity_timeout_secs: 3600, // must not trigger first
            ..Default::default()
        },
        enable_warnings: false,
        ..Default::default()
    };
    let manager = CachedAutoLockManager::new(config);

    // A zero-lifetime session is expired the moment it is added.
    let session = Session::new("user123".to_string(), Duration::from_secs(0));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager
        .register_callback(Arc::new(move |event| {
            let _ = tx.send(event);
        }))
        .await;

    manager
        .start_background_monitoring_with_interval(Duration::from_millis(10))
        .await
        .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a lock event must arrive")
        .expect("channel open");
    match event {
        AutoLockEvent::Locked {
            session_id: id,
            reason,
        } => {
            assert_eq!(id, session_id);
            assert_eq!(reason, LockReason::AbsoluteTimeout);
        }
        other => panic!("expected Locked, got {other:?}"),
    }

    // The monitor also stops cleanly, and starting twice is a no-op.
    manager
        .start_background_monitoring_with_interval(Duration::from_millis(10))
        .await
        .unwrap();
    manager.stop_background_monitoring().await;
    manager.stop_background_monitoring().await; // second stop is a no-op
}

#[tokio::test]
async fn test_background_monitoring_warns_before_inactivity_lock() {
    let config = EnhancedAutoLockConfig {
        base: crate::auth::AutoLockConfig {
            inactivity_timeout_secs: 3,
            ..Default::default()
        },
        warning_time_secs: 2, // warn once idle passes 1s
        enable_warnings: true,
        ..Default::default()
    };
    let manager = CachedAutoLockManager::new(config);

    let session = Session::new("user456".to_string(), Duration::from_secs(3600));
    manager.add_session(session).await.unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager
        .register_callback(Arc::new(move |event| {
            let _ = tx.send(event);
        }))
        .await;

    manager
        .start_background_monitoring_with_interval(Duration::from_millis(50))
        .await
        .unwrap();

    // First event: the single warning while still inside the window.
    let first = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("warning must arrive")
        .expect("channel open");
    match first {
        AutoLockEvent::LockPending {
            session_id,
            seconds_remaining,
        } => {
            assert!(!session_id.is_empty());
            assert!(seconds_remaining <= 3, "got {seconds_remaining}");
        }
        other => panic!("expected LockPending, got {other:?}"),
    }

    // Then the lock once the full inactivity timeout elapses.
    let second = tokio::time::timeout(Duration::from_secs(4), rx.recv())
        .await
        .expect("lock must arrive")
        .expect("channel open");
    match second {
        AutoLockEvent::Locked { session_id, reason } => {
            assert!(!session_id.is_empty());
            assert_eq!(reason, LockReason::Inactivity);
        }
        other => panic!("expected Locked, got {other:?}"),
    }

    manager.stop_background_monitoring().await;

    // The background loop fed the check-time metrics.
    let metrics = manager.get_performance_metrics().await;
    assert!(metrics.background_checks_performed > 0);
    assert!(metrics.background_check_time_us >= 0.0);
}
