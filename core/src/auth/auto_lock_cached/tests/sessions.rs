use crate::auth::auto_lock::AutoLockEvent;
use crate::auth::auto_lock_cached::CachedAutoLockManager;
use crate::auth::{EnhancedAutoLockConfig, Session};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_concurrent_session_limit_enforced() {
    let config = EnhancedAutoLockConfig {
        max_concurrent_sessions: 2,
        ..Default::default()
    };
    let manager = CachedAutoLockManager::new(config);

    for i in 0..2 {
        let session = Session::new("limited-user".to_string(), Duration::from_secs(3600));
        manager.add_session(session).await.unwrap();
        let _ = i;
    }

    // The third session for the same user exceeds the limit.
    let extra = Session::new("limited-user".to_string(), Duration::from_secs(3600));
    let err = manager.add_session(extra).await.unwrap_err();
    assert!(err.contains("Maximum concurrent sessions"), "got: {err}");

    // A different user is unaffected.
    let other = Session::new("other-user".to_string(), Duration::from_secs(3600));
    manager.add_session(other).await.unwrap();
}

#[tokio::test]
async fn test_update_activity_and_unknown_session() {
    let manager = CachedAutoLockManager::new(EnhancedAutoLockConfig::default());

    let session = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    manager.update_activity(&session_id).await.unwrap();

    // Unknown session id surfaces a "not found" error, and validity is false.
    assert_eq!(
        manager
            .update_activity("no-such-session")
            .await
            .unwrap_err(),
        "Session not found"
    );
    assert!(!manager.is_session_valid("no-such-session").await);

    // Clearing caches wipes the session and resets the hit ratio.
    manager.clear_caches().await;
    assert!(!manager.is_session_valid(&session_id).await);
    assert_eq!(manager.cache_hit_ratio().await, 0.0);
}

#[tokio::test]
async fn test_update_activity_after_grace_period_touches_and_emits() {
    let manager = CachedAutoLockManager::new(EnhancedAutoLockConfig::default());

    let session = Session::new("user123".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    // The Debug rendering finishes non-exhaustively over the internal
    // RwLocks; it must still produce output.
    let rendered = format!("{:?}", manager);
    assert!(
        rendered.contains("CachedAutoLockManager"),
        "got: {rendered}"
    );

    // The callback is registered after the add, so only the real update
    // below (past the 100 ms grace window) reaches the channel.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager
        .register_callback(Arc::new(move |event| {
            let _ = tx.send(event);
        }))
        .await;

    tokio::time::sleep(Duration::from_millis(150)).await;
    manager.update_activity(&session_id).await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("activity event must arrive")
        .expect("channel open");
    match event {
        AutoLockEvent::Activity { session_id: id } => assert_eq!(id, session_id),
        other => panic!("expected Activity, got {other:?}"),
    }

    // An immediate follow-up lands inside the grace window: it succeeds
    // but skips the processing path, so no second event is emitted.
    manager.update_activity(&session_id).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err(),
        "grace-window update must not emit"
    );
}
