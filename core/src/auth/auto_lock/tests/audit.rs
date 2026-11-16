use super::*;

#[tokio::test]
async fn test_audit_logging_on_lock_unlock() {
    let db = Database::in_memory().await.expect("in-memory db");
    db.migrate().await.expect("migrate");
    let audit_repo = AuditLogRepository::new(db.clone());

    let manager = AutoLockManager::with_basic_config(AutoLockConfig::default())
        .with_audit_repo(AuditLogRepository::new(db.clone()));

    // audit_logs.user_id has a FK to user_auth, so the user must exist.
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO user_auth (user_id, enabled_factors, failed_attempts, created_at, updated_at)
             VALUES (?, '[]', 0, ?, ?)",
    )
    .bind(user.to_string())
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(db.pool())
    .await
    .unwrap();
    manager.set_current_user(user).await;

    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    manager.lock_session(&session_id).await.unwrap();
    manager.unlock_session(&session_id).await.unwrap();
    manager.clear_current_user().await;

    // Both events were written with the session id attached.
    let locked = audit_repo
        .find_by_action(&AuditAction::SessionLocked)
        .await
        .unwrap();
    assert!(locked
        .iter()
        .any(|l| l.session_id.as_deref() == Some(session_id.as_str())
            && l.user_id.as_deref() == Some(user.to_string().as_str())));
    let unlocked = audit_repo
        .find_by_action(&AuditAction::SessionUnlocked)
        .await
        .unwrap();
    assert!(unlocked
        .iter()
        .any(|l| l.session_id.as_deref() == Some(session_id.as_str())));
}

/// 审计写库后经 Emitter 上报（session_locked/session_unlocked wire 事件）；
/// `set_event_emitter(None)` 摘除后只落本地库、不再上报。
#[tokio::test]
async fn audit_events_feed_emitter_until_detached() {
    use crate::events::testing::{eventually, FakeSink};
    use std::sync::Arc;

    let db = Database::in_memory().await.expect("in-memory db");
    db.migrate().await.expect("migrate");

    // audit_logs.user_id has a FK to user_auth, so the user must exist.
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO user_auth (user_id, enabled_factors, failed_attempts, created_at, updated_at)
             VALUES (?, '[]', 0, ?, ?)",
    )
    .bind(user.to_string())
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(db.pool())
    .await
    .unwrap();

    let mut manager = AutoLockManager::with_basic_config(AutoLockConfig::default())
        .with_audit_repo(AuditLogRepository::new(db.clone()));
    manager.set_current_user(user).await;

    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();

    let sink = Arc::new(FakeSink::default());
    let emitter = crate::events::Emitter::with_config(
        sink.clone(),
        crate::events::EmitterConfig {
            batch_size: 1,
            ..Default::default()
        },
    );
    emitter.start();
    manager.set_event_emitter(Some(emitter.clone()));

    manager.lock_session(&session_id).await.unwrap();
    eventually(|| sink.call_count() >= 1).await;
    assert_eq!(sink.batches()[0][0].action, "session_locked");
    assert_eq!(
        sink.batches()[0][0].session_id.as_deref(),
        Some(session_id.as_str())
    );
    assert_eq!(
        sink.batches()[0][0].user_id.as_deref(),
        Some(user.to_string().as_str())
    );

    manager.unlock_session(&session_id).await.unwrap();
    eventually(|| sink.call_count() >= 2).await;
    assert_eq!(sink.batches()[1][0].action, "session_unlocked");

    // 摘除上报器：审计仍写本地库，但不再上报
    manager.set_event_emitter(None);
    manager.lock_session(&session_id).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(sink.call_count(), 2);
    emitter.stop().await;
}
