use super::*;

/// 后台监控超时落锁的审计行同样上报，且带全 session 上下文
/// （session_id/user_id/details——修复原先裸 action 行的缺陷）。
#[tokio::test]
async fn background_timeout_lock_reports_session_context() {
    use crate::events::testing::{eventually, FakeSink};
    use std::sync::Arc;

    let db = Database::in_memory().await.expect("in-memory db");
    db.migrate().await.expect("migrate");

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

    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            inactivity_timeout_secs: 2,
            absolute_timeout_secs: 0,
            ..Default::default()
        },
        background_check_interval_secs: 1,
        ..Default::default()
    };
    let mut manager =
        AutoLockManager::new(config).with_audit_repo(AuditLogRepository::new(db.clone()));
    manager.set_current_user(user).await;

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

    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();
    manager.start_background_monitoring().await;

    // ~2s 后后台任务按 inactivity 超时落锁并上报
    tokio::time::sleep(Duration::from_millis(2600)).await;
    manager.stop_background_monitoring().await;

    eventually(|| {
        sink.batches()
            .iter()
            .flatten()
            .any(|e| e.action == "session_locked")
    })
    .await;
    let batches = sink.batches();
    let reported = batches
        .iter()
        .flatten()
        .find(|e| e.action == "session_locked")
        .expect("session_locked reported");
    assert_eq!(reported.session_id.as_deref(), Some(session_id.as_str()));
    assert_eq!(reported.user_id.as_deref(), Some(user.to_string().as_str()));
    emitter.stop().await;
}

#[tokio::test]
async fn test_background_monitoring_warns_then_locks() {
    let db = Database::in_memory().await.expect("in-memory db");
    db.migrate().await.expect("migrate");

    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            inactivity_timeout_secs: 2,
            absolute_timeout_secs: 0,
            ..Default::default()
        },
        warning_time_secs: 1,
        enable_warnings: true,
        background_check_interval_secs: 1,
        ..Default::default()
    };
    let manager = AutoLockManager::new(config).with_audit_repo(AuditLogRepository::new(db.clone()));

    let events = Arc::new(std::sync::Mutex::new(Vec::<AutoLockEvent>::new()));
    let sink = events.clone();
    manager
        .register_callback(Arc::new(move |event| {
            sink.lock().unwrap().push(event);
        }))
        .await;

    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    manager.add_session(session).await.unwrap();
    manager.start_background_monitoring().await;

    // Tick 1 (~1s): idle 1s >= warning threshold -> LockPending.
    // Tick 2 (~2s): idle 2s >= inactivity timeout -> Locked(Inactivity).
    tokio::time::sleep(Duration::from_millis(2600)).await;
    manager.stop_background_monitoring().await;

    let got = events.lock().unwrap().clone();
    assert!(got.iter().any(|e| matches!(
        e,
        AutoLockEvent::LockPending {
            seconds_remaining: 1,
            ..
        }
    )));
    assert!(got.iter().any(|e| matches!(
        e,
        AutoLockEvent::Locked {
            reason: LockReason::Inactivity,
            ..
        }
    )));

    // The manager locked the session and the audit trail recorded it.
    let locked = manager.get_session(&session_id).await.unwrap();
    assert!(locked.locked);
    let logs = AuditLogRepository::new(db)
        .find_by_action(&AuditAction::SessionLocked)
        .await
        .unwrap();
    assert!(!logs.is_empty());
}

#[tokio::test]
async fn test_background_monitoring_absolute_timeout_locks() {
    let config = EnhancedAutoLockConfig {
        base: AutoLockConfig {
            inactivity_timeout_secs: 0,
            absolute_timeout_secs: 1,
            ..Default::default()
        },
        background_check_interval_secs: 1,
        ..Default::default()
    };
    let manager = AutoLockManager::new(config);

    let events = Arc::new(std::sync::Mutex::new(Vec::<AutoLockEvent>::new()));
    let sink = events.clone();
    manager
        .register_callback(Arc::new(move |event| {
            sink.lock().unwrap().push(event);
        }))
        .await;

    let session = Session::new("u".to_string(), Duration::from_secs(3600));
    manager.add_session(session).await.unwrap();
    manager.start_background_monitoring().await;

    // Two ticks: on the second one lifetime (~2s) exceeds the 1s absolute timeout.
    tokio::time::sleep(Duration::from_millis(2400)).await;
    manager.stop_background_monitoring().await;
    // Give the spawned callback tasks a chance to run (current-thread runtime).
    tokio::time::sleep(Duration::from_millis(100)).await;

    let got = events.lock().unwrap().clone();
    // Idle check is disabled, so the lock reason is the absolute timeout.
    assert!(got.iter().any(|e| matches!(
        e,
        AutoLockEvent::Locked {
            reason: LockReason::AbsoluteTimeout,
            ..
        }
    )));
}

#[test]
fn should_send_warning_is_disabled_by_config_flags() {
    let info = session_info_with_idle_seconds(120);

    // Warnings disabled entirely.
    let config = EnhancedAutoLockConfig::default();
    assert!(!should_send_warning(&config, &info));

    // Enabled but with a zero threshold.
    let config = EnhancedAutoLockConfig {
        enable_warnings: true,
        warning_time_secs: 0,
        ..Default::default()
    };
    assert!(!should_send_warning(&config, &info));
}

#[test]
fn get_seconds_until_lock_reports_zero_past_the_timeout() {
    let mut config = EnhancedAutoLockConfig::default();
    config.base.inactivity_timeout_secs = 2;

    // Still inside the window: whole seconds remain.
    let fresh = session_info_with_idle_seconds(0);
    assert_eq!(get_seconds_until_lock(&config, &fresh), 2);

    // Idle beyond the timeout: nothing remains.
    let stale = session_info_with_idle_seconds(5);
    assert_eq!(get_seconds_until_lock(&config, &stale), 0);
}
