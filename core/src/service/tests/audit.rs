use super::*;

#[tokio::test]
async fn test_query_audit_log_filter_branches() {
    let (_db, service) = unlocked_service().await;
    // The real user (already `current_user`): audit rows carry an FK to
    // user_auth, so only an existing user id can label the logs.
    let user_id = service.current_user.expect("initialize_user set the user");

    let identity = service
        .create_identity("Filter Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // Curated rows so every branch has deterministic data: a failure, a
    // security-sensitive success, and a plain success.
    service
        .log_audit(
            AuditAction::CredentialCreated,
            ResourceType::Credential,
            false,
            None,
            Some(identity.id),
            Some("seed failure".to_string()),
        )
        .await;
    service
        .log_audit(
            AuditAction::CredentialDecrypted,
            ResourceType::Credential,
            true,
            None,
            Some(identity.id),
            None,
        )
        .await;

    // user_id filter: dedicated query + in-memory re-check.
    let mine = service
        .query_audit_logs(AuditLogQuery {
            user_id: Some(user_id.to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!mine.is_empty());
    let uid_str = user_id.to_string();
    assert!(mine
        .iter()
        .all(|l| l.user_id.as_deref() == Some(uid_str.as_str())));

    let foreign = service
        .query_audit_logs(AuditLogQuery {
            user_id: Some("no-such-user".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(foreign.is_empty());

    // failures_only: dedicated query + the success-negation re-check.
    let failures = service
        .query_audit_logs(AuditLogQuery {
            failures_only: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!failures.is_empty());
    assert!(failures.iter().all(|l| !l.success));

    // security_sensitive_only: only the sensitive-action rows survive.
    let sensitive = service
        .query_audit_logs(AuditLogQuery {
            security_sensitive_only: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!sensitive.is_empty());
    assert!(sensitive
        .iter()
        .all(|l| { SECURITY_SENSITIVE_AUDIT_ACTIONS.contains(&l.action.to_string().as_str()) }));

    // Combined filter: the user branch stays the primary query while the
    // failure condition is re-checked in memory.
    let my_failures = service
        .query_audit_logs(AuditLogQuery {
            user_id: Some(user_id.to_string()),
            failures_only: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!my_failures.is_empty());
    assert!(my_failures
        .iter()
        .all(|l| !l.success && l.user_id.as_deref() == Some(uid_str.as_str())));

    // time_range: a window covering "now" matches (the existing suite
    // only checks the empty future window).
    let now = chrono::Utc::now();
    let in_window = service
        .query_audit_logs(AuditLogQuery {
            time_range: Some((
                now - chrono::Duration::hours(1),
                now + chrono::Duration::hours(1),
            )),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!in_window.is_empty());
}

#[tokio::test]
async fn test_audit_query_statistics_and_cleanup() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let mut service = PersonaService::new(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();

    let identity = service
        .create_identity("Audit Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // 全量查询：初始化 + 建身份至少各留一条，且按时间降序
    let all = service
        .query_audit_logs(AuditLogQuery::default())
        .await
        .unwrap();
    assert!(!all.is_empty());
    assert!(
        all.windows(2).all(|w| w[0].timestamp >= w[1].timestamp),
        "audit logs must be ordered by timestamp desc"
    );

    // 按 identity 过滤
    let by_identity = service
        .query_audit_logs(AuditLogQuery {
            identity_id: Some(identity.id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!by_identity.is_empty());
    assert!(by_identity
        .iter()
        .all(|l| l.identity_id == Some(identity.id)));
    assert!(by_identity
        .iter()
        .any(|l| l.action.to_string() == "identity_created"));

    // action 过滤（走 find_by_action 主查询 + 内存复核）
    let created = service
        .query_audit_logs(AuditLogQuery {
            action: Some(AuditAction::IdentityCreated),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(created
        .iter()
        .all(|l| l.action.to_string() == "identity_created"));

    // limit 截断
    let limited = service
        .query_audit_logs(AuditLogQuery {
            limit: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(limited.len(), 1);

    // 统计
    let stats = service.audit_log_statistics().await.unwrap();
    assert!(stats.total_logs > 0);

    // 时间窗口放在未来 → 空
    let now = chrono::Utc::now();
    let future = service
        .query_audit_logs(AuditLogQuery {
            time_range: Some((
                now + chrono::Duration::hours(1),
                now + chrono::Duration::hours(2),
            )),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(future.is_empty());

    // 清理保留 0 天 → 删光
    let deleted = service.cleanup_audit_logs(0).await.unwrap();
    assert!(deleted > 0);
    let after = service
        .query_audit_logs(AuditLogQuery::default())
        .await
        .unwrap();
    assert!(after.is_empty());
}
