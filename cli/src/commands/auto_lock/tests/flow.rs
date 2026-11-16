use super::*;

#[tokio::test]
async fn assign_default_stats_and_session_commands() {
    let dir = TempDir::new().unwrap();

    handler(
        AutoLockCommand::Create {
            name: "team".to_string(),
            description: None,
            security_level: AutoLockSecurityLevel::Low,
            inactivity_timeout: None,
            absolute_timeout: None,
            sensitive_timeout: None,
            max_sessions: None,
            warnings: false,
            warning_time: None,
            force_sensitive: false,
            use_case: None,
        },
        &dir,
    )
    .await
    .expect("create works");

    let repo = init_repository(&config_for(&dir)).await.unwrap();
    let policy = repo.find_all().await.unwrap().remove(0);
    let pid = policy.id;
    drop(repo);

    let user = uuid::Uuid::new_v4();

    // Non-UUID user ids are rejected.
    let err = handler(
        AutoLockCommand::Assign {
            user_id: "not-a-uuid".to_string(),
            policy_identifier: "team".to_string(),
        },
        &dir,
    )
    .await
    .expect_err("bad user id must fail");
    assert!(err.to_string().contains("valid UUID"));

    handler(
        AutoLockCommand::Assign {
            user_id: user.to_string(),
            policy_identifier: "team".to_string(),
        },
        &dir,
    )
    .await
    .expect("assign works");

    handler(
        AutoLockCommand::UserPolicy {
            user_id: user.to_string(),
        },
        &dir,
    )
    .await
    .expect("user policy works");
    handler(
        AutoLockCommand::UserPolicy {
            user_id: uuid::Uuid::new_v4().to_string(),
        },
        &dir,
    )
    .await
    .expect("unassigned user works");

    handler(AutoLockCommand::SetDefault { policy_id: pid }, &dir)
        .await
        .expect("set default works");
    handler(
        AutoLockCommand::Stats {
            policy_id: Some(pid),
        },
        &dir,
    )
    .await
    .expect("stats for policy works");
    handler(AutoLockCommand::Stats { policy_id: None }, &dir)
        .await
        .expect("system stats works");
    handler(
        AutoLockCommand::Status {
            user_id: Some(user.to_string()),
        },
        &dir,
    )
    .await
    .expect("status with user works");
    handler(AutoLockCommand::Status { user_id: None }, &dir)
        .await
        .expect("global status works");

    handler(
        AutoLockCommand::Unassign {
            user_id: user.to_string(),
        },
        &dir,
    )
    .await
    .expect("unassign works");

    // Session lock/unlock round-trip; unknown ids report but do not panic.
    handler(AutoLockCommand::Lock { session_id: None }, &dir)
        .await
        .expect("lock without id works");
    handler(
        AutoLockCommand::Lock {
            session_id: Some("ghost".to_string()),
        },
        &dir,
    )
    .await
    .expect("lock unknown session reports gracefully");
    handler(
        AutoLockCommand::Unlock {
            session_id: "ghost".to_string(),
        },
        &dir,
    )
    .await
    .expect("unlock unknown session reports gracefully");

    let err = handler(
        AutoLockCommand::Assign {
            user_id: user.to_string(),
            policy_identifier: "ghost".to_string(),
        },
        &dir,
    )
    .await
    .expect_err("unknown policy must fail");
    assert!(err.to_string().contains("Policy 'ghost' not found"));
}

#[tokio::test]
async fn system_stats_without_default_warns_and_lock_reports_missing_session() {
    let dir = TempDir::new().unwrap();

    // Locking an explicit but unknown session reports the failure
    // gracefully (the handler owns a fresh in-memory SessionManager).
    handler(
        AutoLockCommand::Lock {
            session_id: Some("ghost".to_string()),
        },
        &dir,
    )
    .await
    .expect("lock of an unknown session reports gracefully");

    // Migration 008 seeds a default policy, so remove every policy (the
    // seeded default included) to reach the "no default" warning.
    let repo = init_repository(&config_for(&dir)).await.unwrap();
    for policy in repo.find_all().await.unwrap() {
        repo.delete(&policy.id).await.unwrap();
    }
    assert!(repo.get_default_policy().await.unwrap().is_none());
    drop(repo);

    handler(AutoLockCommand::Stats { policy_id: None }, &dir)
        .await
        .expect("system stats without any policy works");
}
