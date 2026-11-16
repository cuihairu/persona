use super::*;

#[tokio::test]
async fn assign_by_policy_uuid_and_rejects_bad_user_ids() {
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
    let policy = repo
        .find_all()
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.name == "team")
        .unwrap();
    drop(repo);

    let user = uuid::Uuid::new_v4();

    // Assignment resolved through the policy UUID (not the name).
    handler(
        AutoLockCommand::Assign {
            user_id: user.to_string(),
            policy_identifier: policy.id.to_string(),
        },
        &dir,
    )
    .await
    .expect("assign by policy uuid works");

    // Non-UUID user ids are rejected everywhere.
    for command in [
        AutoLockCommand::Unassign {
            user_id: "nope".to_string(),
        },
        AutoLockCommand::UserPolicy {
            user_id: "nope".to_string(),
        },
    ] {
        let err = handler(command, &dir)
            .await
            .expect_err("bad user id must fail");
        assert!(err.to_string().contains("valid UUID"));
    }

    handler(
        AutoLockCommand::Unassign {
            user_id: user.to_string(),
        },
        &dir,
    )
    .await
    .expect("unassign works");
}
