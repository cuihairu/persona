use super::*;

// ---- 解锁链错误分支 ----

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn open_unlocked_rejects_uninitialized_workspace() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let dir = tempfile::tempdir().unwrap();
    let err = execute_with(
        resolve_args(&["work/x/y"]),
        &config_for(&dir),
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("Workspace not initialized"),
        "{err}"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn open_unlocked_rejects_wrong_master_password() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "totally-wrong");
    let (_dir, config) = seeded_workspace().await;
    let err = execute_with(
        resolve_args(&["work/login/password"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("Authentication failed"),
        "{err}"
    );
}
