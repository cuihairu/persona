use super::{
    config_for, ensure_workspace_row, lock_process_env, seeded_db, service_db, switch_args,
};
use crate::commands::switch::execute;
use crate::commands::switch::flow::execute_with;
use crate::commands::switch::identity::select_identity_interactive;
use crate::utils::prompt::scripted::ScriptedUi;
use persona_core::models::Workspace;
use persona_core::storage::{IdentityRepository, WorkspaceRepository};
use persona_core::Database;
use persona_core::Repository;
use tempfile::TempDir;

#[tokio::test]
async fn switch_authenticated_path_with_master_password() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["carol"]).await;
    ensure_workspace_row(&db, &config).await;
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }

    std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
    let err = execute(switch_args(Some("carol"), true), &config)
        .await
        .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Authentication failed"));

    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
    execute(switch_args(Some("carol"), true), &config)
        .await
        .expect("correct password must switch");

    // An authenticated workspace with a stale active pointer reports no
    // current identity (the unlock state hides it) and still switches.
    {
        let repo = WorkspaceRepository::new(service_db(&config).await);
        let identity = IdentityRepository::new(service_db(&config).await)
            .find_by_name("carol")
            .await
            .unwrap()
            .unwrap();
        let mut ws = Workspace::new(config.workspace.path.clone(), "test-workspace".to_string());
        ws.switch_identity(identity.id);
        repo.create(&ws).await.unwrap();
    }
    execute(switch_args(Some("carol"), true), &config)
        .await
        .expect("re-switch on authenticated workspace succeeds");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn switch_late_auth_failures_reach_the_deep_gates() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice", "bob"]).await;
    ensure_workspace_row(&db, &config).await;
    {
        let mut service = crate::commands::service::new_service(service_db(&config).await)
            .await
            .unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }

    // The interactive menu's identity fetch authenticates on its own: a
    // wrong password fails there before any selection is offered.
    let ui = ScriptedUi::new().password("wrong-pin");
    let err = select_identity_interactive(&config, &ui)
        .await
        .expect_err("wrong password must fail the menu fetch");
    assert!(
        err.to_string()
            .contains("Authentication failed: InvalidCredentials"),
        "got: {err}"
    );
    assert!(ui.exhausted());

    // The full interactive flow authenticates three times (menu fetch,
    // verify, perform). Failing only the last one reaches the bail in
    // perform_switch that the earlier gates can never hit with a single
    // env-provided password.
    let ui = ScriptedUi::new()
        .password("master-pin") // menu fetch
        .select(1) // bob
        .password("master-pin") // verify_identity_exists
        .password("wrong-pin"); // perform_switch
    let err = execute_with(switch_args(None, true), &config, &ui)
        .await
        .expect_err("late auth failure must abort the switch");
    assert!(
        err.to_string()
            .contains("Authentication failed: InvalidCredentials"),
        "got: {err}"
    );
    assert!(ui.exhausted());

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
