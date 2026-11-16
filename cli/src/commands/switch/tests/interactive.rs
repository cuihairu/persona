use super::{config_for, ensure_workspace_row, seeded_db, switch_args};
use crate::commands::switch::flow::execute_with;
use crate::commands::switch::identity::select_identity_interactive;
use crate::utils::prompt::scripted::ScriptedUi;
use persona_core::storage::{IdentityRepository, WorkspaceRepository};
use tempfile::TempDir;

#[tokio::test]
async fn switch_interactive_select_and_confirm_gates() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice", "bob"]).await;
    ensure_workspace_row(&db, &config).await;

    // Interactive selection picks the second entry and the confirmation
    // gate declines → nothing changes.
    let ui = ScriptedUi::new().select(1).confirm(false);
    execute_with(switch_args(None, false), &config, &ui)
        .await
        .expect("declined interactive switch returns success");
    assert!(ui.exhausted());

    let repo = WorkspaceRepository::new(db.clone());
    let path_str = config.workspace.path.to_string_lossy().to_string();
    let ws = repo.find_by_path(&path_str).await.unwrap().unwrap();
    assert!(ws.active_identity_id.is_none(), "cancel must not switch");

    // Same run with the confirmation accepted → active pointer moves.
    let ui = ScriptedUi::new().select(1).confirm(true);
    execute_with(switch_args(None, false), &config, &ui)
        .await
        .expect("confirmed interactive switch succeeds");
    assert!(ui.exhausted());

    let ws = repo.find_by_path(&path_str).await.unwrap().unwrap();
    let bob = IdentityRepository::new(db.clone())
        .find_by_name("bob")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ws.active_identity_id, Some(bob.id));
}

#[tokio::test]
async fn switch_select_from_empty_workspace_fails() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &[]).await;

    let err = select_identity_interactive(&config, &ScriptedUi::new())
        .await
        .expect_err("empty workspace must fail");
    assert!(err.to_string().contains("No identities found"));
}

#[tokio::test]
async fn switch_selection_menu_rejects_out_of_range_choice() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice", "bob"]).await;

    let ui = ScriptedUi::new().select(99);
    let err = select_identity_interactive(&config, &ui)
        .await
        .expect_err("out-of-range selection must fail");
    assert!(err.to_string().contains("out of range"));
    assert!(ui.exhausted());
}
