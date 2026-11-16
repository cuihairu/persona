use super::{config_for, ensure_workspace_row, seeded_db, switch_args};
use crate::commands::switch::execute;
use crate::commands::switch::identity::{get_current_identity, select_identity_interactive};
use crate::utils::prompt::scripted::ScriptedUi;
use persona_core::models::{AuditAction, Workspace};
use persona_core::storage::{AuditLogRepository, IdentityRepository, WorkspaceRepository};
use persona_core::Repository;
use tempfile::TempDir;

#[tokio::test]
async fn switch_updates_workspace_and_audits_without_users() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice", "bob"]).await;

    // Migrate command guarantees a workspace row for this path.
    ensure_workspace_row(&db, &config).await;

    execute(switch_args(Some("alice"), true), &config)
        .await
        .expect("forced switch must succeed");

    let repo = WorkspaceRepository::new(db.clone());
    let path_str = config.workspace.path.to_string_lossy().to_string();
    let ws = repo
        .find_by_path(&path_str)
        .await
        .unwrap()
        .expect("workspace row exists");
    let active_id = ws.active_identity_id.expect("active identity recorded");

    let identity = IdentityRepository::new(db.clone())
        .find_by_name("alice")
        .await
        .unwrap()
        .expect("alice exists");
    assert_eq!(active_id, identity.id);

    // Switching to the same identity short-circuits with "already active".
    execute(switch_args(Some("alice"), true), &config)
        .await
        .expect("already-active switch is a no-op");

    // One audit entry for the single real switch.
    let audits = AuditLogRepository::new(db.clone())
        .find_by_action(&AuditAction::WorkspaceEntered)
        .await
        .unwrap();
    assert_eq!(audits.len(), 1);
}

#[tokio::test]
async fn switch_between_identities_audits_twice_and_errors_paths() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice", "bob"]).await;
    ensure_workspace_row(&db, &config).await;

    execute(switch_args(Some("alice"), true), &config)
        .await
        .unwrap();
    execute(switch_args(Some("bob"), true), &config)
        .await
        .unwrap();

    let repo = WorkspaceRepository::new(db.clone());
    let path_str = config.workspace.path.to_string_lossy().to_string();
    let ws = repo.find_by_path(&path_str).await.unwrap().unwrap();
    let bob = IdentityRepository::new(db.clone())
        .find_by_name("bob")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ws.active_identity_id, Some(bob.id));

    let audits = AuditLogRepository::new(db.clone())
        .find_by_action(&AuditAction::WorkspaceEntered)
        .await
        .unwrap();
    assert_eq!(audits.len(), 2);

    // Unknown target fails in verification.
    let err = execute(switch_args(Some("ghost"), true), &config)
        .await
        .expect_err("unknown identity must fail");
    assert!(err.to_string().contains("Identity 'ghost' not found"));

    // --previous resolves the last identity that differs from the
    // current one (bob), i.e. alice, straight from the audit trail.
    let mut prev = switch_args(None, true);
    prev.previous = true;
    execute(prev, &config)
        .await
        .expect("previous resolves alice");
    let ws = repo
        .find_by_path(&path_str)
        .await
        .unwrap()
        .expect("workspace row survived");
    let alice = IdentityRepository::new(db)
        .find_by_name("alice")
        .await
        .unwrap()
        .expect("alice exists");
    assert_eq!(ws.active_identity_id, Some(alice.id));

    // Interactive selection with an empty database reports the hint.
    let empty = TempDir::new().unwrap();
    let err = select_identity_interactive(&config_for(&empty), &ScriptedUi::new())
        .await
        .expect_err("empty selection must fail");
    assert!(err.to_string().contains("No identities found"));
}

#[tokio::test]
async fn switch_previous_without_other_history_is_a_clear_error() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice", "bob"]).await;
    ensure_workspace_row(&db, &config).await;

    // Only alice was ever entered; every history row matches the
    // current identity, so there is no previous to return.
    execute(switch_args(Some("alice"), true), &config)
        .await
        .unwrap();
    let mut prev = switch_args(None, true);
    prev.previous = true;
    let err = execute(prev, &config)
        .await
        .expect_err("previous must fail");
    assert!(err
        .to_string()
        .contains("No previous identity recorded yet"));
}

#[tokio::test]
async fn switch_without_workspace_row_still_succeeds_and_audits() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice"]).await;
    // Deliberately no workspace row: perform_switch must skip the
    // workspace update but still record the audit entry.

    execute(switch_args(Some("alice"), true), &config)
        .await
        .expect("switch without a workspace row succeeds");

    let audits = AuditLogRepository::new(db)
        .find_by_action(&AuditAction::WorkspaceEntered)
        .await
        .unwrap();
    assert_eq!(audits.len(), 1, "switch is audited without a workspace row");
}

#[tokio::test]
async fn switch_ignores_a_stale_active_pointer_without_users() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice"]).await;
    ensure_workspace_row(&db, &config).await;

    // Point the workspace at an identity that no longer exists; the
    // lookup falls through and reports "no current identity".
    {
        let repo = WorkspaceRepository::new(db.clone());
        let mut ws = Workspace::new(config.workspace.path.clone(), "test-workspace".to_string());
        ws.switch_identity(uuid::Uuid::new_v4());
        repo.create(&ws).await.unwrap();
    }
    assert_eq!(get_current_identity(&config).await.unwrap(), None);

    execute(switch_args(Some("alice"), true), &config)
        .await
        .expect("switch with a stale pointer succeeds");
}

#[tokio::test]
async fn switch_current_identity_resolves_active_pointer_by_id() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice", "bob"]).await;

    // A workspace row whose active pointer targets alice resolves her
    // name through the by-id lookup.
    let alice = IdentityRepository::new(db.clone())
        .find_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    let mut ws = Workspace::new(config.workspace.path.clone(), "test-workspace".to_string());
    ws.switch_identity(alice.id);
    WorkspaceRepository::new(db.clone())
        .create(&ws)
        .await
        .unwrap();

    assert_eq!(
        get_current_identity(&config).await.unwrap().as_deref(),
        Some("alice")
    );
}
