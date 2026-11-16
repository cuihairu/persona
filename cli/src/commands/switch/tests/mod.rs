use crate::commands::switch::SwitchArgs;
use crate::config::CliConfig;
use persona_core::models::{Identity as CoreIdentityModel, IdentityType, Workspace};
use persona_core::storage::{IdentityRepository, WorkspaceRepository};
use persona_core::Database;
use persona_core::Repository;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serializes env mutations against the bridge and service tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_process_env() -> (
    std::sync::MutexGuard<'static, ()>,
    std::sync::MutexGuard<'static, ()>,
) {
    // Recover from a poisoned lock: a panicking sibling test must not
    // cascade into every other env-gated test.
    fn lock_or_recover(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
        lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    (
        lock_or_recover(&crate::commands::bridge::tests::ENV_LOCK),
        lock_or_recover(&ENV_LOCK),
    )
}

fn config_for(dir: &TempDir) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    config
}

fn args(name: Option<&str>, force: bool) -> SwitchArgs {
    SwitchArgs {
        name: name.map(String::from),
        force,
        interactive: false,
        previous: false,
    }
}

fn switch_args(name: Option<&str>, force: bool) -> SwitchArgs {
    args(name, force)
}

/// Migrated database with `names` identities inserted.
async fn seeded_db(dir: &TempDir, names: &[&str]) -> Database {
    let db = Database::from_file(dir.path().join("identities.db"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let repo = IdentityRepository::new(db.clone());
    for name in names {
        repo.create(&CoreIdentityModel::new(
            name.to_string(),
            IdentityType::Personal,
        ))
        .await
        .unwrap();
    }
    db
}

/// `persona migrate` normally guarantees a workspace row; create it directly.
async fn ensure_workspace_row(db: &Database, config: &CliConfig) {
    let repo = WorkspaceRepository::new(db.clone());
    repo.create(&Workspace::new(
        config.workspace.path.clone(),
        "test-workspace".to_string(),
    ))
    .await
    .unwrap();
}

async fn service_db(config: &CliConfig) -> Database {
    Database::from_file(config.get_database_path())
        .await
        .unwrap()
}

mod auth;
mod interactive;
mod learn;
mod summary;
mod switch;
