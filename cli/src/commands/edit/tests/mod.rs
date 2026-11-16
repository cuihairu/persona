use super::*;

use crate::config::CliConfig;
use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
use crate::utils::prompt::TerminalUi;
use persona_core::{
    models::{Identity as CoreIdentity, IdentityType},
    storage::IdentityRepository,
    Database,
};
use std::sync::Mutex;
use tempfile::TempDir;

use super::attributes::{edit_existing_attribute, remove_custom_attribute};
use super::display::show_current_values;
use super::fields::{edit_from_args, edit_identity_type, edit_interactive, edit_single_field};
use super::flow::execute_with;
use super::persist::{save_identity, validate_identity};

mod attributes;
mod display;
mod fields;
mod flow;
mod persist;

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

fn sample_identity() -> Identity {
    Identity {
        id: Some(uuid::Uuid::new_v4()),
        name: "alice".to_string(),
        identity_type: "personal".to_string(),
        description: "old description".to_string(),
        email: Some("alice@example.com".to_string()),
        phone: None,
        tags: vec!["work".to_string()],
        attributes: HashMap::new(),
        modified: "2024-01-01 00:00:00".to_string(),
    }
}

/// Migrated database in `dir` with the named identities inserted.
async fn seeded_db(dir: &TempDir, names: &[&str]) -> Database {
    use persona_core::Repository;
    let db = Database::from_file(dir.path().join("identities.db"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let repo = IdentityRepository::new(db.clone());
    for name in names {
        repo.create(&CoreIdentity::new(name.to_string(), IdentityType::Personal))
            .await
            .unwrap();
    }
    db
}
