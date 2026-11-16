use super::*;

use crate::config::CliConfig;
use crate::utils::prompt::scripted::ScriptedUi;
use std::sync::Mutex;
use tempfile::TempDir;

use std::path::Path;

use super::display::show_import_summary;
use super::flow::{
    check_import_conflicts, decrypt_import_file, execute_with, validate_import_file,
};
use super::formats::{parse_csv_import, parse_import_file, parse_json_import, parse_yaml_import};

mod display;
mod flow;
mod formats;

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

fn args(file: &Path, force: bool) -> ImportArgs {
    ImportArgs {
        file: file.to_path_buf(),
        mode: "merge".to_string(),
        dry_run: false,
        force,
        backup: false,
        decrypt: false,
        interactive: false,
    }
}

fn sample_json() -> String {
    serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-01-01T00:00:00Z"},
            "identities": [
                {"name": "alice", "type": "personal", "description": "first", "email": "a@b.c", "tags": ["work"]},
                {"name": "bob", "type": "work", "description": "second"}
            ]
        })
        .to_string()
}
