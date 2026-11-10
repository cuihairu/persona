use super::*;
use crate::config::CliConfig;
#[allow(unused_imports)]
use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
use crate::utils::prompt::TerminalUi;
use persona_core::auth::authentication::AuthResult;
use persona_core::models::{ApiKeyData, IdentityType};
use persona_core::storage::IdentityRepository;
use persona_core::Repository;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serializes env reads against the tests that mutate
/// `PERSONA_MASTER_PASSWORD` from other threads (env-first prompting
/// would otherwise swallow their value instead of the scripted one).
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_process_env() -> (
    std::sync::MutexGuard<'static, ()>,
    std::sync::MutexGuard<'static, ()>,
) {
    (
        crate::commands::bridge::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
    )
}

async fn ssh_test_config(dir: &TempDir) -> crate::config::CliConfig {
    let mut config = crate::config::CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    config
}

mod keycmds;
mod lifecycle;
mod protocol;
mod service;
mod signauth;

// ------------------------------------------------------------------
// Helpers for the command-level flows.
// ------------------------------------------------------------------

fn ssh_args(command: SshSubcommand) -> SshArgs {
    SshArgs { command }
}

/// Workspace with an initialized user and the identities `alice`/`bob`.
async fn unlocked_workspace(dir: &TempDir, master: &str) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let repo = IdentityRepository::new(db.clone());
    for name in ["alice", "bob"] {
        repo.create(&CoreIdentity::new(name.to_string(), IdentityType::Personal))
            .await
            .unwrap();
    }
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.initialize_user(master).await.unwrap();
    config
}

/// Migrated, userless workspace: `ensure_service` never prompts.
async fn userless_workspace(dir: &TempDir) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    config
}

async fn alice_credentials(config: &CliConfig, master: &str) -> Vec<(Uuid, CredentialType)> {
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    assert!(matches!(
        service.authenticate_user(master).await.unwrap(),
        AuthResult::Success
    ));
    let identity = service
        .get_identity_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    service
        .get_credentials_for_identity(&identity.id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| (c.id, c.credential_type))
        .collect()
}

/// Points `PERSONA_AGENT_STATE_DIR` at `dir` for the duration of the
/// test so pid/socket files never touch the real home directory.
/// Drop-restores the previous value.
struct StateDirGuard {
    prev: Option<std::ffi::OsString>,
}

impl Drop for StateDirGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(prev) => std::env::set_var("PERSONA_AGENT_STATE_DIR", prev),
            None => std::env::remove_var("PERSONA_AGENT_STATE_DIR"),
        }
    }
}

fn sandbox_agent_state_dir(dir: &TempDir) -> StateDirGuard {
    let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
    std::env::set_var("PERSONA_AGENT_STATE_DIR", dir.path());
    StateDirGuard {
        prev: prev.map(Into::into),
    }
}

/// Captures an env var and drop-restores it.
struct EnvVarGuard {
    name: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let prev = std::env::var(name).ok();
        std::env::set_var(name, &value);
        EnvVarGuard {
            name,
            prev: prev.map(Into::into),
        }
    }

    fn remove(name: &'static str) -> Self {
        let prev = std::env::var(name).ok();
        std::env::remove_var(name);
        EnvVarGuard {
            name,
            prev: prev.map(Into::into),
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(prev) => std::env::set_var(self.name, prev),
            None => std::env::remove_var(self.name),
        }
    }
}

#[cfg(unix)]
fn write_executable(dir: &TempDir, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}
