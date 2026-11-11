use super::*;
use crate::config::CliConfig;
use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
use persona_core::auth::authentication::AuthResult;
use persona_core::models::{
    ApiKeyData, CredentialData, CredentialType, Identity as CoreIdentityModel, IdentityType,
    PasswordCredentialData,
};
use persona_core::storage::{IdentityRepository, PasskeyRepository};
use std::sync::Arc;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serializes env mutations against the bridge and service tests.
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

fn config_for(dir: &TempDir) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    config
}

fn args(names: &[&str], format: &str) -> ExportArgs {
    ExportArgs {
        names: names.iter().map(|s| s.to_string()).collect(),
        output: None,
        format: format.to_string(),
        include_sensitive: false,
        encrypt: false,
        compression: 0,
        interactive: false,
    }
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
// ------------------------------------------------------------------
// Helpers for the interactive/authenticated `execute_with` flows.
// ------------------------------------------------------------------

fn with_output(mut a: ExportArgs, out: &Path) -> ExportArgs {
    a.output = Some(out.to_path_buf());
    a
}

/// Workspace with an initialized user; identities `alice`/`bob` exist.
async fn authenticated_workspace(dir: &TempDir, master: &str) -> CliConfig {
    let config = config_for(dir);
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let repo = IdentityRepository::new(db.clone());
    for name in ["alice", "bob"] {
        repo.create(&CoreIdentityModel::new(
            name.to_string(),
            IdentityType::Personal,
        ))
        .await
        .unwrap();
    }
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.initialize_user(master).await.unwrap();
    config
}

/// Unlock a fresh service and attach one password + one API-key
/// credential to `alice`. Returns their ids.
async fn seed_credentials(config: &CliConfig, master: &str) -> (uuid::Uuid, uuid::Uuid) {
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

    let login = service
        .create_credential(
            identity.id,
            "Web login".to_string(),
            CredentialType::Password,
            persona_core::models::SecurityLevel::High,
            &CredentialData::Password(PasswordCredentialData {
                password: "s3cret!".to_string(),
                email: Some("alice@example.com".to_string()),
                security_questions: Vec::new(),
            }),
        )
        .await
        .unwrap();
    let token = service
        .create_credential(
            identity.id,
            "API token".to_string(),
            CredentialType::ApiKey,
            persona_core::models::SecurityLevel::Medium,
            &CredentialData::ApiKey(ApiKeyData {
                api_key: "key-123".to_string(),
                api_secret: None,
                token: None,
                permissions: Vec::new(),
                expires_at: None,
            }),
        )
        .await
        .unwrap();
    (login.id, token.id)
}

fn passkey_client_data() -> Vec<u8> {
    br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#
        .to_vec()
}

/// Attach a passkey to `alice`; `export_allowed` controls whether the
/// export is allowed to carry its private key.
async fn seed_passkey(config: &CliConfig, master: &str, export_allowed: bool) -> uuid::Uuid {
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .unwrap();
    assert!(matches!(
        service.authenticate_user(master).await.unwrap(),
        AuthResult::Success
    ));
    let identity = service
        .get_identity_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    let pk = service
        .create_passkey(
            identity.id,
            "example.com".to_string(),
            "https://example.com",
            &passkey_client_data(),
            None,
            Some("alice".to_string()),
            Some("Alice Example".to_string()),
            false,
        )
        .await
        .unwrap();

    if !export_allowed {
        let repo = PasskeyRepository::new(Arc::new(db));
        let mut item = repo.find_by_id(&pk.id).await.unwrap().unwrap();
        item.export_allowed = false;
        repo.update(&item).await.unwrap();
    }
    pk.id
}

use super::output::compress_file;

mod auth;
mod basic;
mod execute;
mod flows;
mod unit;
