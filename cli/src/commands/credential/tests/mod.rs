use super::*;
use crate::config::CliConfig;
use crate::utils::prompt::scripted::ScriptedUi;
use persona_core::models::{
    ApiKeyData, CredentialType, IdentityData, SecureNoteData, SecurityLevel,
    SoftwareLicenseData, SshKeyData,
};
use persona_core::Database;
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

/// Unlocks the workspace and creates the named identity.
async fn seed(config: &CliConfig, identity: &str) -> persona_core::Identity {
    let service = crate::commands::service::init_service(config, &crate::utils::prompt::TerminalUi)
        .await
        .unwrap();
    let created = service
        .create_identity_full(persona_core::Identity::new(
            identity.to_string(),
            persona_core::models::IdentityType::Personal,
        ))
        .await
        .unwrap();
    created
}

fn add_args(identity: &str, name: &str, secret: Option<&str>, favorite: bool) -> CredentialArgs {
    CredentialArgs {
        command: CredentialCommand::Add(Box::new(AddArgs {
            identity: identity.to_string(),
            name: name.to_string(),
            credential_type: CredentialTypeOption::Password,
            security_level: SecurityLevelOption::High,
            username: Some("u1".to_string()),
            url: Some("https://example.com".to_string()),
            prompt_secret: false,
            secret: secret.map(String::from),
            note: None,
            first_name: None,
            last_name: None,
            email: None,
            phone: None,
            birthday: None,
            address: None,
            id_number: None,
            passport_number: None,
            driver_license: None,
            tax_id: None,
            organization: None,
            job_title: None,
            license_key: None,
            version: None,
            publisher: None,
            purchase_date: None,
            order_number: None,
            support_email: None,
            download_url: None,
            seats: None,
            valid_until: None,
            favorite,
        })),
    }
}

use super::args::SecurityLevelOption;
use super::attachments::format_attachment_size;
use super::fields::parse_field_spec;

mod add;
mod attachments;
mod fields;
mod history;
mod show;
