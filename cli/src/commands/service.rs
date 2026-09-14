//! Shared service bootstrap for the interactive command modules.
//!
//! Every top-level command group (`credential`, `passkey`, `totp`, ...)
//! opens the workspace database and unlocks it the same way; the logic
//! lives here so the behaviour stays consistent and testable.

use anyhow::{bail, Context, Result};

use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::PromptUi;
use persona_core::{Database, PersonaService};

/// Open the workspace database, run migrations and unlock the service.
///
/// The master password is resolved in this order:
/// 1. `PERSONA_MASTER_PASSWORD` (CI / automation; a blank value falls
///    through to the interactive prompt)
/// 2. an interactive `dialoguer` prompt
pub(crate) fn prompt_master_password(ui: &dyn PromptUi) -> Result<String> {
    match std::env::var("PERSONA_MASTER_PASSWORD") {
        Ok(p) if !p.trim().is_empty() => Ok(p),
        _ => ui.password("Enter master password to unlock", false, None),
    }
}

/// Prompt for an arbitrary passphrase (import/export payloads).
///
/// Resolved in this order:
/// 1. `PERSONA_PAYLOAD_PASSPHRASE` (CI / automation; blank falls through)
/// 2. an interactive `dialoguer` prompt with confirmation
pub(crate) fn prompt_payload_passphrase(kind: &str, ui: &dyn PromptUi) -> Result<String> {
    match std::env::var("PERSONA_PAYLOAD_PASSPHRASE") {
        Ok(p) if !p.trim().is_empty() => Ok(p),
        _ => ui.password(
            &format!("Enter {} passphrase", kind),
            false,
            Some(("Confirm passphrase", "Passphrases do not match")),
        ),
    }
}

/// Prompt for a credential's secret value.
///
/// Resolved in this order:
/// 1. `PERSONA_CREDENTIAL_SECRET` (CI / automation; blank falls through)
/// 2. an interactive `dialoguer` prompt with confirmation
pub(crate) fn prompt_credential_secret(ui: &dyn PromptUi) -> Result<String> {
    match std::env::var("PERSONA_CREDENTIAL_SECRET") {
        Ok(p) if !p.trim().is_empty() => Ok(p),
        _ => ui.password(
            "Secret / password",
            false,
            Some(("Confirm secret", "Mismatch")),
        ),
    }
}

/// Prompt for a brand-new master password (workspace initialization).
pub(crate) fn prompt_new_master_password(ui: &dyn PromptUi) -> Result<String> {
    match std::env::var("PERSONA_MASTER_PASSWORD") {
        Ok(p) if !p.trim().is_empty() => Ok(p),
        _ => ui.password(
            "Set a new master password",
            false,
            Some(("Confirm master password", "Passwords don't match")),
        ),
    }
}

pub(crate) async fn init_service(config: &CliConfig, ui: &dyn PromptUi) -> Result<PersonaService> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to connect to database: {}", db_path.display()))?;
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run database migrations")?;
    let mut service = PersonaService::new(db)
        .await
        .into_anyhow()
        .context("Failed to create PersonaService")?;

    if !service
        .has_users()
        .await
        .into_anyhow()
        .context("Failed to check users")?
    {
        bail!("Workspace not initialized. Run `persona init` first");
    }

    let password = prompt_master_password(ui)?;

    match service
        .authenticate_user(&password)
        .await
        .into_anyhow()
        .context("Failed to authenticate user")?
    {
        persona_core::auth::authentication::AuthResult::Success => Ok(service),
        other => bail!("Authentication failed: {:?}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the bridge and config tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK.lock().unwrap(),
            ENV_LOCK.lock().unwrap(),
        )
    }

    fn config_for(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    #[tokio::test]
    async fn missing_workspace_is_reported_before_password() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let err = init_service(&config_for(&dir), &crate::utils::prompt::TerminalUi)
            .await
            .err()
            .expect("workspace was never initialized");
        assert!(err.to_string().contains("Workspace not initialized"));
    }

    #[tokio::test]
    async fn env_password_unlocks_seeded_workspace() {
        let _guard = lock_process_env();
        let master = "env-secret-123";

        // Seed a workspace with a user whose master password is `master`.
        let dir = TempDir::new().unwrap();
        let db = Database::from_file(&dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db).await.unwrap();
        service
            .initialize_user(master)
            .await
            .expect("seed master user");
        drop(service);

        // A wrong env password must fail authentication (proves the env
        // path is taken instead of an interactive prompt).
        std::env::set_var("PERSONA_MASTER_PASSWORD", "not-the-password");
        let err = init_service(&config_for(&dir), &crate::utils::prompt::TerminalUi)
            .await
            .err()
            .expect("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        // The correct env password unlocks the service.
        std::env::set_var("PERSONA_MASTER_PASSWORD", master);
        let service = init_service(&config_for(&dir), &crate::utils::prompt::TerminalUi)
            .await
            .expect("correct password must unlock");
        assert!(service.has_users().await.unwrap());

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[test]
    fn passphrase_and_secret_prompts_fall_back_to_the_ui_without_env() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");
        std::env::remove_var("PERSONA_CREDENTIAL_SECRET");

        use crate::utils::prompt::scripted::ScriptedUi;

        // Without the env vars both prompters consult the UI (with its
        // confirmation prompt, which the scripted implementation ignores).
        let ui = ScriptedUi::new().password("payload-pass");
        assert_eq!(
            prompt_payload_passphrase("import", &ui).unwrap(),
            "payload-pass"
        );
        assert!(ui.exhausted());

        let ui = ScriptedUi::new().password("cred-secret");
        assert_eq!(prompt_credential_secret(&ui).unwrap(), "cred-secret");
        assert!(ui.exhausted());

        // A blank env value falls through to the UI as well.
        std::env::set_var("PERSONA_PAYLOAD_PASSPHRASE", "   ");
        let ui = ScriptedUi::new().password("typed-instead");
        assert_eq!(
            prompt_payload_passphrase("export", &ui).unwrap(),
            "typed-instead"
        );
        assert!(ui.exhausted());

        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");
    }
}
