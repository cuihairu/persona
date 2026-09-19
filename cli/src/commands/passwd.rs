//! `persona passwd` — rotate the workspace master password.
//!
//! Every wrapped item key is re-encrypted inside a single transaction
//! (see `PersonaService::change_master_password`). The old password is
//! resolved like unlock (`PERSONA_MASTER_PASSWORD` env first, then an
//! interactive prompt); the **new** password is interactive-only by
//! design — no env override, so a stale environment variable can never
//! silently rotate a vault.
//!
//! Deliberately does *not* go through `init_service`/`authenticate_user`:
//! the `PasswordChangeRequired` short-circuit would reject exactly the
//! password this command must collect, and the command would double-prompt.

use crate::commands::service::{new_service, prompt_master_password};
use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::PromptUi;
use anyhow::{bail, Context, Result};
use clap::Args;
use persona_core::Database;

#[derive(Args)]
pub struct PasswdArgs {}

pub async fn execute(_args: PasswdArgs, config: &CliConfig) -> Result<()> {
    execute_with(config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to connect to database: {}", db_path.display()))?;
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run database migrations")?;
    let mut service = new_service(db)
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

    let old_password = prompt_master_password(ui)?;
    let new_password = ui.password(
        "Set a new master password",
        false,
        Some(("Confirm new master password", "Passwords don't match")),
    )?;
    if new_password == old_password {
        bail!("New password must be different from the current password");
    }

    service
        .change_master_password(&old_password, &new_password)
        .await
        .into_anyhow()
        .context("Failed to change master password")?;

    println!("✓ Master password changed. Use the new password the next time you unlock.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::{CredentialData, CredentialType, IdentityType, PasswordCredentialData};
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the other command tests.
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

    /// Seed an initialized workspace holding one decryptable credential.
    async fn seed_workspace(dir: &TempDir, master: &str) -> persona_core::models::Credential {
        let db = Database::from_file(&dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = new_service(db).await.unwrap();
        service.initialize_user(master).await.unwrap();
        let identity = service
            .create_identity("Passwd".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let credential = service
            .create_credential(
                identity.id,
                "seeded-item".to_string(),
                CredentialType::Password,
                persona_core::SecurityLevel::Medium,
                &CredentialData::Password(PasswordCredentialData {
                    password: "hunter2".to_string(),
                    email: None,
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();
        drop(service);
        credential
    }

    /// Fresh service authenticated with `password` (the post-rotation path
    /// a user would take), then reads the seeded credential through it.
    async fn reauthenticate_and_read(
        dir: &TempDir,
        password: &str,
        credential_id: &uuid::Uuid,
    ) -> anyhow::Result<CredentialData> {
        std::env::set_var("PERSONA_MASTER_PASSWORD", password);
        let service = crate::commands::service::init_service(
            &config_for(dir),
            &crate::utils::prompt::TerminalUi,
        )
        .await?;
        let data = service
            .get_credential_data(credential_id)
            .await
            .into_anyhow();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        drop(service);
        data?.ok_or_else(|| anyhow::anyhow!("seeded credential missing after rotation"))
    }

    #[tokio::test]
    async fn passwd_rotates_and_keeps_data_decryptable() {
        let _guard = lock_process_env();
        let master = "passwd-old-pass";

        let dir = TempDir::new().unwrap();
        let credential = seed_workspace(&dir, master).await;

        // 旧密码走 env 覆盖；新密码仅交互（ScriptedUi 一发即中）
        std::env::set_var("PERSONA_MASTER_PASSWORD", master);
        let ui = ScriptedUi::new().password("passwd-new-pass");
        execute_with(&config_for(&dir), &ui)
            .await
            .expect("rotation succeeds");
        assert!(ui.exhausted());
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        // 旧密码从此被拒
        std::env::set_var("PERSONA_MASTER_PASSWORD", master);
        let result = crate::commands::service::init_service(
            &config_for(&dir),
            &crate::utils::prompt::TerminalUi,
        )
        .await;
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let err = match result {
            Ok(_) => panic!("old password must no longer authenticate"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("Authentication failed"));

        // 新密码解锁，且轮换前的凭据仍可解密（wrapped key 重包成功）
        let data = reauthenticate_and_read(&dir, "passwd-new-pass", &credential.id)
            .await
            .expect("new password unlocks and data stays decryptable");
        match data {
            CredentialData::Password(p) => assert_eq!(p.password, "hunter2"),
            other => panic!("unexpected credential payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn passwd_rejects_a_wrong_old_password() {
        let _guard = lock_process_env();

        let dir = TempDir::new().unwrap();
        seed_workspace(&dir, "real-pass").await;

        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pass");
        let ui = ScriptedUi::new().password("new-pass");
        let err = execute_with(&config_for(&dir), &ui)
            .await
            .expect_err("wrong old password must fail");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        // context 包裹在链首，{:#} 展开整条错误链
        assert!(format!("{err:#}").contains("Invalid current master password"));

        // 真密码依旧可用（失败的尝试不得损坏 vault）
        std::env::set_var("PERSONA_MASTER_PASSWORD", "real-pass");
        let result = crate::commands::service::init_service(
            &config_for(&dir),
            &crate::utils::prompt::TerminalUi,
        )
        .await;
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert!(result.is_ok(), "real password must still authenticate");
    }

    #[tokio::test]
    async fn passwd_rejects_new_password_equal_to_old() {
        let _guard = lock_process_env();
        let master = "same-pass";

        let dir = TempDir::new().unwrap();
        seed_workspace(&dir, master).await;

        std::env::set_var("PERSONA_MASTER_PASSWORD", master);
        let ui = ScriptedUi::new().password(master);
        let err = execute_with(&config_for(&dir), &ui)
            .await
            .expect_err("new == old must be rejected");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert!(err.to_string().contains("must be different"));

        // 未发生轮换：旧密码仍能解锁
        std::env::set_var("PERSONA_MASTER_PASSWORD", master);
        let result = crate::commands::service::init_service(
            &config_for(&dir),
            &crate::utils::prompt::TerminalUi,
        )
        .await;
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert!(result.is_ok(), "old password must still authenticate");
    }

    #[tokio::test]
    async fn passwd_requires_an_initialized_workspace() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let err = execute_with(&config_for(&dir), &crate::utils::prompt::TerminalUi)
            .await
            .expect_err("uninitialized workspace must fail");
        assert!(err.to_string().contains("Workspace not initialized"));
    }

    #[tokio::test]
    async fn passwd_surfaces_core_validation_for_empty_new_password() {
        let _guard = lock_process_env();
        let master = "empty-new-pass";

        let dir = TempDir::new().unwrap();
        seed_workspace(&dir, master).await;

        std::env::set_var("PERSONA_MASTER_PASSWORD", master);
        // ScriptedUi 绕过 TerminalUi 的 allow_empty=false 拦截，
        // core 的空密码校验成为最后防线
        let ui = ScriptedUi::new().password("");
        let err = execute_with(&config_for(&dir), &ui)
            .await
            .expect_err("empty new password must fail");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert!(err.to_string().contains("assword"));
    }
}
