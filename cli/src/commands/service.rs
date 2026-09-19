//! Shared service bootstrap for the interactive command modules.
//!
//! Every top-level command group (`credential`, `passkey`, `totp`, ...)
//! opens the workspace database and unlocks it the same way; the logic
//! lives here so the behaviour stays consistent and testable.

use anyhow::{bail, Context, Result};

use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::PromptUi;
use persona_core::{AuditLog, Database, Emitter, PersonaService, ServerEventSink};
use std::sync::{Arc, OnceLock};

/// 进程级审计事件上报器。
///
/// `PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN` **都**非空时启用
/// （敏感值走 env，与 PERSONA_MASTER_PASSWORD 同一惯例；CLI 不提供
/// 配置文件通道，避免令牌落盘）。core 不读环境变量——读取与构造
/// 都在宿主侧完成。
static EVENT_EMITTER: OnceLock<Emitter> = OnceLock::new();

/// main 在 dispatch 前调用：按环境变量构造全局上报器并启动后台 flush。
pub(crate) fn init_event_emitter_from_env() {
    let url = non_blank_env("PERSONA_SERVER_URL");
    let token = non_blank_env("PERSONA_SERVER_TOKEN");
    let Some((url, token)) = resolve_server_env(url, token) else {
        return;
    };
    match ServerEventSink::new(&url, token) {
        Ok(sink) => {
            let emitter = Emitter::new(Arc::new(sink));
            emitter.start();
            let _ = EVENT_EMITTER.set(emitter);
            tracing::info!("audit event reporting enabled");
        }
        Err(error) => {
            tracing::warn!(%error, "invalid PERSONA_SERVER_URL; event reporting disabled")
        }
    }
}

/// 空白值视同未设置（与 PERSONA_MASTER_PASSWORD 的"blank 回退"惯例一致）。
fn non_blank_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// URL 与 token **都**非空才启用；缺一只报 warn（提为纯函数便于单测——
/// OnceLock 全局一旦 set 无法在测试中清除，副作用路径由集成测试覆盖）。
fn resolve_server_env(url: Option<String>, token: Option<String>) -> Option<(String, String)> {
    match (url, token) {
        (Some(url), Some(token)) => Some((url, token)),
        (Some(_), None) | (None, Some(_)) => {
            tracing::warn!(
                "PERSONA_SERVER_URL and PERSONA_SERVER_TOKEN must both be set; event reporting disabled"
            );
            None
        }
        (None, None) => None,
    }
}

/// 命令 dispatch 结束后调用：尽力 flush 队列剩余事件（幂等）。
/// `panic = "abort"` 的崩溃路径不会经过这里（已知限制，THREAT_MODEL 登记）。
pub(crate) async fn shutdown_event_emitter() {
    if let Some(emitter) = EVENT_EMITTER.get() {
        emitter.stop().await;
    }
}

fn event_emitter() -> Option<Emitter> {
    EVENT_EMITTER.get().cloned()
}

/// [`PersonaService::new`] 的宿主包装：构造后注入全局上报器（未启用时
/// 为无操作）。返回 core Result，保持各调用点 `.into_anyhow()`/`.unwrap()`
/// 链不变。
pub(crate) async fn new_service(db: Database) -> persona_core::Result<PersonaService> {
    let mut service = PersonaService::new(db).await?;
    if let Some(emitter) = event_emitter() {
        service.set_event_emitter(Some(emitter));
    }
    Ok(service)
}

/// 绕过 `PersonaService` 直写审计库的路径（switch/migrate/remove 备份）
/// 用它补发同一事件，保证上报覆盖面。
pub(crate) fn emit_audit(log: &AuditLog) {
    if let Some(emitter) = event_emitter() {
        emitter.emit(log);
    }
}

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
    let mut service = crate::commands::service::new_service(db)
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
            crate::commands::bridge::tests::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
        )
    }

    #[test]
    fn server_env_requires_both_url_and_token() {
        // 决策纯函数：两者都设才启用，缺一只发 warn 并禁用
        assert_eq!(
            resolve_server_env(Some("http://x".into()), Some("t".into())),
            Some(("http://x".to_string(), "t".to_string()))
        );
        assert_eq!(resolve_server_env(Some("http://x".into()), None), None);
        assert_eq!(resolve_server_env(None, Some("t".into())), None);
        assert_eq!(resolve_server_env(None, None), None);
    }

    #[test]
    fn server_env_treats_blank_as_unset() {
        let _guard = lock_process_env();

        std::env::set_var("PERSONA_SERVER_URL", "   ");
        assert_eq!(non_blank_env("PERSONA_SERVER_URL"), None);

        std::env::set_var("PERSONA_SERVER_URL", "http://x");
        assert_eq!(
            non_blank_env("PERSONA_SERVER_URL"),
            Some("http://x".to_string())
        );

        std::env::remove_var("PERSONA_SERVER_URL");
        assert_eq!(non_blank_env("PERSONA_SERVER_URL"), None);
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
        let mut service = crate::commands::service::new_service(db).await.unwrap();
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

    #[test]
    fn new_master_password_prefers_env_and_falls_back_to_ui() {
        let _guard = lock_process_env();
        use crate::utils::prompt::scripted::ScriptedUi;

        // A non-blank env value wins without consulting the UI.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "env-master-pass");
        let untouched = ScriptedUi::new();
        assert_eq!(
            prompt_new_master_password(&untouched).unwrap(),
            "env-master-pass"
        );
        assert!(untouched.exhausted());

        // No env value (or a blank one) prompts, including confirmation.
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let ui = ScriptedUi::new().password("typed-master");
        assert_eq!(prompt_new_master_password(&ui).unwrap(), "typed-master");
        assert!(ui.exhausted());

        std::env::set_var("PERSONA_MASTER_PASSWORD", "   ");
        let ui = ScriptedUi::new().password("typed-again");
        assert_eq!(prompt_new_master_password(&ui).unwrap(), "typed-again");
        assert!(ui.exhausted());

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }
}
