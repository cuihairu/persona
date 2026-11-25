use super::identity::fetch_available_identities;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use anyhow::Context;
use anyhow::{anyhow, Result};
use colored::*;
use persona_core::context::cwd_hash;
use persona_core::models::{AuditAction, AuditLog, ResourceType};
use persona_core::storage::{ContextLearnRepository, IdentityRepository, WorkspaceRepository};
use persona_core::Database;
use persona_core::Repository;
use tracing::info;

pub(crate) async fn perform_switch(
    target_identity: &str,
    current_identity: Option<&str>,
    config: &CliConfig,
    ui: &dyn PromptUi,
    suggestion: Option<&(String, String)>,
) -> Result<()> {
    info!(
        "Switching from {:?} to {}",
        current_identity, target_identity
    );

    // 1. Resolve target identity id
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let identity = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        let password = crate::commands::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to authenticate user: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => service
                .get_identity_by_name(target_identity)
                .await
                .map_err(|e| anyhow!("Failed to load identity: {}", e))?,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        IdentityRepository::new(db.clone())
            .find_by_name(target_identity)
            .await
            .map_err(|e| anyhow!("Failed to load identity: {}", e))?
    };
    let identity = identity.with_context(|| format!("Identity '{}' not found", target_identity))?;

    // 2. Update workspace.active_identity_id (v2 schema; legacy no-op via repo fallback)
    let repo = WorkspaceRepository::new(db.clone());
    let path_str = config.workspace.path.to_string_lossy().to_string();
    if let Some(mut ws) = repo
        .find_by_path(&path_str)
        .await
        .map_err(|e| anyhow!("Failed to load workspace: {}", e))?
    {
        ws.switch_identity(identity.id);
        let _ = repo
            .update(&ws)
            .await
            .map_err(|e| anyhow!("Failed to update workspace: {}", e))?;
    }

    // 3. Audit log workspace enter / identity switched. A `persona use`
    // confirmation of the current top suggestion records the reason —
    // Design acceptance: the audit carries the reason (only the confirmation is recorded, not the signal itself; the §3 privacy boundary).
    let reason = suggestion
        .filter(|(name, _)| name == target_identity)
        .map(|(_, reason)| reason);
    let mut log = AuditLog::new(AuditAction::WorkspaceEntered, ResourceType::Workspace, true)
        .with_identity_id(Some(identity.id))
        .with_resource_id(Some(path_str));
    if let Some(reason) = reason {
        log = log.with_details(Some(format!("confirmed context suggestion: {reason}")));
    }
    // write audit (no unlock requirement if DB unencrypted)
    let audit_repo = persona_core::storage::AuditLogRepository::new(db);
    let _ = audit_repo
        .create(&log)
        .await
        .map_err(|e| anyhow!("Failed to write audit log: {}", e))?;
    // This event is written straight to the audit vault, bypassing the service hook, so the reporting chain is fired here
    crate::commands::service::emit_audit(&log);

    // 4. Context learning (phase 2, off by default): the confirmation lands in the local
    // learning table so later suggest runs can order by "most recently used in the same
    // directory". Degradation principle (design §10): a learning-write failure never
    // affects the switch itself.
    if let Err(e) = record_learn_sample(target_identity, config).await {
        info!("context learn recording skipped: {e}");
    }

    // TODO:
    // 5. Update environment variables/session for downstream tools
    // 6. Notify agent/desktop listeners

    Ok(())
}

/// Learning-table write (wired to the switch): a no-op when the toggle is off. The directory
/// hash shares its source with the suggest side (`config.workspace.path`), and the host is
/// the currently collected signal.
async fn record_learn_sample(identity_name: &str, config: &CliConfig) -> Result<()> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path).await?;
    db.migrate().await?;
    let repo = ContextLearnRepository::new(db);
    if !repo.learn_enabled().await? {
        return Ok(());
    }
    repo.record(
        identity_name,
        &cwd_hash(&config.workspace.path),
        persona_core::context::current_host().as_deref(),
        chrono::Utc::now(),
    )
    .await?;
    Ok(())
}

pub(super) async fn show_identity_summary(
    name: &str,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let identities = fetch_available_identities(config, ui).await?;

    if let Some(info) = identities.get(name) {
        println!();
        println!("{}", "Identity Summary:".yellow().bold());
        println!("  Name: {}", name.bright_cyan());
        println!("  Type: {}", info.identity_type.cyan());
        println!("  Description: {}", info.description.dimmed());

        if let Some(ref email) = info.email {
            println!("  Email: {}", email.cyan());
        }

        if let Some(ref phone) = info.phone {
            println!("  Phone: {}", phone.cyan());
        }

        if !info.tags.is_empty() {
            println!("  Tags: {}", info.tags.join(", ").dimmed());
        }
    }

    Ok(())
}
