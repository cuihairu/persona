use anyhow::{anyhow, Context, Result};
use colored::*;

use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use persona_core::models::{AuditAction, AuditLog, ResourceType};
use persona_core::{storage::IdentityRepository, Database, Repository};

pub(super) async fn create_backup(name: &str, config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    println!("💾 Creating backup...");

    let backup_path = config.backup.directory.join(format!(
        "{}_backup_{}.json",
        name,
        chrono::Utc::now().format("%Y%m%d_%H%M%S")
    ));

    // Export identity data via persona-core if unlocked; otherwise write minimal stub
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;

    // Create backup directory if it doesn't exist
    if let Some(parent) = backup_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create backup directory")?;
    }

    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let backup_data = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        let password = crate::commands::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to authenticate: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {
                if let Some(identity) = service
                    .get_identity_by_name(name)
                    .await
                    .map_err(|e| anyhow!("Lookup failed: {}", e))?
                {
                    let export = service
                        .export_identity(&identity.id)
                        .await
                        .map_err(|e| anyhow!("Export failed: {}", e))?;
                    serde_json::json!({
                        "identity": export.identity,
                        "credentials": export.credentials,
                        "backup_created": chrono::Utc::now().to_rfc3339()
                    })
                } else {
                    anyhow::bail!("Identity '{}' not found", name);
                }
            }
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        // Without unlock, write minimal metadata
        let repo = IdentityRepository::new(db);
        let identity = repo
            .find_by_name(name)
            .await
            .map_err(|e| anyhow!("Lookup failed: {}", e))?
            .with_context(|| format!("Identity '{}' not found", name))?;
        serde_json::json!({
            "identity": identity,
            "credentials": [],
            "backup_created": chrono::Utc::now().to_rfc3339()
        })
    };

    std::fs::write(&backup_path, serde_json::to_string_pretty(&backup_data)?)
        .context("Failed to write backup file")?;

    println!(
        "{} Backup created: {}",
        "✓".green().bold(),
        backup_path.display().to_string().dimmed()
    );

    // Audit backup creation
    let audit_db = Database::from_file(&config.get_database_path())
        .await
        .map_err(|e| anyhow!("Failed to open database for audit: {}", e))?;
    audit_db
        .migrate()
        .await
        .map_err(|e| anyhow!("Failed to run audit migrations: {}", e))?;
    let audit_repo = persona_core::storage::AuditLogRepository::new(audit_db);
    let log = AuditLog::new(AuditAction::BackupCreated, ResourceType::Identity, true)
        .with_resource_id(Some(name.to_string()));
    let _ = audit_repo
        .create(&log)
        .await
        .map_err(|e| anyhow!("Failed to write audit log: {}", e))?;
    // 该事件直写审计库绕过 service 挂钩，上报链路在这里补发
    crate::commands::service::emit_audit(&log);

    Ok(())
}
