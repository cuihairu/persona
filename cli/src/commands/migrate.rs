use crate::utils::core_ext::CoreResultExt;
use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use persona_core::{
    models::{AuditAction, AuditLog, ResourceType, Workspace},
    storage::{AuditLogRepository, WorkspaceRepository},
    Database, Repository,
};

#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// Force run migrations even if the database appears up-to-date
    #[arg(long)]
    force: bool,
}

pub async fn execute(args: MigrateArgs, config: &crate::config::CliConfig) -> Result<()> {
    println!("{}", "🗃  Running database migrations...".cyan().bold());

    // Open DB
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

    // Run migrations (idempotent)
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run migrations")?;
    println!("{} Applied migrations (if any)", "✓".green().bold());

    // Ensure Workspace row exists and is v2-compatible
    let repo = WorkspaceRepository::new(db.clone());
    let path_str = config.workspace.path.to_string_lossy().to_string();
    let ws_name = config
        .workspace
        .path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("default")
        .to_string();

    let mut created = false;
    match repo.find_by_path(&path_str).await.into_anyhow()? {
        Some(mut ws) => {
            // Upgrade fields if missing (repo.update will choose v2/v1 accordingly)
            let mut needs_update = false;
            if ws.name != ws_name {
                ws.name = ws_name.clone();
                needs_update = true;
            }
            // settings: keep as-is; path: repo will write under v2; v1 fallback is no-op
            if needs_update {
                ws.touch();
                let _ = repo.update(&ws).await.into_anyhow()?;
                println!("{} Updated workspace metadata", "✓".green().bold());
            }
        }
        None => {
            let ws = Workspace::new(config.workspace.path.clone(), ws_name);
            let _ = repo.create(&ws).await.into_anyhow()?;
            created = true;
            println!("{} Created workspace record", "✓".green().bold());
        }
    }

    // Write audit log for migration
    let audit_repo = AuditLogRepository::new(db.clone());
    let log = AuditLog::new(AuditAction::DatabaseMigration, ResourceType::Database, true)
        .with_resource_id(Some(db_path.display().to_string()));
    let _ = audit_repo.create(&log).await.into_anyhow()?;

    // Summary
    println!();
    println!("{}", "Migration summary:".yellow().bold());
    println!("  Database: {}", db_path.display().to_string().cyan());
    println!("  Workspace: {}", path_str.cyan());
    println!(
        "  Created new workspace row: {}",
        if created {
            "yes".green()
        } else {
            "no".dimmed()
        }
    );
    println!();
    println!("{}", "Done.".green().bold());
    Ok(())
}
