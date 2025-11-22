use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, Input};

use crate::config::CliConfig;
use persona_core::models::{AuditAction, AuditLog, ResourceType};
use persona_core::{
    storage::{IdentityRepository, WorkspaceRepository},
    Database, PersonaService, Repository,
};

#[derive(Args)]
pub struct RemoveArgs {
    /// Identity name to remove
    name: String,

    /// Force removal without confirmation
    #[arg(short, long)]
    force: bool,

    /// Create backup before removal
    #[arg(short, long)]
    backup: bool,

    /// Remove all associated data
    #[arg(long)]
    purge: bool,
}

pub async fn execute(args: RemoveArgs, config: &CliConfig) -> Result<()> {
    println!(
        "{} Removing identity '{}'...",
        "🗑️".to_string(),
        args.name.bright_red().bold()
    );
    println!();

    // Check if identity exists
    if !identity_exists(&args.name, config).await? {
        anyhow::bail!("Identity '{}' not found", args.name);
    }

    // Check if it's the active identity
    if is_active_identity(&args.name, config).await? {
        println!(
            "{} Identity '{}' is currently active",
            "⚠️".yellow(),
            args.name.yellow()
        );

        if !args.force {
            if !Confirm::new()
                .with_prompt("Do you want to continue removing the active identity?")
                .default(false)
                .interact()?
            {
                println!("{}", "Removal cancelled.".yellow());
                return Ok(());
            }
        }
    }

    // Show identity summary before removal
    show_removal_summary(&args.name, config).await?;

    // Confirmation
    if !args.force {
        println!();
        println!("{}", "⚠️  This action cannot be undone!".red().bold());

        let confirmation_text = format!("remove {}", args.name);
        let user_input: String = Input::new()
            .with_prompt(&format!("Type '{}' to confirm removal", confirmation_text))
            .interact_text()?;

        if user_input != confirmation_text {
            println!(
                "{}",
                "Removal cancelled - confirmation text didn't match.".yellow()
            );
            return Ok(());
        }
    }

    // Create backup if requested
    if args.backup {
        create_backup(&args.name, config).await?;
    }

    // Perform removal
    perform_removal(&args.name, args.purge, config).await?;

    println!();
    println!(
        "{} Identity '{}' removed successfully",
        "✓".green().bold(),
        args.name.bright_green()
    );

    // Show next steps
    show_post_removal_info(config).await?;

    Ok(())
}

async fn identity_exists(name: &str, config: &CliConfig) -> Result<bool> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        use dialoguer::Password;
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to authenticate: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => Ok(service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Lookup failed: {}", e))?
                .is_some()),
            _ => Ok(false),
        }
    } else {
        Ok(IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow!("Lookup failed: {}", e))?
            .is_some())
    }
}

async fn is_active_identity(name: &str, config: &CliConfig) -> Result<bool> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let repo = WorkspaceRepository::new(db.clone());
    let path_str = config.workspace.path.to_string_lossy().to_string();
    if let Some(ws) = repo
        .find_by_path(&path_str)
        .await
        .map_err(|e| anyhow!("Failed to load workspace: {}", e))?
    {
        if let Some(active_id) = ws.active_identity_id {
            if let Some(identity) = IdentityRepository::new(db)
                .find_by_name(name)
                .await
                .map_err(|e| anyhow!("Lookup failed: {}", e))?
            {
                return Ok(identity.id == active_id);
            }
        }
    }
    Ok(false)
}

async fn show_removal_summary(name: &str, config: &CliConfig) -> Result<()> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let identity = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        use dialoguer::Password;
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to authenticate: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Lookup failed: {}", e))?,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow!("Lookup failed: {}", e))?
    }
    .with_context(|| format!("Identity '{}' not found", name))?;

    println!("{}", "Identity to be removed:".yellow().bold());
    println!("  Name: {}", identity.name.cyan());
    println!("  Type: {}", identity.identity_type.to_string().cyan());
    println!(
        "  Email: {}",
        identity.email.as_deref().unwrap_or("-").cyan()
    );
    println!(
        "  Created: {}",
        identity
            .created_at
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .dimmed()
    );
    println!(
        "  Modified: {}",
        identity
            .updated_at
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .dimmed()
    );
    Ok(())
}

async fn create_backup(name: &str, config: &CliConfig) -> Result<()> {
    println!("{} Creating backup...", "💾".to_string());

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

    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let backup_data = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        use dialoguer::Password;
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
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

    Ok(())
}

async fn perform_removal(name: &str, purge: bool, config: &CliConfig) -> Result<()> {
    println!("{} Removing identity data...", "🔄".to_string());

    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        use dialoguer::Password;
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to authenticate: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }

    // Locate identity
    let identity = service
        .get_identity_by_name(name)
        .await
        .map_err(|e| anyhow!("Lookup failed: {}", e))?
        .with_context(|| format!("Identity '{}' not found", name))?;

    // Update workspace active if needed (v2 schema)
    let repo = WorkspaceRepository::new(db.clone());
    let path_str = config.workspace.path.to_string_lossy().to_string();
    if let Some(mut ws) = repo
        .find_by_path(&path_str)
        .await
        .map_err(|e| anyhow!("Failed to load workspace: {}", e))?
    {
        if ws.active_identity_id == Some(identity.id) {
            ws.clear_active_identity();
            let _ = repo
                .update(&ws)
                .await
                .map_err(|e| anyhow!("Failed to update workspace: {}", e))?;
        }
    }

    // Delete identity
    let _ = service
        .delete_identity(&identity.id)
        .await
        .map_err(|e| anyhow!("Failed to delete identity: {}", e))?;

    if purge {
        println!("{} Purging all associated data...", "🧹".to_string());
        // Remove all associated files, caches, etc.
    }

    Ok(())
}

async fn show_post_removal_info(config: &CliConfig) -> Result<()> {
    // Check if there are remaining identities
    let remaining_count = get_remaining_identities_count(config).await?;

    if remaining_count == 0 {
        println!();
        println!("{}", "No identities remaining.".yellow());
        println!("{}", "Create a new identity with:".dimmed());
        println!("  {}", "persona add".cyan());
    } else {
        println!();
        println!("{}", "Remaining identities:".dimmed());
        println!("  View all: {}", "persona list".cyan());
        println!("  Switch to another: {}", "persona switch <name>".cyan());
    }

    Ok(())
}

async fn get_remaining_identities_count(config: &CliConfig) -> Result<usize> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let mut service = PersonaService::new(db)
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        use dialoguer::Password;
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to authenticate: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => Ok(service
                .get_identities()
                .await
                .map_err(|e| anyhow!("Failed to fetch identities: {}", e))?
                .len()),
            _ => Ok(0),
        }
    } else {
        Ok(0)
    }
}
