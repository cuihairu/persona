use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, Select};
use std::collections::HashMap;
use tracing::info;

use crate::config::CliConfig;
use persona_core::models::{AuditAction, AuditLog, ResourceType};
use persona_core::{
    storage::{IdentityRepository, WorkspaceRepository},
    Database, PersonaService, Repository,
};

#[derive(Args)]
pub struct SwitchArgs {
    /// Identity name to switch to
    name: Option<String>,

    /// Force switch without confirmation
    #[arg(short, long)]
    force: bool,

    /// Show interactive selection menu
    #[arg(short, long)]
    interactive: bool,

    /// Switch to previous identity
    #[arg(short, long)]
    previous: bool,
}

pub async fn execute(args: SwitchArgs, config: &CliConfig) -> Result<()> {
    println!("{}", "🔄 Switching identity...".cyan().bold());
    println!();

    let target_identity = if args.previous {
        get_previous_identity(config).await?
    } else if args.interactive || args.name.is_none() {
        select_identity_interactive(config).await?
    } else {
        args.name.context("Identity name is required")?
    };

    // Get current active identity
    let current_identity = get_current_identity(config).await?;

    // Check if already active
    if let Some(ref current) = current_identity {
        if current == &target_identity {
            println!(
                "{} Identity '{}' is already active",
                "ℹ️".blue(),
                target_identity.bright_blue().bold()
            );
            return Ok(());
        }
    }

    // Verify target identity exists
    verify_identity_exists(&target_identity, config).await?;

    // Show confirmation if not forced
    if !args.force {
        let confirmation_message = if let Some(current) = &current_identity {
            format!(
                "Switch from '{}' to '{}'?",
                current.yellow(),
                target_identity.green()
            )
        } else {
            format!("Switch to '{}'?", target_identity.green())
        };

        if !Confirm::new()
            .with_prompt(confirmation_message)
            .default(true)
            .interact()?
        {
            println!("{}", "Switch cancelled.".yellow());
            return Ok(());
        }
    }

    // Perform the switch
    perform_switch(&target_identity, current_identity.as_deref(), config).await?;

    println!();
    println!(
        "{} Successfully switched to identity '{}'",
        "✓".green().bold(),
        target_identity.bright_green().bold()
    );

    // Show identity summary
    show_identity_summary(&target_identity, config).await?;

    Ok(())
}

async fn get_current_identity(config: &CliConfig) -> Result<Option<String>> {
    // Read workspace.active_identity_id; map to identity name
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
        if let Some(id) = ws.active_identity_id {
            // Try to fetch identity name
            // Prefer unlocked service; otherwise direct repo read
            let service = PersonaService::new(db.clone())
                .await
                .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
            if service
                .has_users()
                .await
                .map_err(|e| anyhow!("Failed to check users: {}", e))?
            {
                // Do not prompt here; only return None if locked
                return Ok(None);
            } else {
                let irepo = IdentityRepository::new(db);
                if let Some(identity) = irepo
                    .find_by_id(&id)
                    .await
                    .map_err(|e| anyhow!("Failed to fetch identity: {}", e))?
                {
                    return Ok(Some(identity.name));
                }
            }
        }
    }
    Ok(None)
}

async fn get_previous_identity(_config: &CliConfig) -> Result<String> {
    // TODO: implement history; fallback to error for now
    anyhow::bail!("Previous identity history not available yet")
}

async fn select_identity_interactive(config: &CliConfig) -> Result<String> {
    let identities = fetch_available_identities(config).await?;

    if identities.is_empty() {
        anyhow::bail!("No identities found. Create one with 'persona add'");
    }

    let identity_names: Vec<String> = identities.keys().cloned().collect();
    let identity_descriptions: Vec<String> = identities
        .values()
        .map(|info| format!("{} ({})", info.description, info.identity_type))
        .collect();

    let selection = Select::new()
        .with_prompt("Select identity to switch to")
        .items(&identity_descriptions)
        .interact()?;

    Ok(identity_names[selection].clone())
}

async fn verify_identity_exists(name: &str, config: &CliConfig) -> Result<()> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let mut service = service;
    let exists = if service
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
            .map_err(|e| anyhow!("Failed to authenticate user: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to lookup identity: {}", e))?
                .is_some(),
            _ => false,
        }
    } else {
        IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to lookup identity: {}", e))?
            .is_some()
    };
    if !exists {
        anyhow::bail!("Identity '{}' not found", name);
    }
    Ok(())
}

async fn perform_switch(
    target_identity: &str,
    current_identity: Option<&str>,
    config: &CliConfig,
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

    // 3. Audit log workspace enter / identity switched
    let log = AuditLog::new(AuditAction::WorkspaceEntered, ResourceType::Workspace, true)
        .with_identity_id(Some(identity.id))
        .with_resource_id(Some(path_str));
    // write audit (no unlock requirement if DB unencrypted)
    let audit_repo = persona_core::storage::AuditLogRepository::new(db);
    let _ = audit_repo
        .create(&log)
        .await
        .map_err(|e| anyhow!("Failed to write audit log: {}", e))?;

    // TODO:
    // 4. Update environment variables/session for downstream tools
    // 5. Notify agent/desktop listeners
    // 6. Record history

    Ok(())
}

async fn show_identity_summary(name: &str, config: &CliConfig) -> Result<()> {
    let identities = fetch_available_identities(config).await?;

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

#[derive(Debug, Clone)]
struct IdentityInfo {
    description: String,
    identity_type: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
    created: String,
    modified: String,
}

async fn fetch_available_identities(config: &CliConfig) -> Result<HashMap<String, IdentityInfo>> {
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
    let items = if service
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
            .map_err(|e| anyhow!("Failed to authenticate user: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => service
                .get_identities()
                .await
                .map_err(|e| anyhow!("Failed to fetch identities: {}", e))?,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        IdentityRepository::new(db)
            .find_all()
            .await
            .map_err(|e| anyhow!("Failed to list identities: {}", e))?
    };
    let mut identities = HashMap::new();
    for id in items {
        identities.insert(
            id.name.clone(),
            IdentityInfo {
                description: id.description.unwrap_or_default(),
                identity_type: id.identity_type.to_string().to_lowercase(),
                email: id.email,
                phone: id.phone,
                tags: id.tags,
                created: id.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                modified: id.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            },
        );
    }
    Ok(identities)
}
