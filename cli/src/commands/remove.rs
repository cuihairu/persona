use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, Input};

use crate::config::CliConfig;

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
    println!("{} Removing identity '{}'...", 
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
        println!("{} Identity '{}' is currently active", 
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
            println!("{}", "Removal cancelled - confirmation text didn't match.".yellow());
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
    println!("{} Identity '{}' removed successfully", 
        "✓".green().bold(), 
        args.name.bright_green()
    );

    // Show next steps
    show_post_removal_info(config).await?;

    Ok(())
}

async fn identity_exists(name: &str, _config: &CliConfig) -> Result<bool> {
    // TODO: Implement actual database check using persona-core
    // For now, assume identity exists if it's one of our mock identities
    let mock_identities = ["personal", "work", "social"];
    Ok(mock_identities.contains(&name))
}

async fn is_active_identity(name: &str, _config: &CliConfig) -> Result<bool> {
    // TODO: Implement actual active identity check using persona-core
    // For now, assume "personal" is active
    Ok(name == "personal")
}

async fn show_removal_summary(name: &str, _config: &CliConfig) -> Result<()> {
    // TODO: Fetch actual identity details from database
    println!("{}", "Identity to be removed:".yellow().bold());
    println!("  Name: {}", name.cyan());
    println!("  Type: {}", "personal".cyan());
    println!("  Email: {}", "john@example.com".cyan());
    println!("  Created: {}", "2024-01-15 10:30:00".dim());
    println!("  Last used: {}", "2024-01-22 09:15:00".dim());
    
    Ok(())
}

async fn create_backup(name: &str, config: &CliConfig) -> Result<()> {
    println!("{} Creating backup...", "💾".to_string());
    
    let backup_path = config.backup.directory.join(format!("{}_backup_{}.json", 
        name, 
        chrono::Utc::now().format("%Y%m%d_%H%M%S")
    ));

    // TODO: Implement actual backup creation using persona-core
    // This would export the identity data to a backup file
    
    // Create backup directory if it doesn't exist
    if let Some(parent) = backup_path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create backup directory")?;
    }

    // Mock backup creation
    let backup_data = serde_json::json!({
        "identity": {
            "name": name,
            "type": "personal",
            "email": "john@example.com",
            "created": "2024-01-15 10:30:00",
            "backup_created": chrono::Utc::now().to_rfc3339()
        }
    });

    std::fs::write(&backup_path, serde_json::to_string_pretty(&backup_data)?)
        .context("Failed to write backup file")?;

    println!("{} Backup created: {}", 
        "✓".green().bold(), 
        backup_path.display().to_string().dim()
    );

    Ok(())
}

async fn perform_removal(name: &str, purge: bool, _config: &CliConfig) -> Result<()> {
    println!("{} Removing identity data...", "🔄".to_string());

    // TODO: Implement actual removal using persona-core
    // This would involve:
    // 1. Removing identity from database
    // 2. Clearing associated files if purge is true
    // 3. Updating active identity if this was active
    // 4. Cleaning up temporary files
    // 5. Updating usage statistics

    if purge {
        println!("{} Purging all associated data...", "🧹".to_string());
        // Remove all associated files, caches, etc.
    }

    // Simulate removal operation
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    Ok(())
}

async fn show_post_removal_info(config: &CliConfig) -> Result<()> {
    // Check if there are remaining identities
    let remaining_count = get_remaining_identities_count(config).await?;

    if remaining_count == 0 {
        println!();
        println!("{}", "No identities remaining.".yellow());
        println!("{}", "Create a new identity with:".dim());
        println!("  {}", "persona add".cyan());
    } else {
        println!();
        println!("{}", "Remaining identities:".dim());
        println!("  View all: {}", "persona list".cyan());
        println!("  Switch to another: {}", "persona switch <name>".cyan());
    }

    Ok(())
}

async fn get_remaining_identities_count(_config: &CliConfig) -> Result<usize> {
    // TODO: Implement actual count from database
    Ok(2) // Mock remaining count
}