use anyhow::{anyhow, Result};
use colored::*;

use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use persona_core::{storage::IdentityRepository, Database, Repository};

pub(super) async fn show_post_removal_info(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    // Check if there are remaining identities
    let remaining_count = get_remaining_identities_count(config, ui).await?;

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

pub(super) async fn get_remaining_identities_count(
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<usize> {
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
    if service
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
            persona_core::auth::authentication::AuthResult::Success => Ok(service
                .get_identities()
                .await
                .map_err(|e| anyhow!("Failed to fetch identities: {}", e))?
                .len()),
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        Ok(IdentityRepository::new(db.clone())
            .find_all()
            .await
            .map_err(|e| anyhow!("Failed to fetch identities: {}", e))?
            .len())
    }
}
