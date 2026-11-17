use anyhow::{anyhow, Context, Result};
use colored::*;

use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use persona_core::{storage::IdentityRepository, Database};

pub(super) async fn show_removal_summary(
    name: &str,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
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
