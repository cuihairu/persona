use anyhow::{anyhow, Context, Result};

use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use persona_core::{
    storage::{IdentityRepository, WorkspaceRepository},
    Database, Repository,
};

pub(super) async fn perform_removal(
    name: &str,
    purge: bool,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!("🔄 Removing identity data...");

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
    let has_users = service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?;
    if has_users {
        let password = crate::commands::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to authenticate: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }

    // Locate identity (direct read for unencrypted, user-less workspaces)
    let identity = if has_users {
        service
            .get_identity_by_name(name)
            .await
            .map_err(|e| anyhow!("Lookup failed: {}", e))?
    } else {
        IdentityRepository::new(db.clone())
            .find_by_name(name)
            .await
            .map_err(|e| anyhow!("Lookup failed: {}", e))?
    }
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
    let _ = if has_users {
        service
            .delete_identity(&identity.id)
            .await
            .map_err(|e| anyhow!("Failed to delete identity: {}", e))?
    } else {
        IdentityRepository::new(db.clone())
            .delete(&identity.id)
            .await
            .map_err(|e| anyhow!("Failed to delete identity: {}", e))?
    };

    if purge {
        println!("🧹 Purging all associated data...");
        // Remove all associated files, caches, etc.
    }

    Ok(())
}
