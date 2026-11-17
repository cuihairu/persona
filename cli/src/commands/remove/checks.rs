use anyhow::{anyhow, Result};

use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use persona_core::{
    storage::{IdentityRepository, WorkspaceRepository},
    Database,
};

pub(super) async fn identity_exists(
    name: &str,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<bool> {
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
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Lookup failed: {}", e))?
                .is_some()),
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        Ok(IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow!("Lookup failed: {}", e))?
            .is_some())
    }
}

pub(super) async fn is_active_identity(name: &str, config: &CliConfig) -> Result<bool> {
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
