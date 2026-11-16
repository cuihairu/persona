use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use anyhow::{anyhow, Result};
use persona_core::models::AuditAction;
use persona_core::storage::{AuditLogRepository, IdentityRepository, WorkspaceRepository};
use persona_core::Database;
use persona_core::Repository;
use std::collections::BTreeMap;

pub(super) async fn get_current_identity(config: &CliConfig) -> Result<Option<String>> {
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
            let service = crate::commands::service::new_service(db.clone())
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

/// Resolve the previous identity from the audit trail: the most recent
/// WorkspaceEntered entry pointing at a live identity other than the one
/// that is currently active.
pub(super) async fn get_previous_identity(config: &CliConfig) -> Result<String> {
    let current = get_current_identity(config).await?;

    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;

    let entries = AuditLogRepository::new(db.clone())
        .find_by_action(&AuditAction::WorkspaceEntered)
        .await
        .map_err(|e| anyhow!("Failed to read audit history: {}", e))?;
    let irepo = IdentityRepository::new(db);
    for entry in entries {
        let Some(id) = entry.identity_id else {
            continue;
        };
        let Some(identity) = irepo
            .find_by_id(&id)
            .await
            .map_err(|e| anyhow!("Failed to fetch identity: {}", e))?
        else {
            continue; // identity was deleted since the switch
        };
        if Some(&identity.name) == current.as_ref() {
            continue;
        }
        return Ok(identity.name);
    }
    anyhow::bail!("No previous identity recorded yet")
}

pub(super) async fn select_identity_interactive(
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<String> {
    let identities = fetch_available_identities(config, ui).await?;

    if identities.is_empty() {
        anyhow::bail!("No identities found. Create one with 'persona add'");
    }

    let identity_names: Vec<String> = identities.keys().cloned().collect();
    let identity_descriptions: Vec<String> = identities
        .values()
        .map(|info| format!("{} ({})", info.description, info.identity_type))
        .collect();

    let selection = ui.select(
        "Select identity to switch to",
        &identity_descriptions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        None,
    )?;

    Ok(identity_names[selection].clone())
}

pub(super) async fn verify_identity_exists(
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
    let service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let mut service = service;
    let exists = if service
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
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to lookup identity: {}", e))?
                .is_some(),
            other => anyhow::bail!("Authentication failed: {:?}", other),
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

#[derive(Debug, Clone)]
pub(super) struct IdentityInfo {
    pub(super) description: String,
    pub(super) identity_type: String,
    pub(super) email: Option<String>,
    pub(super) phone: Option<String>,
    pub(super) tags: Vec<String>,
}

/// BTreeMap keeps the interactive selection menu ordered by name instead of
/// HashMap's per-process random iteration order.
pub(super) async fn fetch_available_identities(
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<BTreeMap<String, IdentityInfo>> {
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
    let items = if service
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
    let mut identities = BTreeMap::new();
    for id in items {
        identities.insert(
            id.name.clone(),
            IdentityInfo {
                description: id.description.unwrap_or_default(),
                identity_type: id.identity_type.to_string().to_lowercase(),
                email: id.email,
                phone: id.phone,
                tags: id.tags,
            },
        );
    }
    Ok(identities)
}
