//! 持久化与校验：身份存在性检查、加载（认证/免密两路）、变更校验
//! 与保存（按 id 或名称回读后更新，认证工作区走 service）。

use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use persona_core::{
    models::{Identity as CoreIdentity, IdentityType},
    storage::IdentityRepository,
    Database,
};

use super::Identity;

pub(super) async fn identity_exists(
    name: &str,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<bool> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create service: {}", e))?;
    if service
        .has_users()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check users: {}", e))?
    {
        let password = crate::commands::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow::anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => Ok(service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .is_some()),
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        Ok(IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
            .is_some())
    }
}

pub(super) async fn load_identity(
    name: &str,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<Identity> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create service: {}", e))?;
    let core: CoreIdentity = if service
        .has_users()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check users: {}", e))?
    {
        let password = crate::commands::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow::anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .with_context(|| format!("Identity '{}' not found", name))?,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
            .with_context(|| format!("Identity '{}' not found", name))?
    };

    Ok(Identity {
        id: Some(core.id),
        name: core.name,
        identity_type: core.identity_type.to_string(),
        description: core.description.unwrap_or_default(),
        email: core.email,
        phone: core.phone,
        tags: core.tags,
        attributes: core
            .attributes
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect(),
        modified: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

pub(super) fn validate_identity(identity: &Identity) -> Result<()> {
    if identity.name.is_empty() {
        anyhow::bail!("Identity name cannot be empty");
    }

    if let Some(ref email) = identity.email {
        if !email.contains('@') || !email.contains('.') {
            anyhow::bail!("Invalid email format");
        }
    }

    if let Some(ref phone) = identity.phone {
        if phone.len() < 10 {
            anyhow::bail!("Phone number too short");
        }
    }

    Ok(())
}

pub(super) async fn save_identity(
    identity: &Identity,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create service: {}", e))?;
    let has_users = service
        .has_users()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check users: {}", e))?;
    if has_users {
        let password = crate::commands::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow::anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }

    // Load current identity (by id if present). Unencrypted, user-less
    // workspaces never unlock a service, so fall back to direct repository
    // reads like load/switch/remove do.
    let mut current = if has_users {
        if let Some(id) = identity.id {
            service
                .get_identity(&id)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .with_context(|| format!("Identity not found by id {}", id))?
        } else {
            service
                .get_identity_by_name(&identity.name)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .with_context(|| "Identity not found".to_string())?
        }
    } else {
        use persona_core::Repository;
        let repo = IdentityRepository::new(db.clone());
        if let Some(id) = identity.id {
            repo.find_by_id(&id)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .with_context(|| format!("Identity not found by id {}", id))?
        } else {
            repo.find_by_name(&identity.name)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .with_context(|| "Identity not found".to_string())?
        }
    };

    // Apply changes
    current.name = identity.name.clone();
    current.identity_type = identity
        .identity_type
        .parse::<IdentityType>()
        .unwrap_or(IdentityType::Custom(identity.identity_type.clone()));
    current.description = if identity.description.is_empty() {
        None
    } else {
        Some(identity.description.clone())
    };
    current.email = identity.email.clone();
    current.phone = identity.phone.clone();
    current.tags = identity.tags.clone();
    current.attributes = identity
        .attributes
        .iter()
        .map(|(k, v)| {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                other => other.to_string(),
            };
            (k.clone(), s)
        })
        .collect();
    current.touch();

    if has_users {
        service
            .update_identity(&current)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to update identity: {}", e))?;
    } else {
        use persona_core::Repository;
        IdentityRepository::new(db)
            .update(&current)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to update identity: {}", e))?;
    }
    Ok(())
}
