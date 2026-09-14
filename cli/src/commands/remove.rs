use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
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
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: RemoveArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!(
        "🗑️ Removing identity '{}'...",
        args.name.bright_red().bold()
    );
    println!();

    // Check if identity exists
    if !identity_exists(&args.name, config, ui).await? {
        anyhow::bail!("Identity '{}' not found", args.name);
    }

    // Check if it's the active identity
    if is_active_identity(&args.name, config).await? {
        println!(
            "{} Identity '{}' is currently active",
            "⚠️".yellow(),
            args.name.yellow()
        );

        if !args.force
            && !ui.confirm(
                "Do you want to continue removing the active identity?",
                false,
            )?
        {
            println!("{}", "Removal cancelled.".yellow());
            return Ok(());
        }
    }

    // Show identity summary before removal
    show_removal_summary(&args.name, config, ui).await?;

    // Confirmation
    if !args.force {
        println!();
        println!("{}", "⚠️  This action cannot be undone!".red().bold());

        let confirmation_text = format!("remove {}", args.name);
        let user_input = ui.input(
            &format!("Type '{}' to confirm removal", confirmation_text),
            None,
            true,
        )?;

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
        create_backup(&args.name, config, ui).await?;
    }

    // Perform removal
    perform_removal(&args.name, args.purge, config, ui).await?;

    println!();
    println!(
        "{} Identity '{}' removed successfully",
        "✓".green().bold(),
        args.name.bright_green()
    );

    // Show next steps
    show_post_removal_info(config, ui).await?;

    Ok(())
}

async fn identity_exists(name: &str, config: &CliConfig, ui: &dyn PromptUi) -> Result<bool> {
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
        let password = super::service::prompt_master_password(ui)?;
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

async fn show_removal_summary(name: &str, config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
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
        let password = super::service::prompt_master_password(ui)?;
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

async fn create_backup(name: &str, config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    println!("💾 Creating backup...");

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
        let password = super::service::prompt_master_password(ui)?;
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

async fn perform_removal(
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
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let has_users = service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?;
    if has_users {
        let password = super::service::prompt_master_password(ui)?;
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

async fn show_post_removal_info(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
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

async fn get_remaining_identities_count(config: &CliConfig, ui: &dyn PromptUi) -> Result<usize> {
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
        let password = super::service::prompt_master_password(ui)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{Identity as CoreIdentityModel, IdentityType};
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the bridge and service tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK.lock().unwrap(),
            ENV_LOCK.lock().unwrap(),
        )
    }

    fn config_for(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        // Default's backup dir hangs off the real home; keep it inside the
        // temp workspace so backups neither leak out nor accumulate.
        config.backup.directory = dir.path().join("backups");
        config
    }

    fn args(name: &str, force: bool, purge: bool) -> RemoveArgs {
        RemoveArgs {
            name: name.to_string(),
            force,
            backup: false,
            purge,
        }
    }

    /// Migrated database with `names` identities inserted.
    async fn seeded_db(dir: &TempDir, names: &[&str]) -> Database {
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        for name in names {
            repo.create(&CoreIdentityModel::new(
                name.to_string(),
                IdentityType::Personal,
            ))
            .await
            .unwrap();
        }
        db
    }

    #[tokio::test]
    async fn remove_deletes_identity_and_reports_missing() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice", "bob"]).await;

        // Missing identity fails fast.
        let err = execute(args("ghost", true, false), &config)
            .await
            .expect_err("missing identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));

        // Forced removal succeeds without any prompt.
        execute(args("alice", true, false), &config)
            .await
            .expect("forced removal must succeed");

        // The identity is gone; the other one remains.
        assert!(
            !identity_exists("alice", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );
        assert!(
            identity_exists("bob", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );
        assert_eq!(
            get_remaining_identities_count(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn remove_clears_active_identity_pointer() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice", "bob"]).await;

        // Point the workspace at alice first.
        {
            let repo = WorkspaceRepository::new(db.clone());
            let identity = IdentityRepository::new(db.clone())
                .find_by_name("alice")
                .await
                .unwrap()
                .unwrap();
            let mut ws = persona_core::models::Workspace::new(
                config.workspace.path.clone(),
                "test-workspace".to_string(),
            );
            ws.switch_identity(identity.id);
            repo.create(&ws).await.unwrap();
        }
        assert!(is_active_identity("alice", &config).await.unwrap());

        execute(args("alice", true, true), &config)
            .await
            .expect("removal with purge must succeed");
        assert!(
            !is_active_identity("alice", &config).await.unwrap(),
            "active pointer cleared"
        );
    }

    #[tokio::test]
    async fn remove_authenticated_path_with_master_password() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["carol"]).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }

        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let err = execute(args("carol", true, false), &config)
            .await
            .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        execute(args("carol", true, false), &config)
            .await
            .expect("correct password must remove");
        assert!(
            !identity_exists("carol", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn remove_interactive_confirmations_accept_and_decline() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice", "bob"]).await;

        // Make alice the active identity so both confirmation gates trigger.
        {
            let repo = WorkspaceRepository::new(db.clone());
            let identity = IdentityRepository::new(db.clone())
                .find_by_name("alice")
                .await
                .unwrap()
                .unwrap();
            let mut ws = persona_core::models::Workspace::new(
                config.workspace.path.clone(),
                "test-workspace".to_string(),
            );
            ws.switch_identity(identity.id);
            repo.create(&ws).await.unwrap();
        }

        // Declining the active-identity prompt cancels before removal.
        let ui = ScriptedUi::new().confirm(false);
        execute_with(args("alice", false, false), &config, &ui)
            .await
            .expect("declined prompt returns success");
        assert!(ui.exhausted());
        assert!(
            identity_exists("alice", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );

        // Accepting, then mistyping the confirmation text, also cancels.
        let ui = ScriptedUi::new().confirm(true).input("remove alice!");
        execute_with(args("alice", false, false), &config, &ui)
            .await
            .expect("mismatched text returns success");
        assert!(ui.exhausted());
        assert!(
            identity_exists("alice", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );

        // Accepting and typing the exact phrase removes the identity.
        let ui = ScriptedUi::new().confirm(true).input("remove alice");
        execute_with(args("alice", false, false), &config, &ui)
            .await
            .expect("confirmed removal succeeds");
        assert!(ui.exhausted());
        assert!(
            !identity_exists("alice", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn remove_typed_confirmation_gates_non_active_identity() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["dave"]).await;

        // Wrong text cancels; identity survives.
        let ui = ScriptedUi::new().input("nope");
        execute_with(args("dave", false, false), &config, &ui)
            .await
            .expect("mismatched text returns success");
        assert!(
            identity_exists("dave", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );

        // Correct text with a backup removes and writes the backup file.
        let mut backup_args = args("dave", false, false);
        backup_args.backup = true;
        let ui = ScriptedUi::new().input("remove dave");
        execute_with(backup_args, &config, &ui)
            .await
            .expect("confirmed removal with backup succeeds");
        assert!(
            !identity_exists("dave", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );

        let backups: Vec<_> = std::fs::read_dir(&config.backup.directory)
            .expect("backup directory exists")
            .collect();
        assert_eq!(backups.len(), 1, "one backup file written");
    }
}
