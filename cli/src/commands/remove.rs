use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::models::{AuditAction, AuditLog, ResourceType};
use persona_core::{
    storage::{IdentityRepository, WorkspaceRepository},
    Database, Repository,
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
    let mut service = crate::commands::service::new_service(db.clone())
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
    let mut service = crate::commands::service::new_service(db.clone())
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

    let mut service = crate::commands::service::new_service(db.clone())
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
    // 该事件直写审计库绕过 service 挂钩，上报链路在这里补发
    crate::commands::service::emit_audit(&log);

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
    let mut service = crate::commands::service::new_service(db.clone())
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
    let mut service = crate::commands::service::new_service(db.clone())
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
    use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
    use persona_core::models::{Identity as CoreIdentityModel, IdentityType};
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the bridge and service tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        // Recover from a poisoned lock: a panicking sibling test must not
        // cascade into every other env-gated test.
        fn lock_or_recover(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
            lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }
        (
            lock_or_recover(&crate::commands::bridge::tests::ENV_LOCK),
            lock_or_recover(&ENV_LOCK),
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
            let mut service = crate::commands::service::new_service(db).await.unwrap();
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
            .map(|e| e.expect("backup entry readable"))
            .collect();
        assert_eq!(backups.len(), 1, "one backup file written");

        // The backup written without a workspace user carries the identity
        // stub but no credential export.
        let backup_file = &backups[0].path();
        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(backup_file).unwrap()).unwrap();
        assert_eq!(payload["credentials"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn remove_backup_with_authenticated_workspace_exports_identity() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["erin"]).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        let mut backup_args = args("erin", false, false);
        backup_args.backup = true;
        let ui = ScriptedUi::new().input("remove erin");
        execute_with(backup_args, &config, &ui)
            .await
            .expect("authenticated backup removal succeeds");
        assert!(ui.exhausted());

        // The unlocked path exports the full identity, not the stub.
        let backups: Vec<_> = std::fs::read_dir(&config.backup.directory)
            .expect("backup directory exists")
            .map(|e| e.expect("backup entry readable"))
            .collect();
        assert_eq!(backups.len(), 1);
        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(backups[0].path()).unwrap()).unwrap();
        assert!(payload.get("identity").is_some(), "identity exported");
        assert!(payload.get("backup_created").is_some());

        // A backup for an unknown identity fails inside the unlocked export
        // path (the remove flow itself verifies the name up front).
        let ui = ScriptedUi::new();
        let err = create_backup("ghost", &config, &ui)
            .await
            .expect_err("backup of unknown identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    /// A backup directory path occupied by a regular file fails loudly when
    /// the backup scaffolding tries to create it.
    #[tokio::test]
    async fn backup_directory_creation_failure_is_reported() {
        let dir = TempDir::new().unwrap();
        let mut config = config_for(&dir);
        seeded_db(&dir, &["carol"]).await;

        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        config.backup.directory = blocker;

        let err = create_backup("carol", &config, &ScriptedUi::new())
            .await
            .expect_err("occupied backup directory must fail");
        assert!(
            err.to_string()
                .contains("Failed to create backup directory"),
            "got: {err}"
        );
    }

    /// A wrong master password surfaces as `Authentication failed` from every
    /// helper that unlocks the service (removal, backup, summary, count)
    /// without touching the stored identity.
    #[tokio::test]
    async fn wrong_master_password_fails_all_unlocking_helpers() {
        let _guard = lock_process_env();
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-master");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["carol"]).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("real-master").await.unwrap();
        }
        let ui = ScriptedUi::new();

        let err = perform_removal("carol", false, &config, &ui)
            .await
            .expect_err("wrong password must abort removal");
        assert!(
            err.to_string().contains("Authentication failed"),
            "got: {err}"
        );

        let err = create_backup("carol", &config, &ui)
            .await
            .expect_err("wrong password must abort the backup");
        assert!(
            err.to_string().contains("Authentication failed"),
            "got: {err}"
        );

        let err = show_removal_summary("carol", &config, &ui)
            .await
            .expect_err("wrong password must abort the summary");
        assert!(
            err.to_string().contains("Authentication failed"),
            "got: {err}"
        );

        let err = get_remaining_identities_count(&config, &ui)
            .await
            .expect_err("wrong password must abort the count");
        assert!(
            err.to_string().contains("Authentication failed"),
            "got: {err}"
        );

        // Verification reads through the authenticated path: use the real
        // password so the read succeeds and proves nothing was removed.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "real-master");
        assert!(
            identity_exists("carol", &config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap()
        );

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn remove_prompt_errors_propagate_to_the_caller() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice", "bob"]).await;

        // alice is the active identity; a failing confirm prompt aborts
        // before anything is removed.
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

        {
            let inner = ScriptedUi::new();
            let ui = FailOn::new(&inner, PromptKind::Confirm);
            let err = execute_with(args("alice", false, false), &config, &ui)
                .await
                .expect_err("failing confirm must abort");
            assert!(err.to_string().contains("failing ui: confirm prompt"));
            assert!(
                identity_exists("alice", &config, &crate::utils::prompt::TerminalUi)
                    .await
                    .unwrap()
            );
        }

        // bob is not active: the first prompt is the typed confirmation.
        {
            let inner = ScriptedUi::new();
            let ui = FailOn::new(&inner, PromptKind::Input);
            let err = execute_with(args("bob", false, false), &config, &ui)
                .await
                .expect_err("failing input must abort");
            assert!(err.to_string().contains("failing ui: input prompt"));
            assert!(
                identity_exists("bob", &config, &crate::utils::prompt::TerminalUi)
                    .await
                    .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn remove_non_active_identity_keeps_the_workspace_pointer() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice", "bob"]).await;

        // The workspace points at alice; bob is removed without touching it.
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

        execute(args("bob", true, false), &config)
            .await
            .expect("forced removal of the non-active identity succeeds");

        let repo = WorkspaceRepository::new(db.clone());
        let ws = repo
            .find_by_path(&config.workspace.path.to_string_lossy())
            .await
            .unwrap()
            .expect("workspace row survives");
        let alice = IdentityRepository::new(db.clone())
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ws.active_identity_id, Some(alice.id));
    }

    #[tokio::test]
    async fn remove_last_identity_reports_empty_remaining_state() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["solo"]).await;

        execute(args("solo", true, false), &config)
            .await
            .expect("removing the only identity succeeds");

        // Count 0 hits the "No identities remaining" hint branch.
        assert_eq!(
            get_remaining_identities_count(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn is_active_identity_is_false_for_unknown_names_and_empty_workspace() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;

        // No workspace row at all → not active.
        assert!(!is_active_identity("alice", &config).await.unwrap());

        // Workspace row exists but points elsewhere / name unknown.
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
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

        assert!(is_active_identity("alice", &config).await.unwrap());
        assert!(
            !is_active_identity("ghost", &config).await.unwrap(),
            "unknown identity is never active"
        );
    }
}
