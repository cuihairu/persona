use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;
use std::collections::BTreeMap;
use tracing::info;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
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
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: SwitchArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!("{}", "🔄 Switching identity...".cyan().bold());
    println!();

    let target_identity = if args.previous {
        get_previous_identity(config).await?
    } else if args.interactive || args.name.is_none() {
        select_identity_interactive(config, ui).await?
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
    verify_identity_exists(&target_identity, config, ui).await?;

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

        if !ui.confirm(&confirmation_message, true)? {
            println!("{}", "Switch cancelled.".yellow());
            return Ok(());
        }
    }

    // Perform the switch
    perform_switch(&target_identity, current_identity.as_deref(), config, ui).await?;

    println!();
    println!(
        "{} Successfully switched to identity '{}'",
        "✓".green().bold(),
        target_identity.bright_green().bold()
    );

    // Show identity summary
    show_identity_summary(&target_identity, config, ui).await?;

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

async fn select_identity_interactive(config: &CliConfig, ui: &dyn PromptUi) -> Result<String> {
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

async fn verify_identity_exists(name: &str, config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
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
        let password = super::service::prompt_master_password(ui)?;
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

async fn perform_switch(
    target_identity: &str,
    current_identity: Option<&str>,
    config: &CliConfig,
    ui: &dyn PromptUi,
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
        let password = super::service::prompt_master_password(ui)?;
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

async fn show_identity_summary(name: &str, config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    let identities = fetch_available_identities(config, ui).await?;

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
}

/// BTreeMap keeps the interactive selection menu ordered by name instead of
/// HashMap's per-process random iteration order.
async fn fetch_available_identities(
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
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let items = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        let password = super::service::prompt_master_password(ui)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{
        AuditAction, Identity as CoreIdentityModel, IdentityType, Workspace,
    };
    use persona_core::storage::{AuditLogRepository, WorkspaceRepository};
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
        config
    }

    fn args(name: Option<&str>, force: bool) -> SwitchArgs {
        SwitchArgs {
            name: name.map(String::from),
            force,
            interactive: false,
            previous: false,
        }
    }

    fn switch_args(name: Option<&str>, force: bool) -> SwitchArgs {
        args(name, force)
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

    /// `persona migrate` normally guarantees a workspace row; create it directly.
    async fn ensure_workspace_row(db: &Database, config: &CliConfig) {
        let repo = WorkspaceRepository::new(db.clone());
        repo.create(&Workspace::new(
            config.workspace.path.clone(),
            "test-workspace".to_string(),
        ))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn switch_updates_workspace_and_audits_without_users() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice", "bob"]).await;

        // Migrate command guarantees a workspace row for this path.
        ensure_workspace_row(&db, &config).await;

        execute(switch_args(Some("alice"), true), &config)
            .await
            .expect("forced switch must succeed");

        let repo = WorkspaceRepository::new(db.clone());
        let path_str = config.workspace.path.to_string_lossy().to_string();
        let ws = repo
            .find_by_path(&path_str)
            .await
            .unwrap()
            .expect("workspace row exists");
        let active_id = ws.active_identity_id.expect("active identity recorded");

        let identity = IdentityRepository::new(db.clone())
            .find_by_name("alice")
            .await
            .unwrap()
            .expect("alice exists");
        assert_eq!(active_id, identity.id);

        // Switching to the same identity short-circuits with "already active".
        execute(switch_args(Some("alice"), true), &config)
            .await
            .expect("already-active switch is a no-op");

        // One audit entry for the single real switch.
        let audits = AuditLogRepository::new(db.clone())
            .find_by_action(&AuditAction::WorkspaceEntered)
            .await
            .unwrap();
        assert_eq!(audits.len(), 1);
    }

    #[tokio::test]
    async fn switch_between_identities_audits_twice_and_errors_paths() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice", "bob"]).await;
        ensure_workspace_row(&db, &config).await;

        execute(switch_args(Some("alice"), true), &config)
            .await
            .unwrap();
        execute(switch_args(Some("bob"), true), &config)
            .await
            .unwrap();

        let repo = WorkspaceRepository::new(db.clone());
        let path_str = config.workspace.path.to_string_lossy().to_string();
        let ws = repo.find_by_path(&path_str).await.unwrap().unwrap();
        let bob = IdentityRepository::new(db.clone())
            .find_by_name("bob")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ws.active_identity_id, Some(bob.id));

        let audits = AuditLogRepository::new(db.clone())
            .find_by_action(&AuditAction::WorkspaceEntered)
            .await
            .unwrap();
        assert_eq!(audits.len(), 2);

        // Unknown target fails in verification.
        let err = execute(switch_args(Some("ghost"), true), &config)
            .await
            .expect_err("unknown identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));

        // Previous-identity history is not implemented yet.
        let mut prev = switch_args(None, true);
        prev.previous = true;
        let err = execute(prev, &config)
            .await
            .expect_err("previous must fail");
        assert!(err
            .to_string()
            .contains("Previous identity history not available"));

        // Interactive selection with an empty database reports the hint.
        let empty = TempDir::new().unwrap();
        let err = select_identity_interactive(&config_for(&empty), &ScriptedUi::new())
            .await
            .expect_err("empty selection must fail");
        assert!(err.to_string().contains("No identities found"));
    }

    #[tokio::test]
    async fn switch_authenticated_path_with_master_password() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["carol"]).await;
        ensure_workspace_row(&db, &config).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }

        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let err = execute(switch_args(Some("carol"), true), &config)
            .await
            .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        execute(switch_args(Some("carol"), true), &config)
            .await
            .expect("correct password must switch");

        // An authenticated workspace with a stale active pointer reports no
        // current identity (the unlock state hides it) and still switches.
        {
            let repo = WorkspaceRepository::new(service_db(&config).await);
            let identity = IdentityRepository::new(service_db(&config).await)
                .find_by_name("carol")
                .await
                .unwrap()
                .unwrap();
            let mut ws =
                Workspace::new(config.workspace.path.clone(), "test-workspace".to_string());
            ws.switch_identity(identity.id);
            repo.create(&ws).await.unwrap();
        }
        execute(switch_args(Some("carol"), true), &config)
            .await
            .expect("re-switch on authenticated workspace succeeds");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    async fn service_db(config: &CliConfig) -> Database {
        Database::from_file(config.get_database_path())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn switch_interactive_select_and_confirm_gates() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice", "bob"]).await;
        ensure_workspace_row(&db, &config).await;

        // Interactive selection picks the second entry and the confirmation
        // gate declines → nothing changes.
        let ui = ScriptedUi::new().select(1).confirm(false);
        execute_with(switch_args(None, false), &config, &ui)
            .await
            .expect("declined interactive switch returns success");
        assert!(ui.exhausted());

        let repo = WorkspaceRepository::new(db.clone());
        let path_str = config.workspace.path.to_string_lossy().to_string();
        let ws = repo.find_by_path(&path_str).await.unwrap().unwrap();
        assert!(ws.active_identity_id.is_none(), "cancel must not switch");

        // Same run with the confirmation accepted → active pointer moves.
        let ui = ScriptedUi::new().select(1).confirm(true);
        execute_with(switch_args(None, false), &config, &ui)
            .await
            .expect("confirmed interactive switch succeeds");
        assert!(ui.exhausted());

        let ws = repo.find_by_path(&path_str).await.unwrap().unwrap();
        let bob = IdentityRepository::new(db.clone())
            .find_by_name("bob")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ws.active_identity_id, Some(bob.id));
    }

    #[tokio::test]
    async fn switch_select_from_empty_workspace_fails() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &[]).await;

        let err = select_identity_interactive(&config, &ScriptedUi::new())
            .await
            .expect_err("empty workspace must fail");
        assert!(err.to_string().contains("No identities found"));
    }

    #[tokio::test]
    async fn switch_summary_renders_contact_details_and_tags() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["rich", "plain"]).await;
        ensure_workspace_row(&db, &config).await;

        // Give the identity email/phone/tags so every summary section prints.
        {
            let repo = IdentityRepository::new(db.clone());
            let mut rich = repo
                .find_by_name("rich")
                .await
                .unwrap()
                .expect("rich exists");
            rich.email = Some("rich@example.com".to_string());
            rich.phone = Some("+49123456789".to_string());
            rich.tags = vec!["ops".to_string(), "oncall".to_string()];
            rich.description = Some("the rich one".to_string());
            repo.update(&rich).await.unwrap();
        }

        execute(switch_args(Some("rich"), true), &config)
            .await
            .expect("switch to a fully-populated identity succeeds");

        // Interactive selection of the other identity renders the summary
        // for it afterwards. The menu is name-ordered: "plain" sorts first.
        let ui = ScriptedUi::new().select(0).confirm(true);
        execute_with(switch_args(None, false), &config, &ui)
            .await
            .expect("interactive switch to plain succeeds");
        assert!(ui.exhausted());
    }

    #[tokio::test]
    async fn switch_without_workspace_row_still_succeeds_and_audits() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice"]).await;
        // Deliberately no workspace row: perform_switch must skip the
        // workspace update but still record the audit entry.

        execute(switch_args(Some("alice"), true), &config)
            .await
            .expect("switch without a workspace row succeeds");

        let audits = AuditLogRepository::new(db)
            .find_by_action(&AuditAction::WorkspaceEntered)
            .await
            .unwrap();
        assert_eq!(audits.len(), 1, "switch is audited without a workspace row");
    }

    #[tokio::test]
    async fn switch_ignores_a_stale_active_pointer_without_users() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let db = seeded_db(&dir, &["alice"]).await;
        ensure_workspace_row(&db, &config).await;

        // Point the workspace at an identity that no longer exists; the
        // lookup falls through and reports "no current identity".
        {
            let repo = WorkspaceRepository::new(db.clone());
            let mut ws = Workspace::new(
                config.workspace.path.clone(),
                "test-workspace".to_string(),
            );
            ws.switch_identity(uuid::Uuid::new_v4());
            repo.create(&ws).await.unwrap();
        }
        assert_eq!(get_current_identity(&config).await.unwrap(), None);

        execute(switch_args(Some("alice"), true), &config)
            .await
            .expect("switch with a stale pointer succeeds");
    }

    #[tokio::test]
    async fn switch_selection_menu_rejects_out_of_range_choice() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice", "bob"]).await;

        let ui = ScriptedUi::new().select(99);
        let err = select_identity_interactive(&config, &ui)
            .await
            .expect_err("out-of-range selection must fail");
        assert!(err.to_string().contains("out of range"));
        assert!(ui.exhausted());
    }
}
