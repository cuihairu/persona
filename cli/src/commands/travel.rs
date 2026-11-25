//! `persona travel …`: travel mode (move every marked identity off this device in
//! one bundle, or restore it as it was).
//!
//! The semantics and the gates all live in core (see `persona_core::travel`);
//! this module only orchestrates: the status display and mark/unmark do not
//! need to decrypt the master key (status has no gate, mark goes through the
//! unlock fork in switch.rs), while enter/exit need a full unlock
//! (`init_service`, which also brings up attachment storage). The travel
//! passphrase is independent of the master passphrase, and its three-level
//! resolution mirrors backup.rs: `--passphrase-env` →
//! `PERSONA_PAYLOAD_PASSPHRASE` → prompt.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::models::{AuditAction, AuditLog, ResourceType};
use persona_core::storage::{AuditLogRepository, IdentityRepository, Repository};
use persona_core::Database;
use persona_core::PersonaService;

#[derive(Args)]
pub struct TravelArgs {
    #[command(subcommand)]
    command: TravelCommand,
}

#[derive(Subcommand)]
enum TravelCommand {
    /// Show travel mode status (flag/sidecar/consistency) and marked identities
    Status,
    /// Mark an identity to leave this device when entering travel mode
    Mark {
        /// Identity name
        name: String,
    },
    /// Unmark an identity (it stays on this device)
    Unmark {
        /// Identity name
        name: String,
    },
    /// Enter travel mode: pack marked identities into the encrypted sidecar and remove them from the vault
    Enter {
        /// Read the travel passphrase from this env var (must be set and non-empty)
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Skip the confirmation prompt (dangerous: marked identities are removed from this device immediately)
        #[arg(short, long)]
        yes: bool,
    },
    /// Exit travel mode: enter the travel passphrase to restore the packed identities into the vault
    Exit {
        /// Read the travel passphrase from this env var
        #[arg(long)]
        passphrase_env: Option<String>,
    },
}

pub async fn execute(args: TravelArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: TravelArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        TravelCommand::Status => show_status(config).await,
        TravelCommand::Mark { name } => set_marked(config, ui, &name, true).await,
        TravelCommand::Unmark { name } => set_marked(config, ui, &name, false).await,
        TravelCommand::Enter {
            passphrase_env,
            yes,
        } => enter(config, ui, passphrase_env.as_deref(), yes).await,
        TravelCommand::Exit { passphrase_env } => exit(config, ui, passphrase_env.as_deref()).await,
    }
}

/// Open the database + migrate + build an unlocked service (status only reads the flag, so no master passphrase is needed).
async fn open_service(config: &CliConfig) -> Result<(Database, PersonaService)> {
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
    Ok((db, service))
}

/// List the marked identities. sqlx is only a dev-dependency of the cli (production
/// code goes through the repository layer), so open one read-only connection here
/// and list all identities before filtering.
async fn marked_names(config: &CliConfig) -> Result<Vec<String>> {
    let db = Database::from_file(config.get_database_path())
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    let mut names: Vec<String> = IdentityRepository::new(db)
        .find_all()
        .await
        .map_err(|e| anyhow!("Failed to list identities: {}", e))?
        .into_iter()
        .filter(|identity| identity.travel_marked)
        .map(|identity| identity.name)
        .collect();
    names.sort();
    Ok(names)
}

async fn show_status(config: &CliConfig) -> Result<()> {
    let db_path = config.get_database_path();
    let (_db, service) = open_service(config).await?;
    let status = service
        .travel_status(&db_path)
        .await
        .into_anyhow()
        .context("failed to read travel status")?;

    println!("{}", "✈️  Travel mode".cyan().bold());
    if status.active {
        if status.inconsistent {
            println!(
                "{}",
                "⚠️  INCONSISTENT: travel mode is active but the sidecar file is \
                 missing — the data only lived in that file and is LOST."
                    .red()
                    .bold()
            );
            println!(
                "   expected sidecar: {}",
                persona_core::travel::sidecar_path(&db_path).display()
            );
        } else {
            match &status.entered_at {
                Some(at) => println!("{}", format!("State: ACTIVE (since {at})").green().bold()),
                None => println!("{}", "State: ACTIVE".green().bold()),
            }
            println!(
                "   marked identities are sealed in {}",
                persona_core::travel::sidecar_path(&db_path).display()
            );
        }
    } else {
        println!("State: inactive");
        let sidecar = persona_core::travel::sidecar_path(&db_path);
        if status.sidecar_exists {
            println!(
                "{}",
                format!(
                    "⚠️  Leftover sidecar found at {} — remove it manually or run \
                     `persona travel exit` to restore",
                    sidecar.display()
                )
                .yellow()
            );
        }
    }

    let marked = marked_names(config).await?;
    if marked.is_empty() {
        println!("Marked for travel: (none)");
        println!(
            "{}",
            "Use `persona travel mark <name>` to mark an identity.".bright_black()
        );
    } else {
        println!("Marked for travel: {}", marked.join(", "));
    }
    Ok(())
}

/// mark/unmark: the unlock fork from switch.rs — with a user present, unlock and
/// go through the service (which audits on its own); on an uninitialized
/// database go straight to the repository and add the audit row by hand (the
/// identities column exists but the master-passphrase scheme has not been set up).
async fn set_marked(config: &CliConfig, ui: &dyn PromptUi, name: &str, marked: bool) -> Result<()> {
    let (db, mut service) = open_service(config).await?;

    if service
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
            persona_core::auth::authentication::AuthResult::Success => {}
            other => bail!("Authentication failed: {:?}", other),
        }
        let identity = service
            .get_identity_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to load identity: {}", e))?
            .with_context(|| format!("Identity '{name}' not found"))?;
        service
            .set_travel_marked(&identity.id, marked)
            .await
            .into_anyhow()
            .context("failed to update travel mark")?;
    } else {
        let repo = IdentityRepository::new(db.clone());
        let mut identity = repo
            .find_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to load identity: {}", e))?
            .with_context(|| format!("Identity '{name}' not found"))?;
        identity.travel_marked = marked;
        repo.update(&identity)
            .await
            .map_err(|e| anyhow!("Failed to update identity: {}", e))?;
        let log = AuditLog::new(AuditAction::TravelMarkChanged, ResourceType::Identity, true)
            .with_identity_id(Some(identity.id));
        AuditLogRepository::new(db.clone())
            .create(&log)
            .await
            .map_err(|e| anyhow!("Failed to write audit log: {}", e))?;
        crate::commands::service::emit_audit(&log);
    }

    println!(
        "{}",
        format!(
            "✓ Identity '{name}' {} for travel",
            if marked { "marked" } else { "unmarked" }
        )
        .green()
    );
    Ok(())
}

async fn enter(
    config: &CliConfig,
    ui: &dyn PromptUi,
    passphrase_env: Option<&str>,
    yes: bool,
) -> Result<()> {
    let db_path = config.get_database_path();
    let service = crate::commands::service::init_service(config, ui).await?;

    let marked = marked_names(config).await?;
    if marked.is_empty() {
        bail!("no identities are marked for travel — use `persona travel mark <name>` first");
    }

    // Confirmation first, passphrase second: a cancelled run should not be asked for a passphrase
    if !yes {
        let listing = marked.join(", ");
        if !ui.confirm(
            &format!(
                "Move {len} marked identit{} ({listing}) off this device? \
                 They will only be recoverable with the travel passphrase.",
                if marked.len() == 1 { "y" } else { "ies" },
                len = marked.len(),
            ),
            false,
        )? {
            println!("{}", "Enter travel mode cancelled.".yellow());
            return Ok(());
        }
    }
    let passphrase = resolve_passphrase(passphrase_env, ui, true)?;

    println!("{}", "📦 Packing marked identities...".cyan().bold());
    let counts = service
        .enter_travel_mode(&db_path, &passphrase)
        .await
        .into_anyhow()?;
    println!(
        "{}",
        format!(
            "✅ Travel mode active — {} identit{}, {} credential{}, {} attachment file{}, \
             {} passkey{}, {} wallet{} and {} history rows moved to {}",
            counts.identities,
            if counts.identities == 1 { "y" } else { "ies" },
            counts.credentials,
            if counts.credentials == 1 { "" } else { "s" },
            counts.files,
            if counts.files == 1 { "" } else { "s" },
            counts.passkeys,
            if counts.passkeys == 1 { "" } else { "s" },
            counts.wallets,
            if counts.wallets == 1 { "" } else { "s" },
            counts.history_rows,
            persona_core::travel::sidecar_path(&db_path).display(),
        )
        .green()
    );
    println!(
        "{}",
        "   The travel passphrase is the ONLY way to restore this data — \
         there is no master-password fallback."
            .yellow()
    );
    Ok(())
}

async fn exit(config: &CliConfig, ui: &dyn PromptUi, passphrase_env: Option<&str>) -> Result<()> {
    let db_path = config.get_database_path();
    let service = crate::commands::service::init_service(config, ui).await?;

    if !persona_core::travel::sidecar_path(&db_path).exists() {
        bail!(
            "no travel sidecar at {} — travel mode was never entered here (or the file was removed)",
            persona_core::travel::sidecar_path(&db_path).display()
        );
    }

    // The passphrase itself is the confirmation: type it once
    let passphrase = resolve_passphrase(passphrase_env, ui, false)?;

    println!("{}", "📥 Restoring marked identities...".cyan().bold());
    let counts = service
        .exit_travel_mode(&db_path, &passphrase)
        .await
        .into_anyhow()?;
    println!(
        "{}",
        format!(
            "✅ Travel mode exited — {} identit{}, {} credential{}, {} attachment file{}, \
             {} passkey{}, {} wallet{} and {} history rows restored",
            counts.identities,
            if counts.identities == 1 { "y" } else { "ies" },
            counts.credentials,
            if counts.credentials == 1 { "" } else { "s" },
            counts.files,
            if counts.files == 1 { "" } else { "s" },
            counts.passkeys,
            if counts.passkeys == 1 { "" } else { "s" },
            counts.wallets,
            if counts.wallets == 1 { "" } else { "s" },
            counts.history_rows,
        )
        .green()
    );
    Ok(())
}

/// Three-level travel passphrase resolution (mirrors backup.rs): an explicit env
/// variable → `PERSONA_PAYLOAD_PASSPHRASE` → interactive prompt. enter asks for
/// confirmation (a new passphrase is typed twice, done at the terminal layer);
/// exit does not (the passphrase already exists).
fn resolve_passphrase(env_var: Option<&str>, ui: &dyn PromptUi, confirm: bool) -> Result<String> {
    if let Some(var) = env_var {
        return std::env::var(var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| format!("--passphrase-env {var} is not set (or blank)"));
    }
    if let Ok(value) = std::env::var("PERSONA_PAYLOAD_PASSPHRASE") {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    let confirmation = confirm.then_some(("Confirm passphrase", "Passphrases do not match"));
    ui.password("Enter travel passphrase", false, confirmation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{Identity, IdentityType, Workspace};
    use persona_core::storage::WorkspaceRepository;

    /// Process env is a single slot: any test that sets/removes `PERSONA_*` must
    /// be serialized against the tests that read it (prompt_master_password prefers
    /// env). Take the bridge tests' global lock (same as switch/ssh/backup, with
    /// poisoned-lock recovery to avoid cascades).
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::commands::bridge::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard for environment variables: cleanup is guaranteed even when a
    /// panic unwinds. It used to rely on an explicit remove_var at the end of the
    /// test, so a single panic leaked PERSONA_MASTER_PASSWORD to other tests in
    /// the same process (switch/ssh ScriptedUi queues answered by env instead, and
    /// failed out of alignment).
    struct EnvVar(&'static str);

    impl EnvVar {
        fn set(name: &'static str, value: &str) -> Self {
            std::env::set_var(name, value);
            Self(name)
        }

        /// Make sure the variable does not exist (clearing any residue left in the process); nothing needs restoring on exit.
        fn remove(name: &'static str) -> Self {
            std::env::remove_var(name);
            Self(name)
        }
    }

    impl Drop for EnvVar {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    fn config_for(dir: &tempfile::TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// Build a database with a master user (and one identity), returning
    /// (dir, config).
    ///
    /// The workspace row is added the way the full `persona init` flow does it —
    /// core's travel settings read/write require the first row of workspaces to
    /// exist.
    async fn seeded_workspace() -> (tempfile::TempDir, CliConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        WorkspaceRepository::new(db.clone())
            .create(&Workspace::new(
                dir.path().to_path_buf(),
                "test".to_string(),
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let identity = service
            .create_identity("work".to_string(), IdentityType::Work)
            .await
            .unwrap();
        assert!(!identity.travel_marked);
        (dir, config)
    }

    /// For a present row, look at travel_marked; after enter the row is moved out
    /// of the vault, so None also counts as unmarked (that is exactly the
    /// "marked identities are no longer on this machine" state being asserted).
    async fn identity_marked(config: &CliConfig, name: &str) -> bool {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db.clone());
        repo.find_by_name(name)
            .await
            .unwrap()
            .map(|identity| identity.travel_marked)
            .unwrap_or(false)
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mark_then_unmark_persists_and_audits() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let ui = ScriptedUi::new();
        let args = TravelArgs {
            command: TravelCommand::Mark {
                name: "work".to_string(),
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());
        assert!(identity_marked(&config, "work").await);

        let audits: i64 = {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            sqlx::query_scalar(
                "SELECT COUNT(1) FROM audit_logs WHERE action = 'travel_mark_changed'",
            )
            .fetch_one(db.pool())
            .await
            .unwrap()
        };
        assert_eq!(audits, 1, "mark flip is audited");

        let args = TravelArgs {
            command: TravelCommand::Unmark {
                name: "work".to_string(),
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert!(!identity_marked(&config, "work").await);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mark_unknown_identity_fails() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;
        let args = TravelArgs {
            command: TravelCommand::Mark {
                name: "ghost".to_string(),
            },
        };
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn enter_requires_confirmation_then_moves_data_to_sidecar() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let _pp = EnvVar::remove("PERSONA_PAYLOAD_PASSPHRASE");
        let (_dir, config) = seeded_workspace().await;

        // Mark first
        let args = TravelArgs {
            command: TravelCommand::Mark {
                name: "work".to_string(),
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();

        // enter without a confirmation: refused
        // (work is already marked, so this exercises the cancel path)
        let ui = ScriptedUi::new().confirm(false);
        let args = TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: None,
                yes: false,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(
            ui.exhausted(),
            "cancel must not reach the passphrase prompt"
        );
        assert!(!persona_core::travel::sidecar_path(&config.get_database_path()).exists());

        // Confirmation + passphrase (the retype is done by dialoguer inside
        // TerminalUi; ScriptedUi's password ignores the confirmation argument and
        // consumes a single answer)
        let ui = ScriptedUi::new().confirm(true).password("travel-secret");
        let args = TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: None,
                yes: false,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());

        // Row gone + sidecar written + flag set
        assert!(!identity_marked(&config, "work").await, "row must be gone");
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM identities")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 0, "marked identity removed from the vault");
        let sealed = std::fs::read(persona_core::travel::sidecar_path(
            &config.get_database_path(),
        ))
        .unwrap();
        assert!(persona_core::backup::file_crypto::is_persona_encrypted(
            &sealed
        ));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn exit_wrong_passphrase_keeps_sidecar_then_right_one_restores() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let _tp = EnvVar::set("PERSONA_TRAVEL_TEST_PW", "travel-secret");
        let (_dir, config) = seeded_workspace().await;
        let db_path = config.get_database_path();

        let args = TravelArgs {
            command: TravelCommand::Mark {
                name: "work".to_string(),
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();
        let args = TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: Some("PERSONA_TRAVEL_TEST_PW".to_string()),
                yes: true,
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();

        // Wrong passphrase: the sidecar is kept and the data is still missing
        let ui = ScriptedUi::new().password("wrong");
        let args = TravelArgs {
            command: TravelCommand::Exit {
                passphrase_env: None,
            },
        };
        let err = execute_with(args, &config, &ui).await.unwrap_err();
        assert!(err.to_string().contains("passphrase is wrong"), "{err}");
        assert!(persona_core::travel::sidecar_path(&db_path).exists());

        // Right passphrase: restored + sidecar removed
        let ui = ScriptedUi::new().password("travel-secret");
        let args = TravelArgs {
            command: TravelCommand::Exit {
                passphrase_env: None,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());
        assert!(!persona_core::travel::sidecar_path(&db_path).exists());
        let db = Database::from_file(&db_path).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM identities")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1, "identity restored");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn enter_reports_missing_passphrase_env() {
        let _guard = env_guard();
        let _tp = EnvVar::remove("PERSONA_TRAVEL_TEST_PW");
        // A missing explicitly-named env variable is a configuration error, no silent fallback
        let ui = ScriptedUi::new();
        let err = super::resolve_passphrase(Some("PERSONA_TRAVEL_TEST_PW"), &ui, true).unwrap_err();
        assert!(err.to_string().contains("--passphrase-env"), "{err}");
        assert!(ui.exhausted(), "env path must not touch the prompt");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn enter_without_marked_identities_is_rejected() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let _tp = EnvVar::set("PERSONA_TRAVEL_TEST_PW", "pw");
        let (_dir, config) = seeded_workspace().await;
        let args = TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: Some("PERSONA_TRAVEL_TEST_PW".to_string()),
                yes: true,
            },
        };
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no identities are marked"),
            "{err}"
        );
    }

    /// A vault without the master-passphrase scheme: build the workspace + identity
    /// directly, skipping `initialize_user` → `has_users()` is false, so mark goes
    /// through the repository-direct fork.
    async fn seeded_workspace_without_users() -> (tempfile::TempDir, CliConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        WorkspaceRepository::new(db.clone())
            .create(&Workspace::new(
                dir.path().to_path_buf(),
                "test".to_string(),
            ))
            .await
            .unwrap();
        IdentityRepository::new(db.clone())
            .create(&Identity::new("anon".to_owned(), IdentityType::Personal))
            .await
            .unwrap();
        db.close().await;
        (dir, config)
    }

    fn status_args() -> TravelArgs {
        TravelArgs {
            command: TravelCommand::Status,
        }
    }

    fn mark_args(name: &str) -> TravelArgs {
        TravelArgs {
            command: TravelCommand::Mark {
                name: name.to_string(),
            },
        }
    }

    /// enter with an env passphrase + confirmation skipped (the test must have set `PERSONA_TRAVEL_TEST_PW`).
    fn enter_args() -> TravelArgs {
        TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: Some("PERSONA_TRAVEL_TEST_PW".to_string()),
                yes: true,
            },
        }
    }

    /// mark must still work when the master-passphrase scheme has not been set up
    /// (you may want to mark before first use), and it must add the audit row — this
    /// is the manual path in set_marked that parallels the service fork.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mark_on_an_uninitialized_vault_updates_the_row_and_audits() {
        let _guard = env_guard();
        // PERSONA_MASTER_PASSWORD is not set: if the implementation wrongly takes the
        // unlock fork, the ScriptedUi with no env and no prompt queue panics outright
        // (surfacing the wrong fork before any assertion).
        let (_dir, config) = seeded_workspace_without_users().await;

        execute_with(mark_args("anon"), &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert!(identity_marked(&config, "anon").await);

        let audit_count = || async {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(1) FROM audit_logs WHERE action = 'travel_mark_changed'",
            )
            .fetch_one(db.pool())
            .await
            .unwrap();
            db.close().await;
            count
        };
        assert_eq!(audit_count().await, 1, "repo 分叉也要补审计");

        let args = TravelArgs {
            command: TravelCommand::Unmark {
                name: "anon".to_string(),
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert!(!identity_marked(&config, "anon").await);
        assert_eq!(audit_count().await, 2, "mark 与 unmark 各补一条审计");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mark_with_a_wrong_master_password_is_rejected() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "not-the-pin");
        let (_dir, config) = seeded_workspace().await;
        let err = execute_with(mark_args("work"), &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Authentication failed"), "{err}");
        assert!(
            !identity_marked(&config, "work").await,
            "认证失败不得改旗标"
        );
    }

    /// Walk the four world states of status (inactive / leftover sidecar /
    /// ACTIVE / flag set but the container gone) and render each; the branch
    /// conditions are pinned down with core's travel_status, and stdout is not
    /// asserted on (unit tests cannot capture it; the behavior is backed by the
    /// state assertions).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn status_walks_inactive_leftover_active_and_inconsistent_states() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let _tp = EnvVar::set("PERSONA_TRAVEL_TEST_PW", "travel-secret");
        let (_dir, config) = seeded_workspace().await;
        let db_path = config.get_database_path();
        let sidecar = persona_core::travel::sidecar_path(&db_path);

        async fn flags(config: &CliConfig) -> persona_core::travel::TravelStatus {
            // PersonaService does not implement Debug: panic by hand with the error when init_service fails
            let service =
                match crate::commands::service::init_service(config, &ScriptedUi::new()).await {
                    Ok(service) => service,
                    Err(err) => panic!("init_service failed: {err}"),
                };
            service
                .travel_status(&config.get_database_path())
                .await
                .into_anyhow()
                .unwrap()
        }

        // (1) inactive, no sidecar, nothing marked
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert!(!flags(&config).await.active);

        // (2) inactive but a leftover sidecar (hand-made): the warning branch
        std::fs::write(&sidecar, b"leftover").unwrap();
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        let status = flags(&config).await;
        assert!(!status.active && status.sidecar_exists);

        // (3) mark two identities (marked_names must print them sorted)
        let service =
            match crate::commands::service::init_service(&config, &ScriptedUi::new()).await {
                Ok(service) => service,
                Err(err) => panic!("init_service failed: {err}"),
            };
        service
            .create_identity("alpha".to_string(), IdentityType::Work)
            .await
            .unwrap();
        execute_with(mark_args("work"), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(mark_args("alpha"), &config, &ScriptedUi::new())
            .await
            .unwrap();
        // status while marked (the listing has content, and both wording branches for travelling are reached)
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert_eq!(
            marked_names(&config).await.unwrap(),
            vec!["alpha".to_string(), "work".to_string()],
            "标记清单必须排序"
        );

        // (4) a leftover sidecar in the way: enter must refuse — it is the container of the previous bundle, and overwriting it would lose data
        let err = execute_with(enter_args(), &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("travel sidecar already exists"),
            "unexpected: {err}"
        );

        // (5) clear the leftover -> enter -> ACTIVE
        std::fs::remove_file(&sidecar).unwrap();
        execute_with(enter_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        let status = flags(&config).await;
        assert!(status.active && !status.inconsistent);
        assert!(status.entered_at.is_some(), "enter 要记录进入时刻");
        assert!(
            marked_names(&config).await.unwrap().is_empty(),
            "行已随包移走"
        );

        // (6) hand-deleted sidecar: the flag is still set but the container is
        // gone -> inconsistent (the data is lost and must be reported honestly
        // rather than pretending it is recoverable)
        std::fs::remove_file(&sidecar).unwrap();
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        let status = flags(&config).await;
        assert!(status.active && status.inconsistent);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn exit_without_a_sidecar_names_where_it_should_be() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;
        let args = TravelArgs {
            command: TravelCommand::Exit {
                passphrase_env: Some("PERSONA_TRAVEL_TEST_PW".to_string()),
            },
        };
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no travel sidecar"), "{err}");
    }

    /// A hit on `PERSONA_PAYLOAD_PASSPHRASE` returns immediately without touching the prompt; blank counts as unset.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn travel_passphrase_falls_back_to_payload_env() {
        let _guard = env_guard();
        let _pp = EnvVar::set("PERSONA_PAYLOAD_PASSPHRASE", "payload-pw");
        let ui = ScriptedUi::new();
        assert_eq!(resolve_passphrase(None, &ui, false).unwrap(), "payload-pw");
        assert!(ui.exhausted(), "payload env 命中就别碰提示");

        let _blank = EnvVar::set("PERSONA_PAYLOAD_PASSPHRASE", "   ");
        let ui = ScriptedUi::new().password("typed-after-blank");
        assert_eq!(
            resolve_passphrase(None, &ui, false).unwrap(),
            "typed-after-blank"
        );
        assert!(ui.exhausted());
    }
}
