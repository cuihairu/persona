use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
use crate::utils::{create_directory, validate_workspace_path};
use persona_core::{Database, Repository};

#[derive(Args)]
pub struct InitArgs {
    /// Workspace directory path
    #[arg(short, long)]
    path: Option<PathBuf>,

    /// Skip interactive prompts and use defaults
    #[arg(short, long)]
    yes: bool,

    /// Initialize with encryption enabled
    #[arg(short, long)]
    encrypted: bool,

    /// Set master password (use with caution)
    #[arg(long)]
    master_password: Option<String>,

    /// Backup directory path
    #[arg(long)]
    backup_dir: Option<PathBuf>,
}

pub async fn execute(args: InitArgs, _config: &CliConfig) -> Result<()> {
    execute_with(args, _config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: InitArgs,
    _config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!("{}", "🚀 Initializing Persona workspace...".cyan().bold());
    println!();

    // Determine workspace path
    let workspace_path = determine_workspace_path(args.path, args.yes, ui)?;

    // Validate workspace path
    validate_workspace_path(&workspace_path)?;

    // Create workspace directory
    create_directory(&workspace_path).context("Failed to create workspace directory")?;

    println!(
        "{} Workspace directory: {}",
        "✓".green().bold(),
        workspace_path.display().to_string().yellow()
    );

    // Initialize encryption if requested
    let encryption_enabled = if args.yes {
        args.encrypted
    } else {
        ui.confirm("Enable encryption for identity data?", true)?
    };

    let master_password = if encryption_enabled {
        get_master_password(args.master_password, args.yes, ui)?
    } else {
        None
    };

    // Create workspace structure
    create_workspace_structure(&workspace_path)?;

    // Initialize configuration
    initialize_config(&workspace_path, encryption_enabled, args.backup_dir)?;

    // Initialize database
    initialize_database(&workspace_path, master_password.as_deref()).await?;

    println!();
    println!(
        "{}",
        "🎉 Persona workspace initialized successfully!"
            .green()
            .bold()
    );
    println!();
    println!("{}", "Next steps:".yellow().bold());
    println!("  1. Create your first identity: {}", "persona add".cyan());
    println!("  2. List all identities: {}", "persona list".cyan());
    println!(
        "  3. Switch between identities: {}",
        "persona switch <name>".cyan()
    );
    println!();
    println!("{}", "For more help, run: persona --help".dimmed());

    Ok(())
}

fn determine_workspace_path(
    path: Option<PathBuf>,
    yes: bool,
    ui: &dyn PromptUi,
) -> Result<PathBuf> {
    if let Some(path) = path {
        return Ok(path);
    }

    // PERSONA_WORKSPACE_PATH shares the same env override source as config::load
    // (--path wins when explicit): `-y` no longer bypasses the env and falls
    // straight to the home default, otherwise init writes to one place and
    // subsequent commands read another via the env
    if let Some(env_path) = crate::config::workspace_path_from_env() {
        return Ok(env_path);
    }

    if yes {
        // Use default path in non-interactive mode
        let default_path = dirs::home_dir()
            .context("Failed to get home directory")?
            .join(".persona");
        return Ok(default_path);
    }

    // Interactive mode
    let default_path = dirs::home_dir()
        .context("Failed to get home directory")?
        .join(".persona");

    let path_str = ui.input_with_default("Workspace directory", &default_path.to_string_lossy())?;

    Ok(PathBuf::from(path_str))
}

fn get_master_password(
    provided_password: Option<String>,
    yes: bool,
    ui: &dyn PromptUi,
) -> Result<Option<String>> {
    if let Some(password) = provided_password {
        warn!("Using master password from command line is not recommended for security reasons");
        return Ok(Some(password));
    }

    if yes {
        // Generate a random password in non-interactive mode
        let password = generate_random_password();
        println!(
            "{} Generated master password: {}",
            "⚠️".yellow(),
            password.bright_yellow().bold()
        );
        println!("{}", "Please save this password securely!".red().bold());
        return Ok(Some(password));
    }

    // Interactive mode
    let password = ui.password(
        "Enter master password",
        false,
        Some(("Confirm master password", "Passwords don't match")),
    )?;

    Ok(Some(password))
}

fn generate_random_password() -> String {
    use rand::RngExt;
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::rng();

    (0..16)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn create_workspace_structure(workspace_path: &Path) -> Result<()> {
    let directories = ["identities", "backups", "exports", "temp", "logs"];

    for dir in &directories {
        let dir_path = workspace_path.join(dir);
        create_directory(&dir_path)
            .with_context(|| format!("Failed to create directory: {}", dir))?;
    }

    println!("{} Created workspace structure", "✓".green().bold());
    Ok(())
}

/// Write the workspace config. **An existing config is never wholesale reset to
/// defaults** (merge semantics): re-running `persona init` may only touch fields
/// this run explicitly owns (workspace.path; the encryption flag only moves up,
/// never down; the backup directory only when --backup-dir was given), and every
/// other user-customized value is preserved as-is. Before overwriting, a
/// `config.toml.bak` is written; the real write goes through a temp file +
/// rename for an atomic replacement. When the existing file fails to parse, the
/// original is left untouched (preserving the scene for the user to inspect —
/// never paper over it with defaults).
fn initialize_config(
    workspace_path: &Path,
    encryption_enabled: bool,
    backup_dir: Option<PathBuf>,
) -> Result<()> {
    let config_path = workspace_path.join("config.toml");
    let config = if config_path.exists() {
        let existing = std::fs::read_to_string(&config_path).with_context(|| {
            format!("Failed to read existing config: {}", config_path.display())
        })?;
        let parsed: CliConfig = match toml::from_str(&existing) {
            Ok(parsed) => parsed,
            Err(e) => {
                // On a parse failure, do not overwrite or back up then rewrite: keep it as-is and let the user fix it.
                warn!(
                    "Existing config.toml is invalid ({}); leaving it untouched",
                    e
                );
                println!(
                    "{} Existing config.toml is invalid and was left untouched: {}",
                    "⚠".yellow(),
                    e
                );
                return Ok(());
            }
        };
        // Keep the user's current values, syncing only the fields this init run explicitly owns
        let mut merged = parsed;
        merged.workspace.path = workspace_path.to_path_buf();
        // The encryption flag only moves up, never down: --encrypted raises it to
        // true; without that flag an encrypted config is not downgraded to
        // unencrypted (the vault's real encryption state lives in the DB, the config
        // is only the display layer, but it must not lie either)
        if encryption_enabled {
            merged.security.encryption_enabled = true;
        }
        if let Some(dir) = backup_dir {
            merged.backup.directory = dir;
        }
        let backup_path = workspace_path.join("config.toml.bak");
        std::fs::write(&backup_path, existing)
            .with_context(|| format!("Failed to back up config to {}", backup_path.display()))?;
        merged
    } else {
        let mut config = CliConfig::default();
        config.workspace.path = workspace_path.to_path_buf();
        config.security.encryption_enabled = encryption_enabled;
        config.backup.directory = backup_dir.unwrap_or_else(|| workspace_path.join("backups"));
        config
    };

    let config_content =
        toml::to_string_pretty(&config).context("Failed to serialize configuration")?;

    // Atomic replacement: write the temp file first, then rename, to avoid a truncated config file
    let tmp_path = workspace_path.join("config.toml.tmp");
    std::fs::write(&tmp_path, &config_content)
        .with_context(|| format!("Failed to write temporary config: {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &config_path)
        .with_context(|| format!("Failed to replace config: {}", config_path.display()))?;

    println!("{} Created configuration file", "✓".green().bold());
    Ok(())
}

async fn initialize_database(workspace_path: &Path, master_password: Option<&str>) -> Result<()> {
    let db_path = workspace_path.join("identities.db");

    // Initialize SQLite database with proper schema using persona-core
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open workspace DB: {}", e))?;

    // Run migrations to set up the schema
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run database migrations: {}", e))?;

    // Ensure a workspace row exists (supports legacy and v2 schemas)
    {
        use persona_core::models::Workspace;
        use persona_core::storage::WorkspaceRepository;
        let repo = WorkspaceRepository::new(db.clone());
        // Use path string to lookup or create
        let path_str = workspace_path.to_string_lossy().to_string();
        let name = workspace_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("default")
            .to_string();
        if repo
            .find_by_path(&path_str)
            .await
            .map_err(|e| anyhow::anyhow!("Workspace lookup failed: {}", e))?
            .is_none()
        {
            let ws = Workspace::new(workspace_path, name);
            // Persist; repo will choose proper schema (legacy/v2)
            let _ = repo
                .create(&ws)
                .await
                .map_err(|e| anyhow::anyhow!("Workspace creation failed: {}", e))?;
        }
    }

    // If master password is provided, initialize the service
    if let Some(password) = master_password {
        let mut service = crate::commands::service::new_service(db)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create PersonaService: {}", e))?;

        // Red line: on a vault that already has users, **never** insert a second
        // user_auth row — a new salt desynchronizes the master key hierarchy and the
        // old passphrase can no longer decrypt stored credentials (passphrase changes
        // go through `persona passwd`). The user-existence query is fail-closed too
        // (error out rather than "treat as an empty vault"); otherwise multi-process
        // concurrency or a database-lock timeout would be mistaken for a first boot
        // and a ghost row would get written.
        let has_users = service
            .has_users()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to check vault users: {}", e))?;
        if has_users {
            println!(
                "{} Vault already has a user; master password left unchanged (use `persona passwd` to rotate)",
                "⚠".yellow().bold()
            );
        } else {
            match service.initialize_user(password).await {
                Ok(_user_id) => {
                    println!("{} Initialized user authentication", "✓".green().bold());
                }
                Err(e) => {
                    warn!("Failed to initialize user: {}", e);
                    println!(
                        "{} Database created, but user initialization failed",
                        "⚠".yellow().bold()
                    );
                    println!(
                        "  Set up authentication later with `persona init --master-password <pw>` (first-run only; existing users are never re-initialized)"
                    );
                }
            }
        }
    } else {
        println!(
            "{} Database created, authentication not configured",
            "✓".green().bold()
        );
        println!(
            "  Set the master password on first use: `persona add` will prompt for it (set PERSONA_MASTER_PASSWORD for automation)"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations (HOME) against the bridge and service tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        fn lock_or_recover(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
            lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }
        (
            lock_or_recover(&crate::commands::bridge::tests::ENV_LOCK),
            lock_or_recover(&ENV_LOCK),
        )
    }

    fn init_args(yes: bool) -> InitArgs {
        InitArgs {
            // None: interactive mode asks for the workspace directory.
            path: None,
            yes,
            encrypted: true,
            master_password: None,
            backup_dir: None,
        }
    }

    /// Explicit `--path` > `PERSONA_WORKSPACE_PATH` > home default; a blank env
    /// value counts as unset (otherwise it would fall through to an empty PathBuf
    /// = the current directory).
    #[test]
    fn workspace_path_env_overrides_yes_default_but_not_explicit_path() {
        let (_bridge_guard, _guard) = lock_process_env();
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("env-ws");

        let previous = std::env::var("PERSONA_WORKSPACE_PATH").ok();
        let restore = |prev: Option<String>| match prev {
            Some(v) => std::env::set_var("PERSONA_WORKSPACE_PATH", v),
            None => std::env::remove_var("PERSONA_WORKSPACE_PATH"),
        };

        std::env::set_var("PERSONA_WORKSPACE_PATH", &env_path);
        // -y with an empty ui queue: if the implementation wrongly goes interactive/prompt, ScriptedUi panics outright
        let got = determine_workspace_path(None, true, &ScriptedUi::new()).unwrap();
        assert_eq!(got, env_path, "env must override the -y home default");

        let explicit = dir.path().join("explicit-ws");
        let got =
            determine_workspace_path(Some(explicit.clone()), true, &ScriptedUi::new()).unwrap();
        assert_eq!(got, explicit, "--path wins over env");

        std::env::set_var("PERSONA_WORKSPACE_PATH", "   ");
        let got = determine_workspace_path(None, true, &ScriptedUi::new()).unwrap();
        assert!(
            got.is_absolute(),
            "blank env must fall back to the home default, got {got:?}"
        );

        restore(previous);
    }

    /// The workspace directory must pre-exist `create_directory`'s parent
    /// handling; point args at a fresh subdir of the temp dir.
    fn fresh_subdir(dir: &TempDir) -> PathBuf {
        dir.path().join("ws")
    }

    #[tokio::test]
    async fn yes_flag_initializes_workspace_with_generated_password() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);

        let mut args = init_args(true);
        args.path = Some(path.clone());
        execute(args, &crate::config::CliConfig::default())
            .await
            .expect("non-interactive init must succeed");

        for sub in ["identities", "backups", "exports", "temp", "logs"] {
            assert!(path.join(sub).is_dir(), "{} created", sub);
        }
        assert!(path.join("config.toml").is_file());
        assert!(path.join("identities.db").is_file());

        // A random master password was generated and printed; the DB has a
        // user (authentication configured).
        let db = Database::from_file(path.join("identities.db"))
            .await
            .unwrap();
        let service = crate::commands::service::new_service(db).await.unwrap();
        assert!(
            service.has_users().await.unwrap(),
            "yes mode seeds a master user"
        );
    }

    #[tokio::test]
    async fn interactive_init_accepts_scripted_answers() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);

        let ui = ScriptedUi::new()
            .input(path.to_string_lossy().as_ref())
            .confirm(true) // enable encryption
            .password("master-pin"); // confirmed master password
        execute_with(init_args(false), &crate::config::CliConfig::default(), &ui)
            .await
            .expect("interactive init must succeed");
        assert!(ui.exhausted());

        let db = Database::from_file(path.join("identities.db"))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        assert!(service.has_users().await.unwrap());
        let authed = service.authenticate_user("master-pin").await.unwrap();
        assert!(matches!(authed, persona_core::auth::AuthResult::Success));
    }

    #[tokio::test]
    async fn interactive_init_without_encryption_skips_password() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);

        let ui = ScriptedUi::new()
            .input(path.to_string_lossy().as_ref())
            .confirm(false); // decline encryption
        execute_with(init_args(false), &crate::config::CliConfig::default(), &ui)
            .await
            .expect("declined-encryption init must succeed");
        assert!(ui.exhausted());

        let db = Database::from_file(path.join("identities.db"))
            .await
            .unwrap();
        let service = crate::commands::service::new_service(db).await.unwrap();
        assert!(!service.has_users().await.unwrap());
    }

    #[tokio::test]
    async fn cli_provided_master_password_beats_prompting() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);

        let mut args = init_args(false);
        args.master_password = Some("from-cli".to_string());
        let ui = ScriptedUi::new()
            .input(path.to_string_lossy().as_ref())
            .confirm(true); // encryption accepted, password comes from CLI
        execute_with(args, &crate::config::CliConfig::default(), &ui)
            .await
            .expect("init with CLI password must succeed");
        assert!(ui.exhausted(), "no password prompt was consumed");

        let db = Database::from_file(path.join("identities.db"))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        assert!(matches!(
            service.authenticate_user("from-cli").await.unwrap(),
            persona_core::auth::AuthResult::Success
        ));
    }

    #[tokio::test]
    async fn backup_dir_option_lands_in_written_config() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);
        let backup_dir = dir.path().join("custom-backups");

        let mut args = init_args(true);
        args.path = Some(path.clone());
        args.backup_dir = Some(backup_dir.clone());
        execute(args, &crate::config::CliConfig::default())
            .await
            .expect("init with explicit backup dir must succeed");

        let written = std::fs::read_to_string(path.join("config.toml")).unwrap();
        assert!(
            written.contains(&backup_dir.to_string_lossy().to_string()),
            "config must reference the custom backup dir:\n{}",
            written
        );
    }

    #[tokio::test]
    async fn non_interactive_init_without_encryption_skips_authentication() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);

        let mut args = init_args(true);
        args.encrypted = false;
        args.path = Some(path.clone());
        execute(args, &crate::config::CliConfig::default())
            .await
            .expect("unencrypted init must succeed");

        let db = Database::from_file(path.join("identities.db"))
            .await
            .unwrap();
        let service = crate::commands::service::new_service(db).await.unwrap();
        assert!(
            !service.has_users().await.unwrap(),
            "no user is created without encryption"
        );
    }

    #[tokio::test]
    async fn reinitializing_an_initialized_database_warns_but_succeeds() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);

        let mut first = init_args(true);
        first.path = Some(path.clone());
        first.master_password = Some("first-pin".to_string());
        execute(first, &crate::config::CliConfig::default())
            .await
            .expect("first init succeeds");

        // Second init over the same directory: the user already exists, so
        // authentication setup fails and the warning branch runs instead.
        let mut second = init_args(true);
        second.path = Some(path.clone());
        second.master_password = Some("second-pin".to_string());
        execute(second, &crate::config::CliConfig::default())
            .await
            .expect("re-init still completes");

        // The original credentials keep working.
        let db = Database::from_file(path.join("identities.db"))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        assert!(matches!(
            service.authenticate_user("first-pin").await.unwrap(),
            persona_core::auth::AuthResult::Success
        ));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn unwritable_workspace_directory_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();

        let mut args = init_args(true);
        args.path = Some(path.clone());
        let err = execute(args, &crate::config::CliConfig::default())
            .await
            .expect_err("read-only workspace must fail");
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("workspace directory is not writable"),
            "unexpected error: {err}"
        );

        // Restore permissions so TempDir cleanup can delete the tree.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn yes_flag_falls_back_to_the_home_directory_without_a_path() {
        let _guard = lock_process_env();
        let dir = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();

        // `dirs::home_dir()` reads $HOME on Linux, so a redirected home moves
        // the default workspace path with it. On Windows, dirs uses
        // SHGetFolderPath which reads from the registry, so env var
        // overrides don't work — skip the test there.
        std::env::set_var("HOME", dir.path());
        let path = determine_workspace_path(None, true, &ScriptedUi::new())
            .expect("non-interactive default path");
        assert_eq!(path, dir.path().join(".persona"));

        match original_home {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn master_password_prompt_errors_propagate() {
        let inner = ScriptedUi::new();
        let ui = FailOn::new(&inner, PromptKind::Password);
        let err = get_master_password(None, false, &ui)
            .expect_err("a failing password prompt must abort");
        assert!(err.to_string().contains("failing ui: password prompt"));

        // An explicit --password short-circuits the prompt entirely.
        let inner = ScriptedUi::new();
        let ui = FailOn::new(&inner, PromptKind::Password);
        assert_eq!(
            get_master_password(Some("from-cli".to_string()), false, &ui).unwrap(),
            Some("from-cli".to_string())
        );
    }

    /// Number of user_auth rows (ghost-user detection: re-running init must never insert a second row).
    async fn user_auth_row_count(path: &Path) -> i64 {
        let db = Database::from_file(path.join("identities.db"))
            .await
            .unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(1) FROM user_auth")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    /// Regression (data-loss grade): re-running `persona init` must merge the
    /// existing config, user-customized values must not be overwritten by defaults,
    /// and a `config.toml.bak` must be left before overwriting.
    #[tokio::test]
    async fn reinitializing_preserves_custom_config_and_backs_up() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);

        let mut first = init_args(true);
        first.path = Some(path.clone());
        execute(first, &crate::config::CliConfig::default())
            .await
            .expect("first init must succeed");

        // The user changed three non-default values (including the security section of an unencrypted first boot)
        let config_path = path.join("config.toml");
        let original = std::fs::read_to_string(&config_path).unwrap();
        let customized = original
            .replace("auto_lock_timeout = 300", "auto_lock_timeout = 7777")
            .replace("max_backups = 30", "max_backups = 99")
            .replace("level = \"info\"", "level = \"debug\"");
        assert_ne!(
            customized, original,
            "test fixture must have changed the values"
        );
        std::fs::write(&config_path, &customized).unwrap();

        // Re-run init without --encrypted: the encryption flag must not be moved off the user's value
        let mut second = init_args(true);
        second.path = Some(path.clone());
        second.encrypted = false;
        execute(second, &crate::config::CliConfig::default())
            .await
            .expect("re-init must not fail on an existing workspace");

        let written = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            written.contains("auto_lock_timeout = 7777"),
            "custom auto_lock_timeout must survive re-init:\n{written}"
        );
        assert!(
            written.contains("max_backups = 99"),
            "custom max_backups must survive re-init:\n{written}"
        );
        assert!(
            written.contains("level = \"debug\""),
            "custom logging level must survive re-init:\n{written}"
        );
        assert!(
            path.join("config.toml.bak").exists(),
            "an existing config must be backed up before being rewritten"
        );
        assert_eq!(
            std::fs::read_to_string(path.join("config.toml.bak")).unwrap(),
            customized,
            "the backup must hold the pre-init content"
        );
        assert!(
            !path.join("config.toml.tmp").exists(),
            "the atomic write must leave no temp file behind"
        );
    }

    /// Regression (data-loss grade): re-running `persona init --master-password` on
    /// a vault that already has users must not insert a second user_auth row (a new
    /// salt would make the old passphrase unable to decrypt stored credentials);
    /// saved credentials and decryptability must remain intact.
    #[tokio::test]
    async fn reinitializing_an_initialized_vault_never_adds_a_second_user() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);

        let mut first = init_args(true);
        first.path = Some(path.clone());
        first.master_password = Some("first-pin".to_string());
        execute(first, &crate::config::CliConfig::default())
            .await
            .expect("first init must succeed");
        assert_eq!(
            user_auth_row_count(&path).await,
            1,
            "one user after first init"
        );

        // The saved passphrase: create an identity + credential
        let db = Database::from_file(path.join("identities.db"))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db.clone())
            .await
            .unwrap();
        assert!(matches!(
            service.authenticate_user("first-pin").await.unwrap(),
            persona_core::auth::AuthResult::Success
        ));
        let identity = service
            .create_identity(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            )
            .await
            .unwrap();
        let created = service
            .create_credential(
                identity.id,
                "GitHub".to_string(),
                persona_core::models::CredentialType::Password,
                persona_core::models::SecurityLevel::High,
                &persona_core::models::CredentialData::Password(
                    persona_core::models::PasswordCredentialData {
                        password: "ghp-real-secret-value".to_string(),
                        email: Some("alice@example.com".to_string()),
                        security_questions: Vec::new(),
                    },
                ),
            )
            .await
            .unwrap();

        // Re-run init with a different master passphrase: must not create a new user or destroy stored credentials
        let mut second = init_args(true);
        second.path = Some(path.clone());
        second.master_password = Some("second-pin".to_string());
        execute(second, &crate::config::CliConfig::default())
            .await
            .expect("re-init must not fail on an existing vault");

        assert_eq!(
            user_auth_row_count(&path).await,
            1,
            "re-init must not insert a phantom second user row"
        );
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        assert!(
            matches!(
                service.authenticate_user("first-pin").await.unwrap(),
                persona_core::auth::AuthResult::Success
            ),
            "the original master password must still unlock"
        );
        assert!(
            !matches!(
                service.authenticate_user("second-pin").await.unwrap(),
                persona_core::auth::AuthResult::Success
            ),
            "the re-init password must not be accepted as a second vault owner"
        );
        let credential = service
            .get_credential(&created.id)
            .await
            .unwrap()
            .expect("the saved credential must still exist");
        let data = service
            .get_credential_data(&credential.id)
            .await
            .unwrap()
            .expect("the saved credential must still decrypt");
        let persona_core::models::CredentialData::Password(password_data) = data else {
            panic!("credential data must round trip as password data");
        };
        assert_eq!(
            password_data.password.as_str(),
            "ghp-real-secret-value",
            "the saved password must be intact after re-init"
        );
    }

    /// Regression (data-loss grade): when an existing config is corrupt, never overwrite it with defaults — preserve the scene.
    #[tokio::test]
    async fn reinitializing_with_an_invalid_config_leaves_it_untouched() {
        let dir = TempDir::new().unwrap();
        let path = fresh_subdir(&dir);
        std::fs::create_dir_all(&path).unwrap();
        let config_path = path.join("config.toml");
        let broken = "not [valid toml";
        std::fs::write(&config_path, broken).unwrap();

        let mut args = init_args(true);
        args.path = Some(path.clone());
        execute(args, &crate::config::CliConfig::default())
            .await
            .expect("re-init must not fail on an invalid existing config");

        assert_eq!(
            std::fs::read_to_string(&config_path).unwrap(),
            broken,
            "an unparseable config must be left untouched, never overwritten with defaults"
        );
    }
}
