use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
use crate::utils::{create_directory, validate_workspace_path};
use persona_core::{Database, PersonaService, Repository};

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

fn initialize_config(
    workspace_path: &Path,
    encryption_enabled: bool,
    backup_dir: Option<PathBuf>,
) -> Result<()> {
    let config_path = workspace_path.join("config.toml");
    let mut config = CliConfig::default();
    config.workspace.path = workspace_path.to_path_buf();
    config.security.encryption_enabled = encryption_enabled;
    config.backup.directory = backup_dir.unwrap_or_else(|| workspace_path.join("backups"));

    let config_content =
        toml::to_string_pretty(&config).context("Failed to serialize configuration")?;

    std::fs::write(&config_path, config_content).context("Failed to write configuration file")?;

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
        let mut service = PersonaService::new(db)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create PersonaService: {}", e))?;

        // Initialize first-time user
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
                println!("  You can set up authentication later using 'persona unlock'");
            }
        }
    } else {
        println!(
            "{} Database created, authentication not configured",
            "✓".green().bold()
        );
        println!("  Run 'persona unlock' to set up your master password");
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
        let service = PersonaService::new(db).await.unwrap();
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
        let mut service = PersonaService::new(db).await.unwrap();
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
        let service = PersonaService::new(db).await.unwrap();
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
        let mut service = PersonaService::new(db).await.unwrap();
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
        let service = PersonaService::new(db).await.unwrap();
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
        let mut service = PersonaService::new(db).await.unwrap();
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
                .contains("failed to create directory"),
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
}
