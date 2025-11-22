use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, Input, Password};
use std::path::PathBuf;
use tracing::warn;

use crate::config::CliConfig;
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
    println!("{}", "🚀 Initializing Persona workspace...".cyan().bold());
    println!();

    // Determine workspace path
    let workspace_path = determine_workspace_path(args.path, args.yes)?;

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
        Confirm::new()
            .with_prompt("Enable encryption for identity data?")
            .default(true)
            .interact()?
    };

    let master_password = if encryption_enabled {
        get_master_password(args.master_password, args.yes)?
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

fn determine_workspace_path(path: Option<PathBuf>, yes: bool) -> Result<PathBuf> {
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

    let path_str: String = Input::new()
        .with_prompt("Workspace directory")
        .default(default_path.to_string_lossy().to_string())
        .interact_text()?;

    Ok(PathBuf::from(path_str))
}

fn get_master_password(provided_password: Option<String>, yes: bool) -> Result<Option<String>> {
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
    let password: String = Password::new()
        .with_prompt("Enter master password")
        .with_confirmation("Confirm master password", "Passwords don't match")
        .interact()?;

    Ok(Some(password))
}

fn generate_random_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();

    (0..16)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn create_workspace_structure(workspace_path: &PathBuf) -> Result<()> {
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
    workspace_path: &PathBuf,
    encryption_enabled: bool,
    backup_dir: Option<PathBuf>,
) -> Result<()> {
    let config_path = workspace_path.join("config.toml");

    let config_content = format!(
        r#"# Persona CLI Configuration

[workspace]
path = "{}"
version = "0.1.0"

[security]
encryption_enabled = {}
auto_lock_timeout = 300  # seconds
require_biometric = false

[backup]
enabled = true
directory = "{}"
auto_backup = true
backup_interval = 86400  # seconds (24 hours)
max_backups = 30

[sync]
enabled = false
server_url = ""
auto_sync = false

[ui]
color_enabled = true
interactive = true
default_output_format = "table"

[logging]
level = "info"
file_enabled = true
max_file_size = "10MB"
max_files = 5
"#,
        workspace_path.display(),
        encryption_enabled,
        backup_dir
            .unwrap_or_else(|| workspace_path.join("backups"))
            .display()
    );

    std::fs::write(&config_path, config_content).context("Failed to write configuration file")?;

    println!("{} Created configuration file", "✓".green().bold());
    Ok(())
}

async fn initialize_database(
    workspace_path: &PathBuf,
    master_password: Option<&str>,
) -> Result<()> {
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
            let ws = Workspace::new(workspace_path.clone(), name);
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
