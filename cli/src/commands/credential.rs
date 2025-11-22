use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::*;
use tabled::{Table, Tabled};
use uuid::Uuid;

use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use persona_core::{
    models::{Credential, CredentialData, CredentialType, PasswordCredentialData, SecurityLevel},
    Database, Identity, PersonaService,
};

#[derive(Args, Debug)]
pub struct CredentialArgs {
    #[command(subcommand)]
    command: CredentialCommand,
}

#[derive(Subcommand, Debug)]
pub enum CredentialCommand {
    /// Create a new credential (password/API key/etc.)
    Add {
        /// Identity name to attach the credential
        #[arg(short, long)]
        identity: String,
        /// Credential display name
        #[arg(short, long)]
        name: String,
        /// Credential type
        #[arg(short, long, default_value = "password")]
        credential_type: CredentialTypeOption,
        /// Security level (critical/high/medium/low)
        #[arg(long, default_value = "high")]
        security_level: SecurityLevelOption,
        /// Optional username / login
        #[arg(long)]
        username: Option<String>,
        /// Optional URL or service
        #[arg(long)]
        url: Option<String>,
        /// Prompt for password/secret in terminal
        #[arg(long)]
        prompt_secret: bool,
        /// Raw secret value (use only in CI)
        #[arg(long, conflicts_with = "prompt_secret")]
        secret: Option<String>,
        /// Mark as favorite
        #[arg(long)]
        favorite: bool,
    },
    /// List credentials with optional filters
    List {
        /// Identity name filter
        #[arg(short, long)]
        identity: Option<String>,
        /// Credential type filter
        #[arg(short, long)]
        credential_type: Option<String>,
        /// Show only favorites
        #[arg(long)]
        favorite: bool,
        /// Output as json/yaml
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Show decrypted credential details
    Show {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Include decrypted payload (will prompt for confirmation)
        #[arg(long)]
        reveal: bool,
    },
    /// Remove a credential
    Remove {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum CredentialTypeOption {
    Password,
    ApiKey,
    SshKey,
    CryptoWallet,
    BankCard,
    GameAccount,
    ServerConfig,
    Certificate,
    TwoFactor,
    Custom,
}

impl From<CredentialTypeOption> for CredentialType {
    fn from(value: CredentialTypeOption) -> Self {
        match value {
            CredentialTypeOption::Password => CredentialType::Password,
            CredentialTypeOption::ApiKey => CredentialType::ApiKey,
            CredentialTypeOption::SshKey => CredentialType::SshKey,
            CredentialTypeOption::CryptoWallet => CredentialType::CryptoWallet,
            CredentialTypeOption::BankCard => CredentialType::BankCard,
            CredentialTypeOption::GameAccount => CredentialType::GameAccount,
            CredentialTypeOption::ServerConfig => CredentialType::ServerConfig,
            CredentialTypeOption::Certificate => CredentialType::Certificate,
            CredentialTypeOption::TwoFactor => CredentialType::TwoFactor,
            CredentialTypeOption::Custom => CredentialType::Custom("custom".into()),
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum SecurityLevelOption {
    Critical,
    High,
    Medium,
    Low,
}

impl From<SecurityLevelOption> for SecurityLevel {
    fn from(value: SecurityLevelOption) -> Self {
        match value {
            SecurityLevelOption::Critical => SecurityLevel::Critical,
            SecurityLevelOption::High => SecurityLevel::High,
            SecurityLevelOption::Medium => SecurityLevel::Medium,
            SecurityLevelOption::Low => SecurityLevel::Low,
        }
    }
}

#[derive(Tabled)]
struct CredentialRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Type")]
    credential_type: String,
    #[tabled(rename = "Identity")]
    identity: String,
    #[tabled(rename = "Username")]
    username: String,
    #[tabled(rename = "Favorite")]
    favorite: String,
}

pub async fn execute(args: CredentialArgs, config: &CliConfig) -> Result<()> {
    match args.command {
        CredentialCommand::Add {
            identity,
            name,
            credential_type,
            security_level,
            username,
            url,
            prompt_secret,
            secret,
            favorite,
        } => {
            add_credential(
                config,
                identity,
                name,
                credential_type,
                security_level,
                username,
                url,
                prompt_secret,
                secret,
                favorite,
            )
            .await?
        }
        CredentialCommand::List {
            identity,
            credential_type,
            favorite,
            format,
        } => list_credentials(config, identity, credential_type, favorite, format).await?,
        CredentialCommand::Show { id, reveal } => show_credential(config, id, reveal).await?,
        CredentialCommand::Remove { id, yes } => remove_credential(config, id, yes).await?,
    }
    Ok(())
}

async fn init_service(config: &CliConfig) -> Result<PersonaService> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to connect to database: {}", db_path.display()))?;
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run database migrations")?;
    let mut service = PersonaService::new(db)
        .await
        .into_anyhow()
        .context("Failed to create PersonaService")?;

    if service
        .has_users()
        .await
        .into_anyhow()
        .context("Failed to check users")?
    {
        let password = dialoguer::Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .into_anyhow()
            .context("Failed to authenticate user")?
        {
            persona_core::auth::authentication::AuthResult::Success => Ok(service),
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        anyhow::bail!("Workspace not initialized. Run `persona init` first");
    }
}

async fn add_credential(
    config: &CliConfig,
    identity_name: String,
    name: String,
    credential_type: CredentialTypeOption,
    security_level: SecurityLevelOption,
    username: Option<String>,
    url: Option<String>,
    prompt_secret: bool,
    secret: Option<String>,
    favorite: bool,
) -> Result<()> {
    println!("{}", "➕ Adding credential...".cyan());
    let mut service = init_service(config).await?;
    let identity = resolve_identity(&mut service, &identity_name).await?;

    let secret_value = if prompt_secret {
        dialoguer::Password::new()
            .with_prompt("Secret / password")
            .with_confirmation("Confirm secret", "Mismatch")
            .interact()?
    } else if let Some(raw) = secret {
        raw
    } else {
        dialoguer::Input::new()
            .with_prompt("Secret / password (leave blank to skip)")
            .allow_empty(true)
            .interact_text()?
    };

    let credential_data = CredentialData::Password(PasswordCredentialData {
        password: secret_value.clone(),
        email: None,
        security_questions: Vec::new(),
    });

    let mut created = service
        .create_credential(
            identity.id,
            name.clone(),
            credential_type.into(),
            security_level.into(),
            &credential_data,
        )
        .await
        .into_anyhow()
        .context("Failed to create credential")?;

    created.username = username.clone();
    created.url = url.clone();
    created.is_favorite = favorite;
    service
        .update_credential(&created)
        .await
        .into_anyhow()
        .context("Failed to update credential metadata")?;

    println!(
        "{} Created credential '{}' for identity '{}'",
        "✓".green(),
        name.bright_green(),
        identity.name.bright_cyan()
    );

    Ok(())
}

async fn list_credentials(
    config: &CliConfig,
    identity_name: Option<String>,
    credential_type: Option<String>,
    favorite_only: bool,
    format: String,
) -> Result<()> {
    let mut service = init_service(config).await?;
    let credentials = if let Some(identity_name) = identity_name {
        let identity = resolve_identity(&mut service, &identity_name).await?;
        service
            .get_credentials_for_identity(&identity.id)
            .await
            .into_anyhow()
            .context("Failed to fetch credentials")?
    } else {
        service
            .search_credentials("")
            .await
            .into_anyhow()
            .context("Failed to fetch credentials")?
    };

    let filtered: Vec<Credential> = credentials
        .into_iter()
        .filter(|cred| {
            if favorite_only && !cred.is_favorite {
                return false;
            }
            if let Some(ref t) = credential_type {
                return cred.credential_type.to_string().eq_ignore_ascii_case(t);
            }
            true
        })
        .collect();

    if filtered.is_empty() {
        println!(
            "{}",
            "No credentials found with the given filters.".yellow()
        );
        return Ok(());
    }

    match format.as_str() {
        "table" => {
            let rows: Vec<CredentialRow> = filtered
                .iter()
                .map(|cred| CredentialRow {
                    id: cred.id.to_string(),
                    name: cred.name.clone(),
                    credential_type: cred.credential_type.to_string(),
                    identity: cred.identity_id.to_string(),
                    username: cred.username.clone().unwrap_or_default(),
                    favorite: if cred.is_favorite { "★" } else { "" }.into(),
                })
                .collect();
            println!("{}", Table::new(rows));
        }
        "json" => {
            println!("{}", serde_json::to_string_pretty(&filtered)?);
        }
        "yaml" => {
            println!("{}", serde_yaml::to_string(&filtered)?);
        }
        other => anyhow::bail!("Unsupported format: {}", other),
    }

    Ok(())
}

async fn show_credential(config: &CliConfig, id: Uuid, reveal: bool) -> Result<()> {
    let mut service = init_service(config).await?;
    let credential = service
        .get_credential(&id)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Credential {} not found", id))?;
    println!("{} {}", "Credential:".bold(), credential.name.cyan());
    println!("  ID: {}", credential.id);
    println!("  Type: {}", credential.credential_type);
    println!("  Identity ID: {}", credential.identity_id);
    if let Some(username) = &credential.username {
        println!("  Username: {}", username);
    }
    if let Some(url) = &credential.url {
        println!("  URL: {}", url);
    }
    println!(
        "  Favorite: {}",
        if credential.is_favorite { "yes" } else { "no" }
    );
    println!("  Security level: {}", credential.security_level);

    if reveal {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Reveal secret value? (visible on screen)")
            .interact()?;
        if confirm {
            if let Some(data) = service
                .get_credential_data(&id)
                .await
                .into_anyhow()?
            {
                match data {
                    CredentialData::Password(password) => {
                        println!("  Password: {}", password.password.blue());
                    }
                    CredentialData::ApiKey(api) => {
                        println!("  API Key: {}", api.api_key.blue());
                    }
                    CredentialData::SshKey(ssh) => {
                        println!("  Private Key: {}", ssh.private_key);
                    }
                    other => {
                        println!("  Data: {:?}", other);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn remove_credential(config: &CliConfig, id: Uuid, yes: bool) -> Result<()> {
    let mut service = init_service(config).await?;
    if !yes {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!("Remove credential {}?", id))
            .default(false)
            .interact()?;
        if !confirm {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }
    }
    let deleted = service.delete_credential(&id).await.into_anyhow()?;
    if deleted {
        println!("{} Removed credential {}", "✓".green(), id);
    } else {
        println!("{} Credential {} not found", "⚠".yellow(), id);
    }
    Ok(())
}

async fn resolve_identity(service: &mut PersonaService, name: &str) -> Result<Identity> {
    service
        .get_identity_by_name(name)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Identity '{}' not found", name))
}
