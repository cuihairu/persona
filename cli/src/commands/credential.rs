use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::*;
use std::path::PathBuf;
use tabled::{Table, Tabled};
use uuid::Uuid;

use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use persona_core::{
    models::{
        Credential, CredentialData, CredentialType, EntityType, PasswordCredentialData,
        SecureNoteData, SecurityLevel,
    },
    Identity, PersonaService,
};

use crate::utils::prompt::{PromptUi, TerminalUi};

use super::service::init_service;

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
        #[arg(long, default_value = "password")]
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
        /// Note content for --credential-type note (prompts when omitted)
        #[arg(long)]
        note: Option<String>,
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
        #[arg(long)]
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
    /// Show change history for a credential (item history; metadata-only diffs)
    History {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
    },
    /// Attach a file to a credential (encrypted with the item's key)
    Attach {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Path of the file to attach
        #[arg(long)]
        file: PathBuf,
        /// Store the file without encryption
        #[arg(long)]
        no_encrypt: bool,
    },
    /// List attachments for a credential
    Attachments {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
    },
    /// Save an attachment to disk (decrypted)
    SaveAttachment {
        /// Attachment UUID (see `credential attachments`)
        #[arg(long)]
        attachment_id: Uuid,
        /// Output file path
        #[arg(long)]
        output: PathBuf,
    },
    /// Remove an attachment
    RemoveAttachment {
        /// Attachment UUID (see `credential attachments`)
        #[arg(long)]
        attachment_id: Uuid,
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
    Note,
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
            CredentialTypeOption::Note => CredentialType::SecureNote,
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
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: CredentialArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
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
            note,
            favorite,
        } => {
            add_credential(
                config,
                ui,
                identity,
                name,
                credential_type,
                security_level,
                username,
                url,
                prompt_secret,
                secret,
                note,
                favorite,
            )
            .await?
        }
        CredentialCommand::List {
            identity,
            credential_type,
            favorite,
            format,
        } => list_credentials(config, ui, identity, credential_type, favorite, format).await?,
        CredentialCommand::Show { id, reveal } => show_credential(config, ui, id, reveal).await?,
        CredentialCommand::Remove { id, yes } => remove_credential(config, ui, id, yes).await?,
        CredentialCommand::History { id } => show_credential_history(config, ui, id).await?,
        CredentialCommand::Attach { id, file, no_encrypt } => {
            attach_file_command(config, ui, id, file, !no_encrypt).await?
        }
        CredentialCommand::Attachments { id } => list_attachments_command(config, ui, id).await?,
        CredentialCommand::SaveAttachment {
            attachment_id,
            output,
        } => save_attachment_command(config, ui, attachment_id, output).await?,
        CredentialCommand::RemoveAttachment { attachment_id, yes } => {
            remove_attachment_command(config, ui, attachment_id, yes).await?
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn add_credential(
    config: &CliConfig,
    ui: &dyn PromptUi,
    identity_name: String,
    name: String,
    credential_type: CredentialTypeOption,
    security_level: SecurityLevelOption,
    username: Option<String>,
    url: Option<String>,
    prompt_secret: bool,
    secret: Option<String>,
    note: Option<String>,
    favorite: bool,
) -> Result<()> {
    println!("{}", "➕ Adding credential...".cyan());
    let mut service = init_service(config, ui).await?;
    let identity = resolve_identity(&mut service, &identity_name).await?;

    // Secure Note：正文走 --note（或可见提示输入），密码路径不适用。
    let credential_data = if matches!(credential_type, CredentialTypeOption::Note) {
        if secret.is_some() || prompt_secret {
            bail!("Note content is provided via --note; --secret/--prompt-secret do not apply");
        }
        let note_text = match note {
            Some(text) if !text.trim().is_empty() => text,
            _ => ui.input("Note content", None, false)?,
        };
        CredentialData::SecureNote(SecureNoteData {
            note: note_text.clone(),
        })
    } else {
        let secret_value = if prompt_secret {
            super::service::prompt_credential_secret(ui)?
        } else if let Some(raw) = secret {
            raw
        } else {
            ui.input("Secret / password (leave blank to skip)", None, true)?
        };

        CredentialData::Password(PasswordCredentialData {
            password: secret_value.clone(),
            email: None,
            security_questions: Vec::new(),
        })
    };

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
    ui: &dyn PromptUi,
    identity_name: Option<String>,
    credential_type: Option<String>,
    favorite_only: bool,
    format: String,
) -> Result<()> {
    let mut service = init_service(config, ui).await?;
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

async fn show_credential(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    reveal: bool,
) -> Result<()> {
    let service = init_service(config, ui).await?;
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
        let confirm = ui.confirm("Reveal secret value? (visible on screen)", false)?;
        if confirm {
            if let Some(data) = service.get_credential_data(&id).await.into_anyhow()? {
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
                    CredentialData::SecureNote(note) => {
                        println!("  --- note ---");
                        println!("{}", note.note.blue());
                        println!("  ------------");
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

async fn remove_credential(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    yes: bool,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    if !yes {
        let confirm = ui.confirm(&format!("Remove credential {}?", id), false)?;
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

#[derive(Tabled)]
struct HistoryRow {
    #[tabled(rename = "Version")]
    version: u32,
    #[tabled(rename = "Time")]
    time: String,
    #[tabled(rename = "Change")]
    change_type: String,
    #[tabled(rename = "Fields")]
    fields: String,
}

/// Item history（1Password 对齐）：凭据的变更时间线。
/// 历史行只含明文元数据 diff——密文变化仅显示为 `encrypted_data` 占位。
/// 凭据删除后历史仍可查询（名称退化为 UUID 展示）。
async fn show_credential_history(config: &CliConfig, ui: &dyn PromptUi, id: Uuid) -> Result<()> {
    let service = init_service(config, ui).await?;
    let credential = service.get_credential(&id).await.into_anyhow()?;
    match &credential {
        Some(cred) => println!("{} {}", "History for:".bold(), cred.name.cyan()),
        None => println!(
            "{} {} (deleted)",
            "History for:".bold(),
            id.to_string().cyan()
        ),
    }

    let history = service
        .get_entity_history(EntityType::Credential, &id)
        .await
        .into_anyhow()
        .context("Failed to fetch credential history")?;

    if history.is_empty() {
        println!("{}", "No recorded changes.".yellow());
        return Ok(());
    }

    let rows: Vec<HistoryRow> = history
        .iter()
        .map(|entry| HistoryRow {
            version: entry.version,
            time: entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            change_type: entry.change_type.to_string(),
            fields: if entry.changes_summary.is_empty() {
                "-".to_string()
            } else {
                entry
                    .changes_summary
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        })
        .collect();
    println!("{}", Table::new(rows));
    Ok(())
}

/// 人类可读的附件大小（B → KB → MB）
fn format_attachment_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Attachments（1Password 对齐）：附件经所属凭据的 per-item key 加密封存，
/// 改密（rewrap）后仍可解密。blob 目录在 init_service 里随解锁一起初始化。
async fn attach_file_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    file: PathBuf,
    encrypt: bool,
) -> Result<()> {
    let mut service = init_service(config, ui).await?;
    let attachment_id = service
        .attach_file(id, &file, encrypt)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to attach {}", file.display()))?;
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file.display().to_string());
    println!(
        "{} Attached {} ({}) as {}",
        "✓".green(),
        filename.cyan(),
        if encrypt { "encrypted".green() } else { "unencrypted".yellow() },
        attachment_id
    );
    Ok(())
}

#[derive(Tabled)]
struct AttachmentRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "File")]
    filename: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Encrypted")]
    encrypted: String,
    #[tabled(rename = "Attached")]
    attached: String,
}

async fn list_attachments_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    let attachments = service
        .get_attachments(&id)
        .await
        .into_anyhow()
        .context("Failed to list attachments")?;

    if attachments.is_empty() {
        println!("{}", "No attachments.".yellow());
        return Ok(());
    }

    let rows: Vec<AttachmentRow> = attachments
        .iter()
        .map(|a| AttachmentRow {
            id: a.id.to_string(),
            filename: a.filename.clone(),
            size: format_attachment_size(a.size),
            encrypted: if a.is_encrypted { "yes".into() } else { "no".into() },
            attached: a.created_at.format("%Y-%m-%d %H:%M").to_string(),
        })
        .collect();
    println!("{}", Table::new(rows));
    Ok(())
}

async fn save_attachment_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    attachment_id: Uuid,
    output: PathBuf,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    service
        .save_attachment(&attachment_id, &output, true)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to save attachment to {}", output.display()))?;
    println!(
        "{} Saved decrypted attachment to {}",
        "✓".green(),
        output.display().to_string().cyan()
    );
    Ok(())
}

async fn remove_attachment_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    attachment_id: Uuid,
    yes: bool,
) -> Result<()> {
    let mut service = init_service(config, ui).await?;
    if !yes {
        let confirm = ui.confirm(&format!("Remove attachment {}?", attachment_id), false)?;
        if !confirm {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }
    }
    service
        .delete_attachment(&attachment_id)
        .await
        .into_anyhow()
        .context("Failed to remove attachment")?;
    println!("{} Removed attachment {}", "✓".green(), attachment_id);
    Ok(())
}

async fn resolve_identity(service: &mut PersonaService, name: &str) -> Result<Identity> {
    service
        .get_identity_by_name(name)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Identity '{}' not found", name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{ApiKeyData, SshKeyData};
    use persona_core::Database;
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

    /// Unlocks the workspace and creates the named identity.
    async fn seed(config: &CliConfig, identity: &str) -> persona_core::Identity {
        let service =
            crate::commands::service::init_service(config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let created = service
            .create_identity_full(persona_core::Identity::new(
                identity.to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        created
    }

    fn add_args(
        identity: &str,
        name: &str,
        secret: Option<&str>,
        favorite: bool,
    ) -> CredentialArgs {
        CredentialArgs {
            command: CredentialCommand::Add {
                identity: identity.to_string(),
                name: name.to_string(),
                credential_type: CredentialTypeOption::Password,
                security_level: SecurityLevelOption::High,
                username: Some("u1".to_string()),
                url: Some("https://example.com".to_string()),
                prompt_secret: false,
                secret: secret.map(String::from),
                note: None,
                favorite,
            },
        }
    }

    #[tokio::test]
    async fn credential_add_list_show_remove_round_trip() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "alice").await;

        // Add with an explicit secret (no prompt path).
        execute(
            add_args("alice", "site-login", Some("s3cret"), true),
            &config,
        )
        .await
        .expect("add with explicit secret works");

        // List all + per identity + favorite filter, in each format.
        for fmt in ["table", "json", "yaml"] {
            execute(
                CredentialArgs {
                    command: CredentialCommand::List {
                        identity: None,
                        credential_type: None,
                        favorite: false,
                        format: fmt.to_string(),
                    },
                },
                &config,
            )
            .await
            .unwrap_or_else(|e| panic!("list {} must work: {}", fmt, e));
        }
        execute(
            CredentialArgs {
                command: CredentialCommand::List {
                    identity: Some("alice".to_string()),
                    credential_type: Some("password".to_string()),
                    favorite: true,
                    format: "json".to_string(),
                },
            },
            &config,
        )
        .await
        .expect("filtered list works");

        // Unknown format fails.
        let err = execute(
            CredentialArgs {
                command: CredentialCommand::List {
                    identity: None,
                    credential_type: None,
                    favorite: false,
                    format: "xml".to_string(),
                },
            },
            &config,
        )
        .await
        .expect_err("bad format must fail");
        assert!(err.to_string().contains("Unsupported format: xml"));

        // Unknown identity fails during add.
        let err = execute(add_args("ghost", "x", Some("pw"), false), &config)
            .await
            .expect_err("unknown identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));

        // Grab the credential id, then show + remove it.
        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let alice = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let creds = service
            .get_credentials_for_identity(&alice.id)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
        let cred_id = creds[0].id;
        assert!(creds[0].is_favorite);
        drop(service);

        execute(
            CredentialArgs {
                command: CredentialCommand::Show {
                    id: cred_id,
                    reveal: false,
                },
            },
            &config,
        )
        .await
        .expect("show works");

        // Missing credential fails fast.
        let err = execute(
            CredentialArgs {
                command: CredentialCommand::Show {
                    id: uuid::Uuid::new_v4(),
                    reveal: false,
                },
            },
            &config,
        )
        .await
        .expect_err("missing credential must fail");
        assert!(err.to_string().contains("not found"));

        execute(
            CredentialArgs {
                command: CredentialCommand::Remove {
                    id: cred_id,
                    yes: true,
                },
            },
            &config,
        )
        .await
        .expect("remove works");

        // Remove is reported for missing credentials too.
        execute(
            CredentialArgs {
                command: CredentialCommand::Remove {
                    id: cred_id,
                    yes: true,
                },
            },
            &config,
        )
        .await
        .expect("second remove reports not found");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn credential_secret_env_var_serves_prompt() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "bob").await;

        // prompt_secret=true reads PERSONA_CREDENTIAL_SECRET instead of the TTY.
        std::env::set_var("PERSONA_CREDENTIAL_SECRET", "env-secret");
        let mut args = add_args("bob", "from-env", None, false);
        if let CredentialCommand::Add {
            ref mut prompt_secret,
            ..
        } = args.command
        {
            *prompt_secret = true;
        }
        execute(args, &config)
            .await
            .expect("add via env secret works");

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let bob = service.get_identity_by_name("bob").await.unwrap().unwrap();
        let creds = service.get_credentials_for_identity(&bob.id).await.unwrap();
        assert_eq!(creds.len(), 1);
        let data = service.get_credential_data(&creds[0].id).await.unwrap();
        match data {
            Some(CredentialData::Password(pw)) => assert_eq!(pw.password, "env-secret"),
            other => panic!("unexpected data: {:?}", other),
        }

        std::env::remove_var("PERSONA_CREDENTIAL_SECRET");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn credential_show_reveal_and_remove_decline_paths() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "cara").await;

        execute(add_args("cara", "vault", Some("topsecret"), false), &config)
            .await
            .expect("seed credential added");

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let cara = service.get_identity_by_name("cara").await.unwrap().unwrap();
        let creds = service
            .get_credentials_for_identity(&cara.id)
            .await
            .unwrap();
        let cred_id = creds[0].id;
        drop(service);

        // Declining the reveal prompt hides the secret.
        let ui = ScriptedUi::new().confirm(false);
        execute_with(
            CredentialArgs {
                command: CredentialCommand::Show {
                    id: cred_id,
                    reveal: true,
                },
            },
            &config,
            &ui,
        )
        .await
        .expect("declined reveal succeeds");
        assert!(ui.exhausted());

        // Accepting it prints the decrypted password.
        let ui = ScriptedUi::new().confirm(true);
        execute_with(
            CredentialArgs {
                command: CredentialCommand::Show {
                    id: cred_id,
                    reveal: true,
                },
            },
            &config,
            &ui,
        )
        .await
        .expect("accepted reveal succeeds");
        assert!(ui.exhausted());

        // Removing with a declined confirmation aborts and keeps the row.
        let ui = ScriptedUi::new().confirm(false);
        execute_with(
            CredentialArgs {
                command: CredentialCommand::Remove {
                    id: cred_id,
                    yes: false,
                },
            },
            &config,
            &ui,
        )
        .await
        .expect("declined removal returns success");
        assert!(ui.exhausted());

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let creds = service
            .get_credentials_for_identity(&cara.id)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1, "declined removal must keep the credential");
        drop(service);

        // Accepting the confirmation deletes it.
        let ui = ScriptedUi::new().confirm(true);
        execute_with(
            CredentialArgs {
                command: CredentialCommand::Remove {
                    id: cred_id,
                    yes: false,
                },
            },
            &config,
            &ui,
        )
        .await
        .expect("confirmed removal deletes");
        assert!(ui.exhausted());

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn credential_show_reveal_renders_api_key_and_ssh_key_payloads() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "erin").await;

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let erin = service.get_identity_by_name("erin").await.unwrap().unwrap();

        // Seed a non-password credential of each decryptable kind directly so
        // the reveal match arms for ApiKey and SshKey render.
        let api_id = service
            .create_credential(
                erin.id,
                "api-token".to_string(),
                CredentialType::ApiKey,
                SecurityLevel::High,
                &CredentialData::ApiKey(ApiKeyData {
                    api_key: "sk-live-123".to_string(),
                    api_secret: None,
                    token: None,
                    permissions: Vec::new(),
                    expires_at: None,
                }),
            )
            .await
            .unwrap()
            .id;
        let ssh_id = service
            .create_credential(
                erin.id,
                "server-key".to_string(),
                CredentialType::SshKey,
                SecurityLevel::High,
                &CredentialData::SshKey(SshKeyData {
                    private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                    public_key: "ssh-ed25519 AAA".to_string(),
                    key_type: "ed25519".to_string(),
                    passphrase: None,
                }),
            )
            .await
            .unwrap()
            .id;
        drop(service);

        // Accepting the reveal prints the API key.
        let ui = ScriptedUi::new().confirm(true);
        execute_with(
            CredentialArgs {
                command: CredentialCommand::Show {
                    id: api_id,
                    reveal: true,
                },
            },
            &config,
            &ui,
        )
        .await
        .expect("api key reveal works");
        assert!(ui.exhausted());

        // Same for the SSH private key arm.
        let ui = ScriptedUi::new().confirm(true);
        execute_with(
            CredentialArgs {
                command: CredentialCommand::Show {
                    id: ssh_id,
                    reveal: true,
                },
            },
            &config,
            &ui,
        )
        .await
        .expect("ssh key reveal works");
        assert!(ui.exhausted());

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    /// Kinds without a dedicated reveal line fall through to the generic
    /// debug formatter instead of being skipped.
    #[tokio::test]
    async fn credential_show_reveal_renders_generic_payload_kinds() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "faye").await;

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let faye = service.get_identity_by_name("faye").await.unwrap().unwrap();

        let totp_id = service
            .create_credential(
                faye.id,
                "login-otp".to_string(),
                CredentialType::TwoFactor,
                SecurityLevel::Medium,
                &CredentialData::TwoFactor(persona_core::TwoFactorData {
                    secret_key: "JBSWY3DPEHPK3PXP".to_string(),
                    issuer: "Example".to_string(),
                    account_name: "faye".to_string(),
                    algorithm: "SHA1".to_string(),
                    digits: 6,
                    period: 30,
                }),
            )
            .await
            .unwrap()
            .id;
        drop(service);

        let ui = ScriptedUi::new().confirm(true);
        execute_with(
            CredentialArgs {
                command: CredentialCommand::Show {
                    id: totp_id,
                    reveal: true,
                },
            },
            &config,
            &ui,
        )
        .await
        .expect("two-factor reveal renders via the generic arm");
        assert!(ui.exhausted());

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn credential_add_prompts_for_secret_and_maps_every_type() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_CREDENTIAL_SECRET");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "dora").await;

        // No --secret and no env var: the interactive input prompt is used.
        // Username/URL are left unset so the plain-show branch also renders.
        let mut prompted = add_args("dora", "typed", None, false);
        if let CredentialCommand::Add {
            ref mut username,
            ref mut url,
            ..
        } = prompted.command
        {
            *username = None;
            *url = None;
        }
        let ui = ScriptedUi::new().input("typed-secret");
        execute_with(prompted, &config, &ui)
            .await
            .expect("prompted secret path works");
        assert!(ui.exhausted());

        // Every credential type / security level mapping round-trips.
        let types = [
            (CredentialTypeOption::ApiKey, SecurityLevelOption::Critical),
            (CredentialTypeOption::SshKey, SecurityLevelOption::Medium),
            (CredentialTypeOption::CryptoWallet, SecurityLevelOption::Low),
            (CredentialTypeOption::BankCard, SecurityLevelOption::High),
            (
                CredentialTypeOption::GameAccount,
                SecurityLevelOption::Medium,
            ),
            (
                CredentialTypeOption::ServerConfig,
                SecurityLevelOption::High,
            ),
            (
                CredentialTypeOption::Certificate,
                SecurityLevelOption::Critical,
            ),
            (CredentialTypeOption::TwoFactor, SecurityLevelOption::High),
            (CredentialTypeOption::Custom, SecurityLevelOption::Low),
        ];
        for (i, (ctype, level)) in types.iter().enumerate() {
            let args = CredentialArgs {
                command: CredentialCommand::Add {
                    identity: "dora".to_string(),
                    name: format!("cred{i}"),
                    credential_type: ctype.clone(),
                    security_level: level.clone(),
                    username: Some("u".to_string()),
                    url: None,
                    prompt_secret: false,
                    secret: Some("pw".to_string()),
                    note: None,
                    favorite: false,
                },
            };
            execute(args, &config)
                .await
                .unwrap_or_else(|e| panic!("add type {ctype:?} must work: {e}"));
        }

        // Type filter keeps only matching rows; favorite filter can empty the
        // list entirely ("No credentials found" path).
        execute(
            CredentialArgs {
                command: CredentialCommand::List {
                    identity: Some("dora".to_string()),
                    credential_type: Some("ApiKey".to_string()),
                    favorite: false,
                    format: "table".to_string(),
                },
            },
            &config,
        )
        .await
        .expect("type-filtered list works");
        execute(
            CredentialArgs {
                command: CredentialCommand::List {
                    identity: Some("dora".to_string()),
                    credential_type: None,
                    favorite: true,
                    format: "table".to_string(),
                },
            },
            &config,
        )
        .await
        .expect("favorite-only empty list works");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn credential_add_note_stores_encrypted_secure_note() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "alice").await;

        let note_args = |name: &str, secret: Option<&str>, note: Option<&str>| CredentialArgs {
            command: CredentialCommand::Add {
                identity: "alice".to_string(),
                name: name.to_string(),
                credential_type: CredentialTypeOption::Note,
                security_level: SecurityLevelOption::High,
                username: None,
                url: None,
                prompt_secret: false,
                secret: secret.map(String::from),
                note: note.map(String::from),
                favorite: false,
            },
        };

        // note 类型不适用密码路径。
        let err = execute_with(note_args("bad", Some("pw"), None), &config, &TerminalUi)
            .await
            .expect_err("note with --secret must fail");
        assert!(err.to_string().contains("--note"));

        // --note 显式提供正文。
        execute_with(
            note_args("Recovery codes", None, Some("1111-2222\n3333-4444")),
            &config,
            &TerminalUi,
        )
        .await
        .expect("explicit note works");

        // --note 缺省：走可见 input 提示（ScriptedUi 预置答案）。
        let scripted = ScriptedUi::new().input("interactive note body");
        execute_with(note_args("Scratch", None, None), &config, &scripted)
            .await
            .expect("interactive note works");
        assert!(scripted.exhausted());

        // 读回：类型与数据变体正确，正文逐字保留（per-item key 加密往返）。
        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let alice = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let creds = service
            .get_credentials_for_identity(&alice.id)
            .await
            .unwrap();
        assert_eq!(creds.len(), 2);
        assert!(creds
            .iter()
            .all(|c| matches!(c.credential_type, CredentialType::SecureNote)));

        let recovery = creds.iter().find(|c| c.name == "Recovery codes").unwrap();
        let data = service
            .get_credential_data(&recovery.id)
            .await
            .unwrap()
            .expect("note data present");
        match data {
            CredentialData::SecureNote(note) => {
                assert_eq!(note.note, "1111-2222\n3333-4444");
            }
            other => panic!("unexpected data: {:?}", other),
        }

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    /// Item history：add 落 created 行，元数据补写落 updated 行，
    /// `history` 子命令列出时间线；删除后历史仍可查询。
    #[tokio::test]
    async fn credential_history_lists_changes_and_survives_delete() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "gina").await;

        // add = create + 元数据补写（username/url/favorite）→ created + updated 两行
        execute(add_args("gina", "hist-login", Some("pw"), true), &config)
            .await
            .expect("seed add works");

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let gina = service.get_identity_by_name("gina").await.unwrap().unwrap();
        let creds = service
            .get_credentials_for_identity(&gina.id)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
        let cred_id = creds[0].id;
        drop(service);

        execute(
            CredentialArgs {
                command: CredentialCommand::History { id: cred_id },
            },
            &config,
        )
        .await
        .expect("history lists rows");

        // 删除后：凭据查询 404，历史命令仍列出（含 deleted 行）
        execute(
            CredentialArgs {
                command: CredentialCommand::Remove {
                    id: cred_id,
                    yes: true,
                },
            },
            &config,
        )
        .await
        .expect("remove works");

        let err = execute(
            CredentialArgs {
                command: CredentialCommand::Show {
                    id: cred_id,
                    reveal: false,
                },
            },
            &config,
        )
        .await
        .expect_err("show after delete must fail");
        assert!(err.to_string().contains("not found"));

        execute(
            CredentialArgs {
                command: CredentialCommand::History { id: cred_id },
            },
            &config,
        )
        .await
        .expect("history survives delete");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    /// Attachments：attach（加密封存）→ attachments 列表 → save-attachment
    /// 解密读回 → remove-attachment；凭据删除级联清附件。
    #[tokio::test]
    async fn credential_attachment_commands_round_trip() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        seed(&config, "hana").await;
        execute(add_args("hana", "attach-login", Some("pw"), false), &config)
            .await
            .expect("seed add works");

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let hana = service.get_identity_by_name("hana").await.unwrap().unwrap();
        let cred_id = service
            .get_credentials_for_identity(&hana.id)
            .await
            .unwrap()[0]
            .id;
        drop(service);

        // 源文件放在独立 tempdir（workspace tempdir 会被 attachments/ 目录复用）
        let src_dir = TempDir::new().unwrap();
        let src = src_dir.path().join("recovery.txt");
        std::fs::write(&src, b"cli-attachment-payload").unwrap();

        execute(
            CredentialArgs {
                command: CredentialCommand::Attach {
                    id: cred_id,
                    file: src.clone(),
                    no_encrypt: false,
                },
            },
            &config,
        )
        .await
        .expect("attach works");

        // 列表命令可跑；元数据断言走 service 层（is_encrypted / 文件名）
        execute(
            CredentialArgs {
                command: CredentialCommand::Attachments { id: cred_id },
            },
            &config,
        )
        .await
        .expect("attachments list works");

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let attachments = service.get_attachments(&cred_id).await.unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].filename, "recovery.txt");
        assert!(attachments[0].is_encrypted);
        let attachment_id = attachments[0].id;
        drop(service);

        // 解密保存：读回与源字节一致（item key 封存的核心保障）
        let out = src_dir.path().join("restored.txt");
        execute(
            CredentialArgs {
                command: CredentialCommand::SaveAttachment {
                    attachment_id,
                    output: out.clone(),
                },
            },
            &config,
        )
        .await
        .expect("save-attachment works");
        assert_eq!(
            std::fs::read(&out).unwrap(),
            b"cli-attachment-payload".to_vec()
        );

        // 移除附件 → 列表清空
        execute(
            CredentialArgs {
                command: CredentialCommand::RemoveAttachment {
                    attachment_id,
                    yes: true,
                },
            },
            &config,
        )
        .await
        .expect("remove-attachment works");

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        assert!(service.get_attachments(&cred_id).await.unwrap().is_empty());

        // 凭据删除级联（再挂一个，然后删凭据）
        drop(service);
        execute(
            CredentialArgs {
                command: CredentialCommand::Attach {
                    id: cred_id,
                    file: src.clone(),
                    no_encrypt: false,
                },
            },
            &config,
        )
        .await
        .expect("re-attach works");
        execute(
            CredentialArgs {
                command: CredentialCommand::Remove {
                    id: cred_id,
                    yes: true,
                },
            },
            &config,
        )
        .await
        .expect("credential remove works");

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        assert!(
            service.get_attachments(&cred_id).await.unwrap().is_empty(),
            "credential deletion must cascade attachments"
        );

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }
}
