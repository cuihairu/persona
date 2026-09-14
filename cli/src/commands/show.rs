use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

use crate::config::CliConfig;
use persona_core::{
    storage::IdentityRepository, Database, Identity as CoreIdentity, PersonaService,
};

#[derive(Args)]
pub struct ShowArgs {
    /// Identity name to show
    name: String,

    /// Output format (table, json, yaml)
    #[arg(short, long, default_value = "table")]
    format: String,

    /// Show sensitive information (requires confirmation)
    #[arg(long)]
    show_sensitive: bool,
}

pub async fn execute(args: ShowArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: ShowArgs,
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    println!(
        "👤 Showing identity '{}'...",
        args.name.bright_cyan().bold()
    );
    println!();

    // Fetch identity details
    let identity = fetch_identity_details(&args.name, config, ui).await?;

    // Display based on format
    match args.format.as_str() {
        "table" => display_table_format(&identity, args.show_sensitive)?,
        "json" => display_json_format(&identity)?,
        "yaml" => display_yaml_format(&identity)?,
        _ => anyhow::bail!("Unsupported output format: {}", args.format),
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct IdentityDetails {
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
    attributes: HashMap<String, Value>,
    active: bool,
    created: String,
    modified: String,
    last_used: Option<String>,
    usage_count: u32,
}

async fn fetch_identity_details(
    name: &str,
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<IdentityDetails> {
    // Open DB
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to connect to database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;

    // Service
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let maybe: Option<CoreIdentity> = if service
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
                .map_err(|e| anyhow!("Failed to fetch identity: {}", e))?,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        // Fallback to direct repository read for non-authenticated DB
        let repo = IdentityRepository::new(db);
        repo.find_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to fetch identity: {}", e))?
    };

    let id = maybe.with_context(|| format!("Identity '{}' not found", name))?;
    Ok(IdentityDetails {
        name: id.name.clone(),
        identity_type: id.identity_type.to_string(),
        description: id.description.unwrap_or_default(),
        email: id.email,
        phone: id.phone,
        tags: id.tags.clone(),
        attributes: id
            .attributes
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect(),
        active: id.is_active,
        created: id.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        modified: id.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        // Usage tracking not implemented yet; leave placeholders
        last_used: None,
        usage_count: 0,
    })
}

fn display_table_format(identity: &IdentityDetails, show_sensitive: bool) -> Result<()> {
    // Basic information
    println!("{}", "Basic Information:".yellow().bold());
    println!("  {}: {}", "Name".dimmed(), identity.name.bright_cyan());
    println!("  {}: {}", "Type".dimmed(), identity.identity_type.cyan());
    println!("  {}: {}", "Description".dimmed(), identity.description);
    println!(
        "  {}: {}",
        "Active".dimmed(),
        if identity.active {
            "Yes".green()
        } else {
            "No".red()
        }
    );
    println!();

    // Contact information
    if identity.email.is_some() || identity.phone.is_some() {
        println!("{}", "Contact Information:".yellow().bold());
        if let Some(ref email) = identity.email {
            println!("  {}: {}", "Email".dimmed(), email.cyan());
        }
        if let Some(ref phone) = identity.phone {
            println!("  {}: {}", "Phone".dimmed(), phone.cyan());
        }
        println!();
    }

    // Tags
    if !identity.tags.is_empty() {
        println!("{}", "Tags:".yellow().bold());
        for tag in &identity.tags {
            println!("  • {}", tag.bright_blue());
        }
        println!();
    }

    // Custom attributes
    if !identity.attributes.is_empty() {
        println!("{}", "Custom Attributes:".yellow().bold());
        for (key, value) in &identity.attributes {
            let value_str = match value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => serde_json::to_string(value).unwrap_or_else(|_| "N/A".to_string()),
            };

            if show_sensitive || !is_sensitive_attribute(key) {
                println!("  {}: {}", key.dimmed(), value_str.cyan());
            } else {
                println!("  {}: {}", key.dimmed(), "***".dimmed());
            }
        }
        println!();
    }

    // Usage statistics
    println!("{}", "Usage Statistics:".yellow().bold());
    println!(
        "  {}: {}",
        "Usage Count".dimmed(),
        identity.usage_count.to_string().cyan()
    );
    if let Some(ref last_used) = identity.last_used {
        println!("  {}: {}", "Last Used".dimmed(), last_used.cyan());
    }
    println!();

    // Timestamps
    println!("{}", "Timestamps:".yellow().bold());
    println!("  {}: {}", "Created".dimmed(), identity.created.cyan());
    println!("  {}: {}", "Modified".dimmed(), identity.modified.cyan());

    Ok(())
}

fn display_json_format(identity: &IdentityDetails) -> Result<()> {
    let json = serde_json::to_string_pretty(identity)?;
    println!("{}", json);
    Ok(())
}

fn display_yaml_format(identity: &IdentityDetails) -> Result<()> {
    let yaml = serde_yaml::to_string(identity)?;
    println!("{}", yaml);
    Ok(())
}

fn is_sensitive_attribute(key: &str) -> bool {
    let sensitive_keys = [
        "password",
        "secret",
        "token",
        "key",
        "ssn",
        "social_security",
        "credit_card",
        "bank_account",
        "pin",
        "passcode",
    ];

    let key_lower = key.to_lowercase();
    sensitive_keys
        .iter()
        .any(|&sensitive| key_lower.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use persona_core::models::{Identity, IdentityType};
    use persona_core::Repository;
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
        config
    }

    fn args(name: &str, format: &str, show_sensitive: bool) -> ShowArgs {
        ShowArgs {
            name: name.to_string(),
            format: format.to_string(),
            show_sensitive,
        }
    }

    /// Creates a migrated database in `dir` and inserts the named identity.
    async fn seed_identity(dir: &TempDir, name: &str) {
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db);
        repo.create(&Identity::new(name.to_string(), IdentityType::Personal))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn every_format_and_error_paths_without_users() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        // All three formats succeed through the unauthenticated read path.
        for format in ["table", "json", "yaml"] {
            execute(args("alice", format, false), &config)
                .await
                .unwrap_or_else(|e| panic!("format {} must work: {}", format, e));
        }

        // Unknown format is rejected after the identity resolves.
        let err = execute(args("alice", "xml", false), &config)
            .await
            .expect_err("unsupported format must fail");
        assert!(err.to_string().contains("Unsupported output format: xml"));

        // A missing identity is reported before formatting runs.
        let err = execute(args("ghost", "table", false), &config)
            .await
            .expect_err("missing identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));
    }

    #[tokio::test]
    async fn authenticated_path_with_master_password() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "bob").await;

        // Seed the workspace user so `has_users` is true and the
        // authentication branch is taken.
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }

        // Wrong env password fails before any identity lookup.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let err = execute(args("bob", "json", false), &config)
            .await
            .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        // Correct env password unlocks; sensitive masking runs either way.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        execute(args("bob", "json", false), &config)
            .await
            .expect("correct password must show identity");
        execute(args("bob", "table", true), &config)
            .await
            .expect("table with sensitive shown");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[test]
    fn table_format_masks_sensitive_attributes() {
        let mut attributes = HashMap::new();
        attributes.insert("api_token".to_string(), Value::String("hunter2".into()));
        attributes.insert("city".to_string(), Value::String("Berlin".into()));

        let details = IdentityDetails {
            name: "bob".into(),
            identity_type: "personal".into(),
            description: String::new(),
            email: Some("bob@example.com".into()),
            phone: None,
            tags: vec!["work".into()],
            attributes,
            active: true,
            created: "2024-01-01 00:00:00".into(),
            modified: "2024-01-02 00:00:00".into(),
            last_used: None,
            usage_count: 0,
        };

        // Rendering must not panic and must not leak the secret — masking is
        // driven by `is_sensitive_attribute`, asserted directly below.
        display_table_format(&details, false).unwrap();
        display_table_format(&details, true).unwrap();
        display_json_format(&details).unwrap();
        display_yaml_format(&details).unwrap();

        assert!(is_sensitive_attribute("api_token"));
        assert!(!is_sensitive_attribute("city"));
        assert!(is_sensitive_attribute("SOCIAL_SECURITY"));
    }
}
