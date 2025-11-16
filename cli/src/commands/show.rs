use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use serde_json::Value;
use std::collections::HashMap;

use crate::config::CliConfig;
use persona_core::{Database, PersonaService, storage::IdentityRepository, Identity as CoreIdentity};

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
    println!("{} Showing identity '{}'...", 
        "👤".to_string(), 
        args.name.bright_cyan().bold()
    );
    println!();

    // Fetch identity details
    let identity = fetch_identity_details(&args.name, config).await?;

    // Display based on format
    match args.format.as_str() {
        "table" => display_table_format(&identity, args.show_sensitive)?,
        "json" => display_json_format(&identity)?,
        "yaml" => display_yaml_format(&identity)?,
        _ => anyhow::bail!("Unsupported output format: {}", args.format),
    }

    Ok(())
}

#[derive(Debug)]
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

async fn fetch_identity_details(name: &str, config: &CliConfig) -> Result<IdentityDetails> {
    use dialoguer::Password;
    // Open DB
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path.to_string_lossy())
        .await
        .context("Failed to connect to database")?;
    db.migrate().await.context("Failed to run database migrations")?;

    // Service
    let mut service = PersonaService::new(db.clone()).await.context("Failed to create PersonaService")?;
    let mut maybe: Option<CoreIdentity> = None;
    if service.has_users().await? {
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service.authenticate_user(&password).await? {
            persona_core::auth::authentication::AuthResult::Success => {
                maybe = service.get_identity_by_name(name).await?;
            }
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        // Fallback to direct repository read for non-authenticated DB
        let repo = IdentityRepository::new(db);
        maybe = repo.find_by_name(name).await?;
    }

    let id = maybe.with_context(|| format!("Identity '{}' not found", name))?;
    Ok(IdentityDetails {
        name: id.name.clone(),
        identity_type: id.identity_type.to_string(),
        description: id.description.unwrap_or_default(),
        email: id.email,
        phone: id.phone,
        tags: id.tags.clone(),
        attributes: id.attributes.into_iter().map(|(k,v)| (k, Value::String(v))).collect(),
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
    println!("  {}: {}", "Name".dim(), identity.name.bright_cyan());
    println!("  {}: {}", "Type".dim(), identity.identity_type.cyan());
    println!("  {}: {}", "Description".dim(), identity.description);
    println!("  {}: {}", "Active".dim(), 
        if identity.active { "Yes".green() } else { "No".red() }
    );
    println!();

    // Contact information
    if identity.email.is_some() || identity.phone.is_some() {
        println!("{}", "Contact Information:".yellow().bold());
        if let Some(ref email) = identity.email {
            println!("  {}: {}", "Email".dim(), email.cyan());
        }
        if let Some(ref phone) = identity.phone {
            println!("  {}: {}", "Phone".dim(), phone.cyan());
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
                println!("  {}: {}", key.dim(), value_str.cyan());
            } else {
                println!("  {}: {}", key.dim(), "***".dim());
            }
        }
        println!();
    }

    // Usage statistics
    println!("{}", "Usage Statistics:".yellow().bold());
    println!("  {}: {}", "Usage Count".dim(), identity.usage_count.to_string().cyan());
    if let Some(ref last_used) = identity.last_used {
        println!("  {}: {}", "Last Used".dim(), last_used.cyan());
    }
    println!();

    // Timestamps
    println!("{}", "Timestamps:".yellow().bold());
    println!("  {}: {}", "Created".dim(), identity.created.cyan());
    println!("  {}: {}", "Modified".dim(), identity.modified.cyan());

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
        "password", "secret", "token", "key", "ssn", "social_security",
        "credit_card", "bank_account", "pin", "passcode"
    ];
    
    let key_lower = key.to_lowercase();
    sensitive_keys.iter().any(|&sensitive| key_lower.contains(sensitive))
}
