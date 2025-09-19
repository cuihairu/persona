use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use serde_json::Value;
use std::collections::HashMap;

use crate::config::CliConfig;

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

async fn fetch_identity_details(name: &str, _config: &CliConfig) -> Result<IdentityDetails> {
    // TODO: Implement actual database fetch using persona-core
    
    // Mock data for demonstration
    Ok(IdentityDetails {
        name: name.to_string(),
        identity_type: "personal".to_string(),
        description: "My personal identity for daily use".to_string(),
        email: Some("john@example.com".to_string()),
        phone: Some("+1234567890".to_string()),
        tags: vec!["default".to_string(), "primary".to_string(), "verified".to_string()],
        attributes: {
            let mut attrs = HashMap::new();
            attrs.insert("full_name".to_string(), Value::String("John Doe".to_string()));
            attrs.insert("birth_date".to_string(), Value::String("1990-01-01".to_string()));
            attrs.insert("location".to_string(), Value::String("New York, NY".to_string()));
            attrs.insert("website".to_string(), Value::String("https://johndoe.com".to_string()));
            attrs
        },
        active: true,
        created: "2024-01-15 10:30:00".to_string(),
        modified: "2024-01-20 14:45:00".to_string(),
        last_used: Some("2024-01-22 09:15:00".to_string()),
        usage_count: 42,
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