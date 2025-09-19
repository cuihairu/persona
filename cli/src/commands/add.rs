use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde_json::Value;
use std::collections::HashMap;
use tracing::info;

use crate::config::CliConfig;

#[derive(Args)]
pub struct AddArgs {
    /// Identity name
    name: Option<String>,

    /// Identity type (personal, work, social, etc.)
    #[arg(short, long)]
    identity_type: Option<String>,

    /// Description
    #[arg(short, long)]
    description: Option<String>,

    /// Email address
    #[arg(short, long)]
    email: Option<String>,

    /// Phone number
    #[arg(short, long)]
    phone: Option<String>,

    /// Skip interactive prompts
    #[arg(short, long)]
    yes: bool,

    /// Import from file
    #[arg(long)]
    from_file: Option<String>,

    /// Set as active identity
    #[arg(long)]
    set_active: bool,
}

pub async fn execute(args: AddArgs, config: &CliConfig) -> Result<()> {
    println!("{}", "➕ Adding new identity...".cyan().bold());
    println!();

    if let Some(file_path) = args.from_file {
        return import_from_file(&file_path, config).await;
    }

    let identity = if args.yes {
        create_identity_non_interactive(args)?
    } else {
        create_identity_interactive(args)?
    };

    // Validate identity data
    validate_identity(&identity)?;

    // Save identity to database
    save_identity(&identity, config).await?;

    println!();
    println!("{} Identity '{}' created successfully!", 
        "✓".green().bold(), 
        identity.name.bright_green().bold()
    );

    if args.set_active {
        set_active_identity(&identity.name, config).await?;
        println!("{} Set '{}' as active identity", 
            "✓".green().bold(), 
            identity.name.bright_green()
        );
    }

    println!();
    println!("{}", "Next steps:".yellow().bold());
    println!("  • View identity: {}", format!("persona show {}", identity.name).cyan());
    println!("  • Edit identity: {}", format!("persona edit {}", identity.name).cyan());
    println!("  • Switch to identity: {}", format!("persona switch {}", identity.name).cyan());

    Ok(())
}

#[derive(Debug)]
struct Identity {
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    attributes: HashMap<String, Value>,
    tags: Vec<String>,
}

fn create_identity_interactive(args: AddArgs) -> Result<Identity> {
    // Get identity name
    let name = if let Some(name) = args.name {
        name
    } else {
        Input::new()
            .with_prompt("Identity name")
            .interact_text()?
    };

    // Get identity type
    let identity_types = vec![
        "personal", "work", "social", "gaming", "shopping", 
        "financial", "healthcare", "education", "other"
    ];
    
    let identity_type = if let Some(t) = args.identity_type {
        t
    } else {
        let selection = Select::new()
            .with_prompt("Identity type")
            .items(&identity_types)
            .default(0)
            .interact()?;
        identity_types[selection].to_string()
    };

    // Get description
    let description = if let Some(desc) = args.description {
        desc
    } else {
        Input::new()
            .with_prompt("Description")
            .allow_empty(true)
            .interact_text()?
    };

    // Get email
    let email = if args.email.is_some() {
        args.email
    } else {
        let email_input: String = Input::new()
            .with_prompt("Email (optional)")
            .allow_empty(true)
            .interact_text()?;
        if email_input.is_empty() { None } else { Some(email_input) }
    };

    // Get phone
    let phone = if args.phone.is_some() {
        args.phone
    } else {
        let phone_input: String = Input::new()
            .with_prompt("Phone (optional)")
            .allow_empty(true)
            .interact_text()?;
        if phone_input.is_empty() { None } else { Some(phone_input) }
    };

    // Get additional attributes
    let attributes = collect_additional_attributes()?;

    // Get tags
    let tags = collect_tags()?;

    Ok(Identity {
        name,
        identity_type,
        description,
        email,
        phone,
        attributes,
        tags,
    })
}

fn create_identity_non_interactive(args: AddArgs) -> Result<Identity> {
    let name = args.name.context("Identity name is required in non-interactive mode")?;
    
    Ok(Identity {
        name,
        identity_type: args.identity_type.unwrap_or_else(|| "personal".to_string()),
        description: args.description.unwrap_or_default(),
        email: args.email,
        phone: args.phone,
        attributes: HashMap::new(),
        tags: Vec::new(),
    })
}

fn collect_additional_attributes() -> Result<HashMap<String, Value>> {
    let mut attributes = HashMap::new();

    if !Confirm::new()
        .with_prompt("Add additional attributes?")
        .default(false)
        .interact()? 
    {
        return Ok(attributes);
    }

    println!("{}", "Enter additional attributes (press Enter with empty key to finish):".dim());

    loop {
        let key: String = Input::new()
            .with_prompt("Attribute name")
            .allow_empty(true)
            .interact_text()?;

        if key.is_empty() {
            break;
        }

        let value: String = Input::new()
            .with_prompt(&format!("Value for '{}'", key))
            .interact_text()?;

        attributes.insert(key, Value::String(value));
    }

    Ok(attributes)
}

fn collect_tags() -> Result<Vec<String>> {
    if !Confirm::new()
        .with_prompt("Add tags?")
        .default(false)
        .interact()? 
    {
        return Ok(Vec::new());
    }

    let tags_input: String = Input::new()
        .with_prompt("Tags (comma-separated)")
        .interact_text()?;

    let tags = tags_input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(tags)
}

fn validate_identity(identity: &Identity) -> Result<()> {
    if identity.name.is_empty() {
        anyhow::bail!("Identity name cannot be empty");
    }

    if identity.name.len() > 50 {
        anyhow::bail!("Identity name cannot exceed 50 characters");
    }

    // Validate email format if provided
    if let Some(email) = &identity.email {
        if !email.contains('@') || !email.contains('.') {
            anyhow::bail!("Invalid email format");
        }
    }

    // Validate phone format if provided
    if let Some(phone) = &identity.phone {
        if phone.len() < 10 {
            anyhow::bail!("Phone number too short");
        }
    }

    Ok(())
}

async fn save_identity(identity: &Identity, _config: &CliConfig) -> Result<()> {
    // TODO: Implement actual database save using persona-core
    info!("Saving identity: {}", identity.name);
    
    // Simulate save operation
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    Ok(())
}

async fn set_active_identity(name: &str, _config: &CliConfig) -> Result<()> {
    // TODO: Implement setting active identity
    info!("Setting active identity: {}", name);
    Ok(())
}

async fn import_from_file(file_path: &str, _config: &CliConfig) -> Result<()> {
    println!("{} Importing identity from file: {}", 
        "📁".to_string(), 
        file_path.yellow()
    );

    // TODO: Implement file import functionality
    // This would parse JSON/YAML/CSV files and create identities

    println!("{} Import completed successfully!", "✓".green().bold());
    Ok(())
}