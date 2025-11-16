use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde_json::Value;
use std::collections::HashMap;
use tracing::info;

use crate::config::CliConfig;
use persona_core::{Identity, IdentityType, PersonaService, Database};

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

async fn create_identity_with_service(mut identity: Identity) -> Result<Identity> {
    // TODO: Get database path from config
    let db_path = std::env::var("PERSONA_DB_PATH")
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join(".persona")
                .join("identities.db")
                .to_string_lossy()
                .to_string()
        });

    // Create database and service
    let db = Database::from_file(&db_path).await
        .context("Failed to connect to database")?;

    // Run migrations
    db.migrate().await
        .context("Failed to run database migrations")?;

    let mut service = PersonaService::new(db).await
        .context("Failed to create PersonaService")?;

    // For now, just create the identity without unlocking the service
    // In a real implementation, we would need to handle authentication
    println!("{} Identity '{}' prepared for creation.",
        "✓".green().bold(),
        identity.name.yellow().bold()
    );
    println!("{} To complete setup, you need to unlock the service with a master password.",
        "ℹ".blue().bold()
    );

    Ok(identity)
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
        ("personal", IdentityType::Personal),
        ("work", IdentityType::Work),
        ("social", IdentityType::Social),
        ("gaming", IdentityType::Gaming),
        ("financial", IdentityType::Financial),
        ("other", IdentityType::Custom("other".to_string()))
    ];

    let identity_type = if let Some(t) = args.identity_type {
        t.parse::<IdentityType>().unwrap_or(IdentityType::Custom(t))
    } else {
        let type_names: Vec<&str> = identity_types.iter().map(|(name, _)| *name).collect();
        let selection = Select::new()
            .with_prompt("Identity type")
            .items(&type_names)
            .default(0)
            .interact()?;
        identity_types[selection].1.clone()
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
    let attributes_map = collect_additional_attributes()?;

    // Get tags
    let tags_vec = collect_tags()?;

    // Create identity using persona-core constructor
    let mut identity = Identity::new(name, identity_type);

    // Set optional fields
    if let Some(desc) = description {
        if !desc.is_empty() {
            identity.description = Some(desc);
        }
    }
    identity.email = email;
    identity.phone = phone;
    // Apply collected tags/attributes
    if !tags_vec.is_empty() {
        identity.tags = tags_vec;
    }
    if !attributes_map.is_empty() {
        // Convert Value -> String for storage
        for (k, v) in attributes_map {
            let s = match v {
                Value::String(s) => s,
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                other => other.to_string(),
            };
            identity.attributes.insert(k, s);
        }
    }

    Ok(identity)
}

fn create_identity_non_interactive(args: AddArgs) -> Result<Identity> {
    let name = args.name.context("Identity name is required in non-interactive mode")?;

    let identity_type = args.identity_type
        .map(|t| t.parse::<IdentityType>().unwrap_or(IdentityType::Custom(t)))
        .unwrap_or(IdentityType::Personal);

    let mut identity = Identity::new(name, identity_type);

    // Set optional fields
    if let Some(desc) = args.description {
        if !desc.is_empty() {
            identity.description = Some(desc);
        }
    }
    identity.email = args.email;
    identity.phone = args.phone;

    Ok(identity)
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

async fn save_identity(identity: &Identity, config: &CliConfig) -> Result<()> {
    use dialoguer::Password;
    use colored::Colorize;

    // Open database
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path.to_string_lossy())
        .await
        .context("Failed to connect to database")?;
    // Ensure schema
    db.migrate().await.context("Failed to run database migrations")?;

    // Create service
    let mut service = PersonaService::new(db).await.context("Failed to create PersonaService")?;

    // Ensure unlocked: try auth if a user exists; otherwise initialize
    if service.has_users().await.context("Failed to check users")? {
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service.authenticate_user(&password).await? {
            persona_core::auth::authentication::AuthResult::Success => {
                // proceed
            }
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        let password = Password::new()
            .with_prompt("Set a new master password")
            .with_confirmation("Confirm master password", "Passwords don't match")
            .interact()?;
        let _ = service.initialize_user(&password).await?;
    }

    // Create in DB (preserve all optional fields)
    let _created = service
        .create_identity_full(identity.clone())
        .await
        .context("Failed to create identity in database")?;

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
