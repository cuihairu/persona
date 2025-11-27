use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde_json::Value;
use std::collections::HashMap;

use crate::config::CliConfig;
use persona_core::{
    models::{Identity as CoreIdentity, IdentityType},
    storage::IdentityRepository,
    Database, PersonaService,
};
use uuid::Uuid;

#[derive(Args)]
pub struct EditArgs {
    /// Identity name to edit
    name: String,

    /// New identity type
    #[arg(long)]
    identity_type: Option<String>,

    /// New description
    #[arg(long)]
    description: Option<String>,

    /// New email address
    #[arg(long)]
    email: Option<String>,

    /// New phone number
    #[arg(long)]
    phone: Option<String>,

    /// Interactive editing mode
    #[arg(short, long)]
    interactive: bool,

    /// Edit specific field only
    #[arg(long)]
    field: Option<String>,

    /// New value for the field
    #[arg(long)]
    value: Option<String>,
}

pub async fn execute(args: EditArgs, config: &CliConfig) -> Result<()> {
    println!(
        "{} Editing identity '{}'...",
        "✏️".to_string(),
        args.name.bright_cyan().bold()
    );
    println!();

    // Check if identity exists
    if !identity_exists(&args.name, config).await? {
        anyhow::bail!("Identity '{}' not found", args.name);
    }

    // Load current identity data
    let mut identity = load_identity(&args.name, config).await?;

    // Show current values
    show_current_values(&identity)?;

    // Perform editing based on mode
    if args.interactive {
        edit_interactive(&mut identity)?;
    } else if let Some(field) = args.field {
        edit_single_field(&mut identity, &field, args.value)?;
    } else {
        edit_from_args(&mut identity, &args)?;
    }

    // Validate changes
    validate_identity(&identity)?;

    // Show changes summary
    show_changes_summary(&identity)?;

    // Confirm changes
    if !Confirm::new()
        .with_prompt("Save changes?")
        .default(true)
        .interact()?
    {
        println!("{}", "Changes discarded.".yellow());
        return Ok(());
    }

    // Save changes
    save_identity(&identity, config).await?;

    println!();
    println!(
        "{} Identity '{}' updated successfully!",
        "✓".green().bold(),
        identity.name.bright_green().bold()
    );

    Ok(())
}

#[derive(Debug, Clone)]
struct Identity {
    id: Option<Uuid>,
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
    attributes: HashMap<String, Value>,
    modified: String,
}

async fn identity_exists(name: &str, config: &CliConfig) -> Result<bool> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create service: {}", e))?;
    if service
        .has_users()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check users: {}", e))?
    {
        use dialoguer::Password;
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow::anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => Ok(service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .is_some()),
            _ => Ok(false),
        }
    } else {
        Ok(IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
            .is_some())
    }
}

async fn load_identity(name: &str, config: &CliConfig) -> Result<Identity> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create service: {}", e))?;
    let core: CoreIdentity = if service
        .has_users()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check users: {}", e))?
    {
        use dialoguer::Password;
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow::anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .with_context(|| format!("Identity '{}' not found", name))?,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
            .with_context(|| format!("Identity '{}' not found", name))?
    };

    Ok(Identity {
        id: Some(core.id),
        name: core.name,
        identity_type: core.identity_type.to_string(),
        description: core.description.unwrap_or_default(),
        email: core.email,
        phone: core.phone,
        tags: core.tags,
        attributes: core
            .attributes
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect(),
        modified: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

fn show_current_values(identity: &Identity) -> Result<()> {
    println!("{}", "Current values:".yellow().bold());
    println!("  {}: {}", "Name".dimmed(), identity.name.cyan());
    println!("  {}: {}", "Type".dimmed(), identity.identity_type.cyan());
    println!("  {}: {}", "Description".dimmed(), identity.description);

    if let Some(ref email) = identity.email {
        println!("  {}: {}", "Email".dimmed(), email.cyan());
    }

    if let Some(ref phone) = identity.phone {
        println!("  {}: {}", "Phone".dimmed(), phone.cyan());
    }

    if !identity.tags.is_empty() {
        println!(
            "  {}: {}",
            "Tags".dimmed(),
            identity.tags.join(", ").dimmed()
        );
    }

    if !identity.attributes.is_empty() {
        println!(
            "  {}: {} custom attributes",
            "Attributes".dimmed(),
            identity.attributes.len()
        );
    }

    println!();
    Ok(())
}

fn edit_interactive(identity: &mut Identity) -> Result<()> {
    let fields = vec![
        "Type",
        "Description",
        "Email",
        "Phone",
        "Tags",
        "Custom Attributes",
        "Done",
    ];

    loop {
        let selection = Select::new()
            .with_prompt("What would you like to edit?")
            .items(&fields)
            .interact()?;

        match selection {
            0 => edit_identity_type(identity)?,
            1 => edit_description(identity)?,
            2 => edit_email(identity)?,
            3 => edit_phone(identity)?,
            4 => edit_tags(identity)?,
            5 => edit_custom_attributes(identity)?,
            6 => break,
            _ => unreachable!(),
        }

        println!();
    }

    Ok(())
}

fn edit_single_field(identity: &mut Identity, field: &str, value: Option<String>) -> Result<()> {
    match field.to_lowercase().as_str() {
        "type" => {
            if let Some(new_type) = value {
                identity.identity_type = new_type;
            } else {
                edit_identity_type(identity)?;
            }
        }
        "description" => {
            if let Some(new_desc) = value {
                identity.description = new_desc;
            } else {
                edit_description(identity)?;
            }
        }
        "email" => {
            if let Some(new_email) = value {
                identity.email = if new_email.is_empty() {
                    None
                } else {
                    Some(new_email)
                };
            } else {
                edit_email(identity)?;
            }
        }
        "phone" => {
            if let Some(new_phone) = value {
                identity.phone = if new_phone.is_empty() {
                    None
                } else {
                    Some(new_phone)
                };
            } else {
                edit_phone(identity)?;
            }
        }
        _ => anyhow::bail!("Unknown field: {}", field),
    }

    Ok(())
}

fn edit_from_args(identity: &mut Identity, args: &EditArgs) -> Result<()> {
    if let Some(ref new_type) = args.identity_type {
        identity.identity_type = new_type.clone();
    }

    if let Some(ref new_desc) = args.description {
        identity.description = new_desc.clone();
    }

    if let Some(ref new_email) = args.email {
        identity.email = if new_email.is_empty() {
            None
        } else {
            Some(new_email.clone())
        };
    }

    if let Some(ref new_phone) = args.phone {
        identity.phone = if new_phone.is_empty() {
            None
        } else {
            Some(new_phone.clone())
        };
    }

    Ok(())
}

fn edit_identity_type(identity: &mut Identity) -> Result<()> {
    let types = vec![
        "personal",
        "work",
        "social",
        "gaming",
        "shopping",
        "financial",
        "healthcare",
        "education",
        "other",
    ];

    let current_index = types
        .iter()
        .position(|&t| t == identity.identity_type)
        .unwrap_or(0);

    let selection = Select::new()
        .with_prompt("Select identity type")
        .items(&types)
        .default(current_index)
        .interact()?;

    identity.identity_type = types[selection].to_string();
    println!(
        "{} Type updated to: {}",
        "✓".green(),
        identity.identity_type.cyan()
    );

    Ok(())
}

fn edit_description(identity: &mut Identity) -> Result<()> {
    let new_description: String = Input::new()
        .with_prompt("Description")
        .with_initial_text(&identity.description)
        .interact_text()?;

    identity.description = new_description;
    println!("{} Description updated", "✓".green());

    Ok(())
}

fn edit_email(identity: &mut Identity) -> Result<()> {
    let current_email = identity.email.as_deref().unwrap_or("");
    let new_email: String = Input::new()
        .with_prompt("Email (leave empty to remove)")
        .with_initial_text(current_email)
        .allow_empty(true)
        .interact_text()?;

    identity.email = if new_email.is_empty() {
        None
    } else {
        Some(new_email)
    };
    println!("{} Email updated", "✓".green());

    Ok(())
}

fn edit_phone(identity: &mut Identity) -> Result<()> {
    let current_phone = identity.phone.as_deref().unwrap_or("");
    let new_phone: String = Input::new()
        .with_prompt("Phone (leave empty to remove)")
        .with_initial_text(current_phone)
        .allow_empty(true)
        .interact_text()?;

    identity.phone = if new_phone.is_empty() {
        None
    } else {
        Some(new_phone)
    };
    println!("{} Phone updated", "✓".green());

    Ok(())
}

fn edit_tags(identity: &mut Identity) -> Result<()> {
    let current_tags = identity.tags.join(", ");
    let new_tags: String = Input::new()
        .with_prompt("Tags (comma-separated)")
        .with_initial_text(&current_tags)
        .allow_empty(true)
        .interact_text()?;

    identity.tags = new_tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    println!("{} Tags updated", "✓".green());

    Ok(())
}

fn edit_custom_attributes(identity: &mut Identity) -> Result<()> {
    let actions = vec![
        "Add new attribute",
        "Edit existing attribute",
        "Remove attribute",
        "Done",
    ];

    loop {
        let selection = Select::new()
            .with_prompt("Attribute action")
            .items(&actions)
            .interact()?;

        match selection {
            0 => add_custom_attribute(identity)?,
            1 => edit_existing_attribute(identity)?,
            2 => remove_custom_attribute(identity)?,
            3 => break,
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn add_custom_attribute(identity: &mut Identity) -> Result<()> {
    let key: String = Input::new().with_prompt("Attribute name").interact_text()?;

    let value: String = Input::new()
        .with_prompt(&format!("Value for '{}'", key))
        .interact_text()?;

    identity
        .attributes
        .insert(key.clone(), Value::String(value));
    println!("{} Added attribute: {}", "✓".green(), key.cyan());

    Ok(())
}

fn edit_existing_attribute(identity: &mut Identity) -> Result<()> {
    if identity.attributes.is_empty() {
        println!("{}", "No custom attributes to edit".yellow());
        return Ok(());
    }

    let keys: Vec<String> = identity.attributes.keys().cloned().collect();
    let selection = Select::new()
        .with_prompt("Select attribute to edit")
        .items(&keys)
        .interact()?;

    let key = &keys[selection];
    let current_value = identity
        .attributes
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let new_value: String = Input::new()
        .with_prompt(&format!("New value for '{}'", key))
        .with_initial_text(current_value)
        .interact_text()?;

    identity
        .attributes
        .insert(key.clone(), Value::String(new_value));
    println!("{} Updated attribute: {}", "✓".green(), key.cyan());

    Ok(())
}

fn remove_custom_attribute(identity: &mut Identity) -> Result<()> {
    if identity.attributes.is_empty() {
        println!("{}", "No custom attributes to remove".yellow());
        return Ok(());
    }

    let keys: Vec<String> = identity.attributes.keys().cloned().collect();
    let selections = MultiSelect::new()
        .with_prompt("Select attributes to remove")
        .items(&keys)
        .interact()?;

    for &index in &selections {
        let key = &keys[index];
        identity.attributes.remove(key);
        println!("{} Removed attribute: {}", "✓".green(), key.cyan());
    }

    Ok(())
}

fn validate_identity(identity: &Identity) -> Result<()> {
    if identity.name.is_empty() {
        anyhow::bail!("Identity name cannot be empty");
    }

    if let Some(ref email) = identity.email {
        if !email.contains('@') || !email.contains('.') {
            anyhow::bail!("Invalid email format");
        }
    }

    if let Some(ref phone) = identity.phone {
        if phone.len() < 10 {
            anyhow::bail!("Phone number too short");
        }
    }

    Ok(())
}

fn show_changes_summary(identity: &Identity) -> Result<()> {
    println!();
    println!("{}", "Changes summary:".yellow().bold());
    println!("  Identity will be updated with new values");
    println!("  Modified timestamp: {}", identity.modified.dimmed());

    Ok(())
}

async fn save_identity(identity: &Identity, config: &CliConfig) -> Result<()> {
    use dialoguer::Password;
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create service: {}", e))?;
    if service
        .has_users()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check users: {}", e))?
    {
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow::anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }

    // Load current identity (by id if present)
    let mut current = if let Some(id) = identity.id {
        service
            .get_identity(&id)
            .await
            .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
            .with_context(|| format!("Identity not found by id {}", id))?
    } else {
        service
            .get_identity_by_name(&identity.name)
            .await
            .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
            .with_context(|| "Identity not found".to_string())?
    };

    // Apply changes
    current.name = identity.name.clone();
    current.identity_type = identity
        .identity_type
        .parse::<IdentityType>()
        .unwrap_or(IdentityType::Custom(identity.identity_type.clone()));
    current.description = if identity.description.is_empty() {
        None
    } else {
        Some(identity.description.clone())
    };
    current.email = identity.email.clone();
    current.phone = identity.phone.clone();
    current.tags = identity.tags.clone();
    current.attributes = identity
        .attributes
        .iter()
        .map(|(k, v)| {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                other => other.to_string(),
            };
            (k.clone(), s)
        })
        .collect();
    current.touch();

    service
        .update_identity(&current)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update identity: {}", e))?;
    Ok(())
}
