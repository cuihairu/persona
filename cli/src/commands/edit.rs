use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use serde_json::Value;
use std::collections::HashMap;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
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
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: EditArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!(
        "✏️ Editing identity '{}'...",
        args.name.bright_cyan().bold()
    );
    println!();

    // Check if identity exists
    if !identity_exists(&args.name, config, ui).await? {
        anyhow::bail!("Identity '{}' not found", args.name);
    }

    // Load current identity data
    let mut identity = load_identity(&args.name, config, ui).await?;

    // Show current values
    show_current_values(&identity)?;

    // Perform editing based on mode
    if args.interactive {
        edit_interactive(&mut identity, ui)?;
    } else if let Some(field) = args.field {
        edit_single_field(&mut identity, &field, args.value, ui)?;
    } else {
        edit_from_args(&mut identity, &args)?;
    }

    // Validate changes
    validate_identity(&identity)?;

    // Show changes summary
    show_changes_summary(&identity)?;

    // Confirm changes
    if !ui.confirm("Save changes?", true)? {
        println!("{}", "Changes discarded.".yellow());
        return Ok(());
    }

    // Save changes
    save_identity(&identity, config, ui).await?;

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

async fn identity_exists(name: &str, config: &CliConfig, ui: &dyn PromptUi) -> Result<bool> {
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
        let password = super::service::prompt_master_password(ui)?;
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
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        Ok(IdentityRepository::new(db)
            .find_by_name(name)
            .await
            .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
            .is_some())
    }
}

async fn load_identity(name: &str, config: &CliConfig, ui: &dyn PromptUi) -> Result<Identity> {
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
        let password = super::service::prompt_master_password(ui)?;
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

fn edit_interactive(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let fields = [
        "Type",
        "Description",
        "Email",
        "Phone",
        "Tags",
        "Custom Attributes",
        "Done",
    ];

    loop {
        let selection = ui.select("What would you like to edit?", &fields, None)?;

        match selection {
            0 => edit_identity_type(identity, ui)?,
            1 => edit_description(identity, ui)?,
            2 => edit_email(identity, ui)?,
            3 => edit_phone(identity, ui)?,
            4 => edit_tags(identity, ui)?,
            5 => edit_custom_attributes(identity, ui)?,
            6 => break,
            _ => unreachable!(),
        }

        println!();
    }

    Ok(())
}

fn edit_single_field(
    identity: &mut Identity,
    field: &str,
    value: Option<String>,
    ui: &dyn PromptUi,
) -> Result<()> {
    match field.to_lowercase().as_str() {
        "type" => {
            if let Some(new_type) = value {
                identity.identity_type = new_type;
            } else {
                edit_identity_type(identity, ui)?;
            }
        }
        "description" => {
            if let Some(new_desc) = value {
                identity.description = new_desc;
            } else {
                edit_description(identity, ui)?;
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
                edit_email(identity, ui)?;
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
                edit_phone(identity, ui)?;
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

fn edit_identity_type(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let types = [
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

    let selection = ui.select("Select identity type", &types, Some(current_index))?;

    identity.identity_type = types[selection].to_string();
    println!(
        "{} Type updated to: {}",
        "✓".green(),
        identity.identity_type.cyan()
    );

    Ok(())
}

fn edit_description(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let new_description = ui.input("Description", Some(&identity.description), false)?;

    identity.description = new_description;
    println!("{} Description updated", "✓".green());

    Ok(())
}

fn edit_email(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let current_email = identity.email.as_deref().unwrap_or("");
    let new_email = ui.input("Email (leave empty to remove)", Some(current_email), true)?;

    identity.email = if new_email.is_empty() {
        None
    } else {
        Some(new_email)
    };
    println!("{} Email updated", "✓".green());

    Ok(())
}

fn edit_phone(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let current_phone = identity.phone.as_deref().unwrap_or("");
    let new_phone = ui.input("Phone (leave empty to remove)", Some(current_phone), true)?;

    identity.phone = if new_phone.is_empty() {
        None
    } else {
        Some(new_phone)
    };
    println!("{} Phone updated", "✓".green());

    Ok(())
}

fn edit_tags(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let current_tags = identity.tags.join(", ");
    let new_tags = ui.input("Tags (comma-separated)", Some(&current_tags), true)?;

    identity.tags = new_tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    println!("{} Tags updated", "✓".green());

    Ok(())
}

fn edit_custom_attributes(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let actions = [
        "Add new attribute",
        "Edit existing attribute",
        "Remove attribute",
        "Done",
    ];

    loop {
        let selection = ui.select("Attribute action", &actions, None)?;

        match selection {
            0 => add_custom_attribute(identity, ui)?,
            1 => edit_existing_attribute(identity, ui)?,
            2 => remove_custom_attribute(identity, ui)?,
            3 => break,
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn add_custom_attribute(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    let key = ui.input("Attribute name", None, false)?;

    let value = ui.input(&format!("Value for '{}'", key), None, false)?;

    identity
        .attributes
        .insert(key.clone(), Value::String(value));
    println!("{} Added attribute: {}", "✓".green(), key.cyan());

    Ok(())
}

fn edit_existing_attribute(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    if identity.attributes.is_empty() {
        println!("{}", "No custom attributes to edit".yellow());
        return Ok(());
    }

    let keys: Vec<String> = identity.attributes.keys().cloned().collect();
    let selection = ui.select(
        "Select attribute to edit",
        &keys.iter().map(String::as_str).collect::<Vec<_>>(),
        None,
    )?;

    let key = &keys[selection];
    let current_value = identity
        .attributes
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let new_value = ui.input(
        &format!("New value for '{}'", key),
        Some(current_value),
        false,
    )?;

    identity
        .attributes
        .insert(key.clone(), Value::String(new_value));
    println!("{} Updated attribute: {}", "✓".green(), key.cyan());

    Ok(())
}

fn remove_custom_attribute(identity: &mut Identity, ui: &dyn PromptUi) -> Result<()> {
    if identity.attributes.is_empty() {
        println!("{}", "No custom attributes to remove".yellow());
        return Ok(());
    }

    let keys: Vec<String> = identity.attributes.keys().cloned().collect();
    let selections = ui.multi_select(
        "Select attributes to remove",
        &keys.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;

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

async fn save_identity(identity: &Identity, config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
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
    let has_users = service
        .has_users()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check users: {}", e))?;
    if has_users {
        let password = super::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow::anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }

    // Load current identity (by id if present). Unencrypted, user-less
    // workspaces never unlock a service, so fall back to direct repository
    // reads like load/switch/remove do.
    let mut current = if has_users {
        if let Some(id) = identity.id {
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
        }
    } else {
        use persona_core::Repository;
        let repo = IdentityRepository::new(db.clone());
        if let Some(id) = identity.id {
            repo.find_by_id(&id)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .with_context(|| format!("Identity not found by id {}", id))?
        } else {
            repo.find_by_name(&identity.name)
                .await
                .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?
                .with_context(|| "Identity not found".to_string())?
        }
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

    if has_users {
        service
            .update_identity(&current)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to update identity: {}", e))?;
    } else {
        use persona_core::Repository;
        IdentityRepository::new(db)
            .update(&current)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to update identity: {}", e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
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

    fn sample_identity() -> Identity {
        Identity {
            id: Some(uuid::Uuid::new_v4()),
            name: "alice".to_string(),
            identity_type: "personal".to_string(),
            description: "old description".to_string(),
            email: Some("alice@example.com".to_string()),
            phone: None,
            tags: vec!["work".to_string()],
            attributes: HashMap::new(),
            modified: "2024-01-01 00:00:00".to_string(),
        }
    }

    /// Migrated database in `dir` with the named identities inserted.
    async fn seeded_db(dir: &TempDir, names: &[&str]) -> Database {
        use persona_core::Repository;
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        for name in names {
            repo.create(&CoreIdentity::new(name.to_string(), IdentityType::Personal))
                .await
                .unwrap();
        }
        db
    }

    #[tokio::test]
    async fn edit_rejects_missing_identity_before_prompts() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let args = EditArgs {
            name: "ghost".to_string(),
            identity_type: None,
            description: None,
            email: None,
            phone: None,
            interactive: false,
            field: None,
            value: None,
        };
        let err = execute(args, &config)
            .await
            .expect_err("missing identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));
    }

    #[test]
    fn single_field_edits_apply_and_clear_on_empty() {
        let mut identity = sample_identity();
        let ui = TerminalUi;

        edit_single_field(
            &mut identity,
            "email",
            Some("new@example.com".to_string()),
            &ui,
        )
        .unwrap();
        assert_eq!(identity.email.as_deref(), Some("new@example.com"));

        // An empty string clears the field.
        edit_single_field(&mut identity, "email", Some(String::new()), &ui).unwrap();
        assert!(identity.email.is_none());

        edit_single_field(
            &mut identity,
            "phone",
            Some("+49123456789".to_string()),
            &ui,
        )
        .unwrap();
        assert_eq!(identity.phone.as_deref(), Some("+49123456789"));
        edit_single_field(&mut identity, "phone", Some(String::new()), &ui).unwrap();
        assert!(identity.phone.is_none());

        edit_single_field(&mut identity, "description", Some("fresh".to_string()), &ui).unwrap();
        assert_eq!(identity.description, "fresh");

        edit_single_field(&mut identity, "type", Some("work".to_string()), &ui).unwrap();
        assert_eq!(identity.identity_type, "work");

        // Field matching is case-insensitive.
        edit_single_field(&mut identity, "DESCRIPTION", Some("upper".to_string()), &ui).unwrap();
        assert_eq!(identity.description, "upper");

        let err =
            edit_single_field(&mut identity, "bogus", Some("x".to_string()), &ui).unwrap_err();
        assert!(err.to_string().contains("Unknown field: bogus"));
    }

    #[test]
    fn single_field_without_value_prompts_interactively() {
        let mut identity = sample_identity();

        // `type` without a value opens the selection menu.
        let ui = ScriptedUi::new().select(3); // → "gaming"
        edit_single_field(&mut identity, "type", None, &ui).unwrap();
        assert_eq!(identity.identity_type, "gaming");

        // `email`/`phone`/`description` without a value open a text prompt.
        let ui = ScriptedUi::new().input("");
        edit_single_field(&mut identity, "email", None, &ui).unwrap();
        assert!(identity.email.is_none());

        let ui = ScriptedUi::new().input("+49123456789");
        edit_single_field(&mut identity, "phone", None, &ui).unwrap();
        assert_eq!(identity.phone.as_deref(), Some("+49123456789"));

        let ui = ScriptedUi::new().input("brand new");
        edit_single_field(&mut identity, "description", None, &ui).unwrap();
        assert_eq!(identity.description, "brand new");
    }

    #[test]
    fn edit_interactive_round_trip_with_scripted_answers() {
        let mut identity = sample_identity();

        // Outer menu: description → email → phone → tags → type →
        // custom attributes → done. Inside the attribute menu: add → edit →
        // remove → edit (empty early-return) → remove (empty early-return) →
        // done. Then the outer menu is closed with "Done".
        let ui = ScriptedUi::new()
            .select(1)
            .input("scripted description")
            .select(2)
            .input("") // clears the email
            .select(3)
            .input("+49123456789")
            .select(4)
            .input("a, b, c")
            .select(0)
            .select(1) // type menu → "work"
            .select(5)
            .select(0) // add attribute
            .input("role")
            .input("admin")
            .select(1) // edit existing attribute
            .select(0) // pick "role"
            .input("super-admin")
            .select(2) // remove attribute
            .multi_select(&[0])
            .select(1) // edit existing — list is empty again, early return
            .select(2) // remove attribute — list is empty again, early return
            .select(3) // done with attributes
            .select(6); // done with editor

        edit_interactive(&mut identity, &ui).unwrap();
        assert!(ui.exhausted());

        assert_eq!(identity.description, "scripted description");
        assert!(identity.email.is_none());
        assert_eq!(identity.phone.as_deref(), Some("+49123456789"));
        assert_eq!(identity.tags, vec!["a", "b", "c"]);
        assert_eq!(identity.identity_type, "work");
        // The attribute was added, edited, then removed again.
        assert!(identity.attributes.is_empty());
    }

    #[test]
    fn edit_from_args_applies_only_present_fields() {
        let mut identity = sample_identity();
        let args = EditArgs {
            name: identity.name.clone(),
            identity_type: Some("work".to_string()),
            description: Some("updated".to_string()),
            email: Some(String::new()),
            phone: Some("+491234567890".to_string()),
            interactive: false,
            field: None,
            value: None,
        };
        edit_from_args(&mut identity, &args).unwrap();
        assert_eq!(identity.identity_type, "work");
        assert_eq!(identity.description, "updated");
        assert!(identity.email.is_none());
        assert_eq!(identity.phone.as_deref(), Some("+491234567890"));

        // Non-empty email/phone keep their values (the Some(...) arm).
        let mut identity = sample_identity();
        identity.email = None;
        identity.phone = None;
        let args = EditArgs {
            name: identity.name.clone(),
            identity_type: None,
            description: None,
            email: Some("kept@example.com".to_string()),
            phone: Some("+49111222333".to_string()),
            interactive: false,
            field: None,
            value: None,
        };
        edit_from_args(&mut identity, &args).unwrap();
        assert_eq!(identity.email.as_deref(), Some("kept@example.com"));
        assert_eq!(identity.phone.as_deref(), Some("+49111222333"));
    }

    #[test]
    fn edit_identity_type_falls_back_to_first_option_for_unknown_types() {
        let mut identity = sample_identity();
        identity.identity_type = "custom-thing".to_string();

        // The current type is not in the menu, so the pre-selection falls
        // back to index 0 ("personal"); picking index 2 selects "social".
        let ui = ScriptedUi::new().select(2);
        edit_identity_type(&mut identity, &ui).unwrap();
        assert!(ui.exhausted());
        assert_eq!(identity.identity_type, "social");
    }

    #[test]
    fn show_current_values_prints_every_optional_section() {
        let mut identity = sample_identity();
        identity.phone = Some("+49123456789".to_string());
        identity
            .attributes
            .insert("role".to_string(), Value::String("admin".to_string()));

        // Rendering every optional section must not panic.
        show_current_values(&identity).unwrap();
    }

    #[tokio::test]
    async fn save_identity_without_id_resolves_by_name_and_coerces_values() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;

        let mut identity = sample_identity();
        identity.id = None; // force the by-name lookup branch
        identity.identity_type = "totally-custom".to_string(); // → IdentityType::Custom
        identity.description = String::new(); // empty description is stored as None
        identity.attributes.insert(
            "count".to_string(),
            Value::Number(serde_json::Number::from(42)),
        );
        identity
            .attributes
            .insert("on".to_string(), Value::Bool(true));
        identity
            .attributes
            .insert("nested".to_string(), serde_json::json!({"k": "v"}));
        identity
            .attributes
            .insert("plain".to_string(), Value::String("text".to_string()));

        save_identity(&identity, &config, &crate::utils::prompt::TerminalUi)
            .await
            .expect("save without id must succeed");

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let saved = IdentityRepository::new(db)
            .find_by_name("alice")
            .await
            .unwrap()
            .expect("identity still exists");
        assert!(matches!(
            saved.identity_type,
            IdentityType::Custom(ref s) if s == "totally-custom"
        ));
        assert_eq!(saved.description, None);
        assert_eq!(
            saved.attributes.get("count").map(String::as_str),
            Some("42")
        );
        assert_eq!(saved.attributes.get("on").map(String::as_str), Some("true"));
        assert_eq!(
            saved.attributes.get("nested").map(String::as_str),
            Some(r#"{"k":"v"}"#)
        );
        assert_eq!(
            saved.attributes.get("plain").map(String::as_str),
            Some("text")
        );
    }

    #[test]
    fn edit_from_args_empty_phone_clears_the_field() {
        let mut identity = sample_identity();
        identity.phone = Some("+49123456789".to_string());
        let args = EditArgs {
            name: identity.name.clone(),
            identity_type: None,
            description: None,
            email: None,
            phone: Some(String::new()),
            interactive: false,
            field: None,
            value: None,
        };
        edit_from_args(&mut identity, &args).unwrap();
        assert!(identity.phone.is_none());
    }

    #[test]
    fn edit_and_remove_existing_attributes_directly() {
        let mut identity = sample_identity();
        identity
            .attributes
            .insert("role".to_string(), Value::String("admin".to_string()));
        identity
            .attributes
            .insert("team".to_string(), Value::String("core".to_string()));

        // Edit the second key in insertion order and retype its value.
        let keys: Vec<String> = identity.attributes.keys().cloned().collect();
        let target = keys.iter().position(|k| k == "team").unwrap();
        let ui = ScriptedUi::new().select(target).input("platform");
        edit_existing_attribute(&mut identity, &ui).unwrap();
        assert!(ui.exhausted());
        assert_eq!(
            identity.attributes.get("team").and_then(|v| v.as_str()),
            Some("platform")
        );

        // Remove both attributes through the multi-select.
        let ui = ScriptedUi::new().multi_select(&[0, 1]);
        remove_custom_attribute(&mut identity, &ui).unwrap();
        assert!(ui.exhausted());
        assert!(identity.attributes.is_empty());
    }

    /// The interactive main menu reaches the custom-attributes submenu,
    /// edits one attribute there, and exits cleanly.
    #[test]
    fn edit_interactive_attributes_submenu_edits_and_exits() {
        let mut identity = sample_identity();
        identity
            .attributes
            .insert("role".to_string(), Value::String("admin".to_string()));

        // main: custom attributes → edit "role" → submenu done → main done.
        let ui = ScriptedUi::new()
            .select(5) // main menu: custom attributes
            .select(1) // submenu: edit existing attribute
            .select(0) // pick "role"
            .input("root")
            .select(3) // submenu: done
            .select(6); // main menu: done
        edit_interactive(&mut identity, &ui).unwrap();
        assert!(ui.exhausted());
        assert_eq!(
            identity.attributes.get("role").and_then(|v| v.as_str()),
            Some("root")
        );
    }

    /// Prompt failures inside the attribute helpers propagate (the `?` on
    /// each scripted prompt) without mutating the identity.
    #[test]
    fn attribute_edit_and_remove_propagate_prompt_errors() {
        let mut identity = sample_identity();
        identity
            .attributes
            .insert("role".to_string(), Value::String("admin".to_string()));

        let inner = ScriptedUi::new();
        let ui = FailOn::new(&inner, PromptKind::Select);
        let err = edit_existing_attribute(&mut identity, &ui).unwrap_err();
        assert!(err.to_string().contains("failing ui: select prompt"));

        let inner = ScriptedUi::new().select(0);
        let ui = FailOn::new(&inner, PromptKind::Input);
        let err = edit_existing_attribute(&mut identity, &ui).unwrap_err();
        assert!(err.to_string().contains("failing ui: input prompt"));

        let inner = ScriptedUi::new();
        let ui = FailOn::new(&inner, PromptKind::MultiSelect);
        let err = remove_custom_attribute(&mut identity, &ui).unwrap_err();
        assert!(err.to_string().contains("failing ui: multi-select prompt"));
        assert_eq!(
            identity.attributes.get("role").and_then(|v| v.as_str()),
            Some("admin")
        );
    }

    /// On a master-password workspace: a wrong password aborts the load, a
    /// correct one loads and saves through the authenticated service, and
    /// `save_identity` with no id resolves the row by name.
    #[tokio::test]
    async fn edit_auth_paths_cover_password_arms_and_name_lookup() {
        let _guard = lock_process_env();

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("edit-master").await.unwrap();
        }

        let args = |description: Option<&str>| EditArgs {
            name: "alice".to_string(),
            identity_type: None,
            description: description.map(str::to_string),
            email: None,
            phone: None,
            interactive: false,
            field: None,
            value: None,
        };

        // Wrong password aborts while loading the identity.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-edit-pin");
        let err = execute_with(
            args(Some("nope")),
            &config,
            &ScriptedUi::new().confirm(true),
        )
        .await
        .expect_err("wrong password must abort the edit");
        assert!(
            err.to_string().contains("Authentication failed"),
            "got: {err}"
        );

        // A direct save with the wrong password fails the same way.
        let mut ghost = sample_identity();
        ghost.name = "alice".to_string();
        ghost.id = None;
        let err = save_identity(&ghost, &config, &crate::utils::prompt::TerminalUi)
            .await
            .expect_err("wrong password must abort the save");
        assert!(
            err.to_string().contains("Authentication failed"),
            "got: {err}"
        );

        // The correct password unlocks, edits, and saves by name (no id).
        std::env::set_var("PERSONA_MASTER_PASSWORD", "edit-master");
        execute_with(
            args(Some("via auth")),
            &config,
            &ScriptedUi::new().confirm(true),
        )
        .await
        .expect("authenticated edit saves");

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let saved = IdentityRepository::new(db)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(saved.description.as_deref(), Some("via auth"));

        // A no-id identity saves through the by-name lookup arm.
        let mut no_id = sample_identity();
        no_id.id = None;
        no_id.name = "alice".to_string();
        no_id.description = "by name".to_string();
        save_identity(&no_id, &config, &crate::utils::prompt::TerminalUi)
            .await
            .expect("save by name through the authenticated service");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn save_identity_reports_missing_identity() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;

        let mut identity = sample_identity();
        identity.name = "ghost".to_string(); // no such identity
        let err = save_identity(&identity, &config, &crate::utils::prompt::TerminalUi)
            .await
            .expect_err("saving an unknown identity must fail");
        assert!(err.to_string().contains("Identity not found"));
    }

    #[test]
    fn validate_identity_checks_name_email_and_phone() {
        let mut identity = sample_identity();
        validate_identity(&identity).expect("valid identity");

        identity.name = String::new();
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("name cannot be empty"));
        identity.name = "alice".to_string();

        identity.email = Some("not-an-email".to_string());
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("Invalid email format"));
        identity.email = Some("a@b.c".to_string());

        identity.phone = Some("123".to_string());
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("Phone number too short"));
    }

    #[tokio::test]
    async fn edit_interactive_sets_and_clears_email_and_phone() {
        let mut identity = sample_identity();
        identity.email = None;
        identity.phone = None;

        // email → type a new address; phone → clear it (already empty).
        let ui = ScriptedUi::new()
            .select(2)
            .input("fresh@example.com")
            .select(3)
            .input("")
            .select(6); // done
        edit_interactive(&mut identity, &ui).unwrap();
        assert!(ui.exhausted());
        assert_eq!(identity.email.as_deref(), Some("fresh@example.com"));
        assert!(identity.phone.is_none());
    }

    #[tokio::test]
    async fn edit_end_to_end_without_users_covers_field_and_args_modes() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;

        let base = |field: Option<String>, value: Option<String>| EditArgs {
            name: "alice".to_string(),
            identity_type: None,
            description: None,
            email: None,
            phone: None,
            interactive: false,
            field,
            value,
        };

        // --field/--value path with an explicit confirmation.
        let ui = ScriptedUi::new().confirm(true);
        execute_with(
            base(
                Some("description".to_string()),
                Some("via field".to_string()),
            ),
            &config,
            &ui,
        )
        .await
        .expect("field edit saves");
        assert!(ui.exhausted());

        // Flag-based edit (--description/--email/--phone) with confirmation.
        let mut flag_args = base(None, None);
        flag_args.description = Some("via flags".to_string());
        flag_args.email = Some("flag@example.com".to_string());
        flag_args.phone = Some("+49123456789".to_string());
        let ui = ScriptedUi::new().confirm(true);
        execute_with(flag_args, &config, &ui)
            .await
            .expect("flag edit saves");
        assert!(ui.exhausted());

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let saved = IdentityRepository::new(db)
            .find_by_name("alice")
            .await
            .unwrap()
            .expect("alice still exists");
        assert_eq!(saved.email.as_deref(), Some("flag@example.com"));
        assert_eq!(saved.phone.as_deref(), Some("+49123456789"));

        // Declining the confirmation keeps the stored values.
        let ui = ScriptedUi::new().confirm(false);
        execute_with(
            base(
                Some("description".to_string()),
                Some("discarded".to_string()),
            ),
            &config,
            &ui,
        )
        .await
        .expect("declined edit returns success");
        assert!(ui.exhausted());

        // --field without a --value falls back to the interactive prompt.
        let ui = ScriptedUi::new().confirm(true).input("prompted desc");
        execute_with(base(Some("description".to_string()), None), &config, &ui)
            .await
            .expect("prompted field edit saves");
        assert!(ui.exhausted());

        // Unknown field names are rejected.
        let err = execute_with(
            base(Some("bogus".to_string()), Some("x".to_string())),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("unknown field must fail");
        assert!(err.to_string().contains("Unknown field: bogus"));
    }

    #[tokio::test]
    async fn edit_authentication_is_propagated() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }

        // Wrong password is reported instead of being treated as "not found".
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let args = EditArgs {
            name: "alice".to_string(),
            identity_type: None,
            description: None,
            email: None,
            phone: None,
            interactive: false,
            field: None,
            value: None,
        };
        let err = execute(args, &config)
            .await
            .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn edit_interactive_flow_saves_and_discards_through_execute() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
            service
                .create_identity_full(CoreIdentity::new(
                    "alice".to_string(),
                    IdentityType::Personal,
                ))
                .await
                .unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        let args = |interactive: bool| EditArgs {
            name: "alice".to_string(),
            identity_type: None,
            description: None,
            email: None,
            phone: None,
            interactive,
            field: None,
            value: None,
        };

        // Interactive mode: change the description, then confirm the save.
        let ui = ScriptedUi::new()
            .select(1) // edit description
            .input("saved via scripted ui")
            .select(6) // done
            .confirm(true); // save changes
        execute_with(args(true), &config, &ui)
            .await
            .expect("interactive edit saves");
        assert!(ui.exhausted());

        // The new description survives a round-trip through the database.
        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let alice = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .expect("alice exists");
        assert_eq!(alice.description.as_deref(), Some("saved via scripted ui"));
        drop(service);

        // Declining the save confirmation discards the changes.
        let ui = ScriptedUi::new()
            .select(1)
            .input("discarded edit")
            .select(6)
            .confirm(false); // discard
        execute_with(args(true), &config, &ui)
            .await
            .expect("discarding returns success");
        assert!(ui.exhausted());

        let service =
            crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
        let alice = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .expect("alice exists");
        assert_eq!(
            alice.description.as_deref(),
            Some("saved via scripted ui"),
            "discarded edit must not persist"
        );

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }
}
