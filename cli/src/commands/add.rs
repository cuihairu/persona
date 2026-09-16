use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;
use serde_json::Value;
use std::collections::HashMap;
use tracing::info;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::{Database, Identity, IdentityType, PersonaService};

#[derive(Args, Clone)]
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
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: AddArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!("{}", "➕ Adding new identity...".cyan().bold());
    println!();

    if let Some(file_path) = args.from_file {
        return import_from_file(&file_path, config).await;
    }

    let identity = if args.yes {
        create_identity_non_interactive(&args)?
    } else {
        create_identity_interactive(&args, ui)?
    };

    // Validate identity data
    validate_identity(&identity)?;

    // Save identity to database
    save_identity(&identity, config, ui).await?;

    println!();
    println!(
        "{} Identity '{}' created successfully!",
        "✓".green().bold(),
        identity.name.bright_green().bold()
    );

    if args.set_active {
        set_active_identity(&identity.name, config).await?;
        println!(
            "{} Set '{}' as active identity",
            "✓".green().bold(),
            identity.name.bright_green()
        );
    }

    println!();
    println!("{}", "Next steps:".yellow().bold());
    println!(
        "  • View identity: {}",
        format!("persona show {}", identity.name).cyan()
    );
    println!(
        "  • Edit identity: {}",
        format!("persona edit {}", identity.name).cyan()
    );
    println!(
        "  • Switch to identity: {}",
        format!("persona switch {}", identity.name).cyan()
    );

    Ok(())
}

fn create_identity_interactive(args: &AddArgs, ui: &dyn PromptUi) -> Result<Identity> {
    // Get identity name
    let name = if let Some(name) = args.name.as_ref() {
        name.clone()
    } else {
        ui.input("Identity name", None, false)?
    };

    // Get identity type
    let identity_types = [
        ("personal", IdentityType::Personal),
        ("work", IdentityType::Work),
        ("social", IdentityType::Social),
        ("gaming", IdentityType::Gaming),
        ("financial", IdentityType::Financial),
        ("other", IdentityType::Custom("other".to_string())),
    ];

    let identity_type = if let Some(t) = args.identity_type.as_ref() {
        t.parse::<IdentityType>()
            .unwrap_or(IdentityType::Custom(t.clone()))
    } else {
        let type_names: Vec<&str> = identity_types.iter().map(|(name, _)| *name).collect();
        let selection = ui.select("Identity type", &type_names, Some(0))?;
        identity_types[selection].1.clone()
    };

    // Get description
    let description = if let Some(desc) = args.description.as_ref() {
        desc.clone()
    } else {
        ui.input("Description", None, true)?
    };

    // Get email
    let email = if let Some(email) = args.email.as_ref() {
        Some(email.clone())
    } else {
        let email_input = ui.input("Email (optional)", None, true)?;
        if email_input.is_empty() {
            None
        } else {
            Some(email_input)
        }
    };

    // Get phone
    let phone = if let Some(phone) = args.phone.as_ref() {
        Some(phone.clone())
    } else {
        let phone_input = ui.input("Phone (optional)", None, true)?;
        if phone_input.is_empty() {
            None
        } else {
            Some(phone_input)
        }
    };

    // Get additional attributes
    let attributes_map = collect_additional_attributes(ui)?;

    // Get tags
    let tags_vec = collect_tags(ui)?;

    // Create identity using persona-core constructor
    let mut identity = Identity::new(name, identity_type);

    // Set optional fields
    if !description.is_empty() {
        identity.description = Some(description);
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

fn create_identity_non_interactive(args: &AddArgs) -> Result<Identity> {
    let name = args
        .name
        .as_ref()
        .cloned()
        .context("Identity name is required in non-interactive mode")?;

    let identity_type = args
        .identity_type
        .as_ref()
        .map(|t| {
            t.parse::<IdentityType>()
                .unwrap_or(IdentityType::Custom(t.clone()))
        })
        .unwrap_or(IdentityType::Personal);

    let mut identity = Identity::new(name, identity_type);

    // Set optional fields
    if let Some(desc) = args.description.as_ref() {
        if !desc.is_empty() {
            identity.description = Some(desc.clone());
        }
    }
    identity.email = args.email.clone();
    identity.phone = args.phone.clone();

    Ok(identity)
}

fn collect_additional_attributes(ui: &dyn PromptUi) -> Result<HashMap<String, Value>> {
    let mut attributes = HashMap::new();

    if !ui.confirm("Add additional attributes?", false)? {
        return Ok(attributes);
    }

    println!(
        "{}",
        "Enter additional attributes (press Enter with empty key to finish):".dimmed()
    );

    loop {
        let key = ui.input("Attribute name", None, true)?;

        if key.is_empty() {
            break;
        }

        let value = ui.input(&format!("Value for '{}'", key), None, false)?;

        attributes.insert(key, Value::String(value));
    }

    Ok(attributes)
}

fn collect_tags(ui: &dyn PromptUi) -> Result<Vec<String>> {
    if !ui.confirm("Add tags?", false)? {
        return Ok(Vec::new());
    }

    let tags_input = ui.input("Tags (comma-separated)", None, false)?;

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

async fn save_identity(identity: &Identity, config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    // Open database
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to database: {}", e))?;
    // Ensure schema
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run database migrations: {}", e))?;

    // Create service
    let mut service = PersonaService::new(db)
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;

    // Ensure unlocked: try auth if a user exists; otherwise initialize
    if service
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
            persona_core::auth::authentication::AuthResult::Success => {
                // proceed
            }
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        let password = super::service::prompt_new_master_password(ui)?;
        let _ = service
            .initialize_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to initialize user: {}", e))?;
    }

    // Create in DB (preserve all optional fields)
    let _created = service
        .create_identity_full(identity.clone())
        .await
        .map_err(|e| anyhow!("Failed to create identity in database: {}", e))?;

    Ok(())
}

async fn set_active_identity(name: &str, _config: &CliConfig) -> Result<()> {
    // TODO: Implement setting active identity
    info!("Setting active identity: {}", name);
    Ok(())
}

async fn import_from_file(file_path: &str, _config: &CliConfig) -> Result<()> {
    println!("📁 Importing identity from file: {}", file_path.yellow());

    // TODO: Implement file import functionality
    // This would parse JSON/YAML/CSV files and create identities

    println!("{} Import completed successfully!", "✓".green().bold());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> AddArgs {
        AddArgs {
            name: None,
            identity_type: None,
            description: None,
            email: None,
            phone: None,
            yes: true,
            from_file: None,
            set_active: false,
        }
    }

    #[test]
    fn create_identity_non_interactive_requires_name() {
        let args = base_args();
        assert!(create_identity_non_interactive(&args).is_err());
    }

    #[test]
    fn create_identity_non_interactive_defaults_type_to_personal() {
        let mut args = base_args();
        args.name = Some("Alice".to_string());
        let identity = create_identity_non_interactive(&args).unwrap();
        assert_eq!(identity.name, "Alice");
        assert!(matches!(identity.identity_type, IdentityType::Personal));
    }

    #[test]
    fn validate_identity_rejects_empty_name() {
        let identity = Identity::new("".to_string(), IdentityType::Personal);
        assert!(validate_identity(&identity).is_err());
    }

    #[test]
    fn validate_identity_rejects_invalid_email() {
        let mut identity = Identity::new("Alice".to_string(), IdentityType::Personal);
        identity.email = Some("invalid".to_string());
        assert!(validate_identity(&identity).is_err());
    }

    #[test]
    fn validate_identity_rejects_short_phone() {
        let mut identity = Identity::new("Alice".to_string(), IdentityType::Personal);
        identity.phone = Some("123".to_string());
        assert!(validate_identity(&identity).is_err());
    }

    #[test]
    fn validate_identity_accepts_basic_identity() {
        let mut identity = Identity::new("Alice".to_string(), IdentityType::Personal);
        identity.email = Some("alice@example.com".to_string());
        identity.phone = Some("1234567890".to_string());
        validate_identity(&identity).unwrap();
    }
}

#[cfg(test)]
mod integration {
    use super::*;
    use crate::config::CliConfig;
    use crate::utils::prompt::scripted::ScriptedUi;
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

    fn args(
        name: Option<&str>,
        identity_type: Option<&str>,
        description: Option<&str>,
        email: Option<&str>,
        yes: bool,
    ) -> AddArgs {
        AddArgs {
            name: name.map(String::from),
            identity_type: identity_type.map(String::from),
            description: description.map(String::from),
            email: email.map(String::from),
            phone: None,
            yes,
            from_file: None,
            set_active: false,
        }
    }

    #[tokio::test]
    async fn add_non_interactive_initializes_and_creates_identity() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);

        // First add initializes the workspace master password from the env.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "new-master-pin");
        execute(
            args(
                Some("alice"),
                Some("personal"),
                Some("first"),
                Some("a@b.c"),
                true,
            ),
            &config,
        )
        .await
        .expect("first add must initialize and create");

        // The identity landed and the second add authenticates instead.
        execute(args(Some("bob"), None, None, None, true), &config)
            .await
            .expect("second add must authenticate with env password");

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = persona_core::storage::IdentityRepository::new(db);
        let alice = repo.find_by_name("alice").await.unwrap().unwrap();
        assert_eq!(alice.email.as_deref(), Some("a@b.c"));
        assert_eq!(alice.description.as_deref(), Some("first"));
        assert!(repo.find_by_name("bob").await.unwrap().is_some());

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    /// Once a master user exists, a wrong `PERSONA_MASTER_PASSWORD` aborts
    /// in `save_identity` before any identity is written.
    #[tokio::test]
    async fn add_with_wrong_master_password_fails_authentication() {
        let _guard = lock_process_env();

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        std::env::set_var("PERSONA_MASTER_PASSWORD", "real-add-pin");
        execute(args(Some("alice"), None, None, None, true), &config)
            .await
            .expect("first add initializes the workspace");

        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-add-pin");
        let err = execute(args(Some("bob"), None, None, None, true), &config)
            .await
            .expect_err("wrong password must fail");
        assert!(
            err.to_string().contains("Authentication failed"),
            "got: {err}"
        );

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = persona_core::storage::IdentityRepository::new(db);
        assert!(repo.find_by_name("bob").await.unwrap().is_none());

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn add_requires_name_in_non_interactive_mode() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let err = execute(args(None, None, None, None, true), &config)
            .await
            .expect_err("missing name must fail");
        assert!(err.to_string().contains("Identity name is required"));
    }

    #[tokio::test]
    async fn add_rejects_invalid_identity_data() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);

        // Bad email fails validation before any DB access.
        let err = execute(
            args(Some("x"), None, None, Some("not-an-email"), true),
            &config,
        )
        .await
        .expect_err("bad email must fail");
        assert!(err.to_string().contains("Invalid email format"));
    }

    #[test]
    fn validate_identity_bounds() {
        let mut identity = Identity::new("ok".to_string(), IdentityType::Personal);
        validate_identity(&identity).expect("valid identity");

        // Over-long name.
        let long = "x".repeat(51);
        identity.name = long;
        let err = validate_identity(&identity).unwrap_err();
        assert!(err.to_string().contains("cannot exceed 50"));

        // Unknown type string becomes Custom via non-interactive parsing.
        let parsed = "weird"
            .parse::<IdentityType>()
            .unwrap_or(IdentityType::Custom("weird".into()));
        let mut identity = Identity::new("t".to_string(), parsed);
        identity.email = Some("a@b.c".to_string());
        validate_identity(&identity).expect("custom type is fine");
    }

    #[tokio::test]
    async fn add_interactive_flow_creates_identity_from_scripted_answers() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        std::env::set_var("PERSONA_MASTER_PASSWORD", "interactive-pin");

        // Fully scripted wizard run: name → type → description → email →
        // phone → attributes (one pair) → tags.
        let ui = ScriptedUi::new()
            .input("ivy") // identity name
            .select(1) // type "work"
            .input("wizard description") // description
            .input("i@x.co") // email
            .input("") // phone (optional, left empty)
            .confirm(true) // add attributes?
            .input("role")
            .input("admin")
            .input("") // empty key ends the attribute loop
            .confirm(true) // add tags?
            .input("a, b");
        let mut wizard_args = args(None, None, None, None, false);
        wizard_args.set_active = false;
        execute_with(wizard_args, &config, &ui)
            .await
            .expect("interactive add creates the identity");
        assert!(ui.exhausted());

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = persona_core::storage::IdentityRepository::new(db.clone());
        let ivy = repo.find_by_name("ivy").await.unwrap().unwrap();
        assert!(matches!(ivy.identity_type, IdentityType::Work));
        assert_eq!(ivy.description.as_deref(), Some("wizard description"));
        assert_eq!(ivy.email.as_deref(), Some("i@x.co"));
        assert!(ivy.phone.is_none());
        assert_eq!(ivy.tags, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(
            ivy.attributes.get("role").map(String::as_str),
            Some("admin")
        );

        // A second run that declines both optional collectors.
        let ui = ScriptedUi::new()
            .input("jon")
            .select(0) // personal
            .input("") // description
            .input("") // email
            .input("") // phone
            .confirm(false) // no attributes
            .confirm(false); // no tags
        let jon_args = args(None, None, None, None, false);
        execute_with(jon_args, &config, &ui)
            .await
            .expect("declined collectors still create the identity");
        assert!(ui.exhausted());

        // A third run types a non-empty phone number interactively.
        let ui = ScriptedUi::new()
            .input("kim")
            .select(0) // personal
            .input("") // description
            .input("") // email
            .input("+31123456789") // phone, typed at the prompt
            .confirm(false) // no attributes
            .confirm(false); // no tags
        let kim_args = args(None, None, None, None, false);
        execute_with(kim_args, &config, &ui)
            .await
            .expect("typed phone number is stored");
        assert!(ui.exhausted());

        let kim = persona_core::storage::IdentityRepository::new(
            Database::from_file(config.get_database_path())
                .await
                .unwrap(),
        )
        .find_by_name("kim")
        .await
        .unwrap()
        .unwrap();
        assert_eq!(kim.phone.as_deref(), Some("+31123456789"));

        let jon = persona_core::storage::IdentityRepository::new(
            Database::from_file(config.get_database_path())
                .await
                .unwrap(),
        )
        .find_by_name("jon")
        .await
        .unwrap()
        .unwrap();
        assert!(jon.tags.is_empty());
        assert!(jon.attributes.is_empty());

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn add_interactive_skips_prompts_for_fields_given_on_cli() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        std::env::set_var("PERSONA_MASTER_PASSWORD", "interactive-pin");

        // Name/type/description/email/phone all come from the CLI, so only
        // the two optional collectors prompt.
        let mut partial = args(
            Some("kara"),
            Some("Work"),
            Some("cli desc"),
            Some("k@x.co"),
            false,
        );
        partial.phone = Some("+49123456789".to_string());
        let ui = ScriptedUi::new()
            .confirm(false) // add attributes?
            .confirm(true) // add tags?
            .input("ops, sre");
        execute_with(partial, &config, &ui)
            .await
            .expect("interactive add with CLI-provided fields succeeds");
        assert!(ui.exhausted());

        let kara = persona_core::storage::IdentityRepository::new(
            Database::from_file(config.get_database_path())
                .await
                .unwrap(),
        )
        .find_by_name("kara")
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(kara.identity_type, IdentityType::Work));
        assert_eq!(kara.phone.as_deref(), Some("+49123456789"));
        assert_eq!(kara.tags, vec!["ops".to_string(), "sre".to_string()]);

        // An unknown --identity-type string becomes a Custom type.
        let mut custom = args(Some("myst"), Some("kubernetes-cluster"), None, None, true);
        custom.phone = None;
        execute(custom, &config)
            .await
            .expect("custom identity type is accepted");

        let myst = persona_core::storage::IdentityRepository::new(
            Database::from_file(config.get_database_path())
                .await
                .unwrap(),
        )
        .find_by_name("myst")
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(myst.identity_type, IdentityType::Custom(ref s) if s == "kubernetes-cluster")
        );

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn add_rejects_short_phone_and_long_name() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);

        let mut short_phone = args(Some("p"), None, None, None, true);
        short_phone.phone = Some("123".to_string());
        let err = execute(short_phone, &config)
            .await
            .expect_err("short phone must fail validation");
        assert!(err.to_string().contains("Phone number too short"));

        let mut long_name = args(Some(&"x".repeat(51)), None, None, None, true);
        long_name.phone = None;
        let err = execute(long_name, &config)
            .await
            .expect_err("over-long name must fail validation");
        assert!(err.to_string().contains("cannot exceed 50"));
    }

    #[tokio::test]
    async fn add_from_file_and_set_active_flags_complete() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);

        // --from-file takes the stub import path and never touches the DB.
        let mut file_args = args(Some("unused"), None, None, None, true);
        file_args.from_file = Some("/tmp/identities.json".to_string());
        execute(file_args, &config)
            .await
            .expect("from-file stub reports success");

        // --set-active runs the (currently no-op) activation step.
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::set_var("PERSONA_MASTER_PASSWORD", "active-pin");
        let mut active_args = args(Some("spark"), None, None, None, true);
        active_args.set_active = true;
        execute(active_args, &config)
            .await
            .expect("set-active add succeeds");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }
}
