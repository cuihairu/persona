use anyhow::{anyhow, Result};
use clap::Args;
use colored::*;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use tabled::{Table, Tabled};

use crate::config::CliConfig;
use persona_core::{Database, Identity as CoreIdentity, PersonaService, Repository};

#[derive(Args)]
pub struct ListArgs {
    /// Filter by identity type
    #[arg(short, long)]
    identity_type: Option<String>,

    /// Filter by tag
    #[arg(short, long)]
    tag: Option<String>,

    /// Search in names and descriptions
    #[arg(short, long)]
    search: Option<String>,

    /// Output format (table, json, yaml, csv)
    #[arg(short, long, default_value = "table")]
    format: String,

    /// Show detailed information
    #[arg(short, long)]
    detailed: bool,

    /// Show only active identity
    #[arg(long)]
    active_only: bool,

    /// Sort by field (name, type, created, modified)
    #[arg(long, default_value = "name")]
    sort_by: String,

    /// Reverse sort order
    #[arg(long)]
    reverse: bool,
}

#[derive(Debug, Tabled)]
struct IdentityRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Type")]
    identity_type: String,
    #[tabled(rename = "Email")]
    email: String,
    #[tabled(rename = "Phone")]
    phone: String,
    #[tabled(rename = "Active")]
    active: String,
    #[tabled(rename = "Created")]
    created: String,
}

#[derive(Debug, Tabled)]
struct DetailedIdentityRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Type")]
    identity_type: String,
    #[tabled(rename = "Description")]
    description: String,
    #[tabled(rename = "Email")]
    email: String,
    #[tabled(rename = "Phone")]
    phone: String,
    #[tabled(rename = "Tags")]
    tags: String,
    #[tabled(rename = "Active")]
    active: String,
    #[tabled(rename = "Created")]
    created: String,
    #[tabled(rename = "Modified")]
    modified: String,
}

pub async fn execute(args: ListArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: ListArgs,
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    println!("{}", "📋 Listing identities...".cyan().bold());
    println!();

    // Fetch identities from database
    let mut identities = fetch_identities(config, ui).await?;

    // Apply filters
    identities = apply_filters(identities, &args)?;

    // Sort identities
    sort_identities(&mut identities, &args.sort_by, args.reverse)?;

    if identities.is_empty() {
        println!("{}", "No identities found.".yellow());
        println!();
        println!("{}", "Create your first identity with:".dimmed());
        println!("  {}", "persona add".cyan());
        return Ok(());
    }

    // Display results
    match args.format.as_str() {
        "table" => display_table(&identities, args.detailed)?,
        "json" => display_json(&identities)?,
        "yaml" => display_yaml(&identities)?,
        "csv" => display_csv(&identities, args.detailed)?,
        _ => anyhow::bail!("Unsupported output format: {}", args.format),
    }

    // Show summary
    if !args.active_only {
        println!();
        show_summary(&identities)?;
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct Identity {
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
    active: bool,
    created: String,
    modified: String,
    attributes: HashMap<String, Value>,
}

async fn fetch_identities(
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<Vec<Identity>> {
    // Open DB
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to connect to database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let db_clone = db.clone();

    // Service
    let mut service = PersonaService::new(db)
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    let items: Vec<CoreIdentity> = if service
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
                .get_identities()
                .await
                .map_err(|e| anyhow!("Failed to fetch identities: {}", e))?,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        // Fallback: when no users set up, read directly via repository (data is not encrypted)
        let repo = persona_core::storage::IdentityRepository::new(db_clone);
        repo.find_all()
            .await
            .map_err(|e| anyhow!("Failed to read identities: {}", e))?
    };
    let mapped: Vec<Identity> = items
        .into_iter()
        .map(|id| Identity {
            name: id.name,
            identity_type: id.identity_type.to_string().to_lowercase(),
            description: id.description.unwrap_or_default(),
            email: id.email,
            phone: id.phone,
            tags: id.tags,
            active: id.is_active,
            created: id.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            modified: id.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            attributes: id
                .attributes
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect(),
        })
        .collect();
    Ok(mapped)
}

fn apply_filters(mut identities: Vec<Identity>, args: &ListArgs) -> Result<Vec<Identity>> {
    // Filter by active only
    if args.active_only {
        identities.retain(|id| id.active);
    }

    // Filter by identity type
    if let Some(ref filter_type) = args.identity_type {
        identities.retain(|id| {
            id.identity_type
                .to_lowercase()
                .contains(&filter_type.to_lowercase())
        });
    }

    // Filter by tag
    if let Some(ref filter_tag) = args.tag {
        identities.retain(|id| {
            id.tags
                .iter()
                .any(|tag| tag.to_lowercase().contains(&filter_tag.to_lowercase()))
        });
    }

    // Search filter
    if let Some(ref search_term) = args.search {
        let search_lower = search_term.to_lowercase();
        identities.retain(|id| {
            id.name.to_lowercase().contains(&search_lower)
                || id.description.to_lowercase().contains(&search_lower)
                || id.identity_type.to_lowercase().contains(&search_lower)
        });
    }

    Ok(identities)
}

fn sort_identities(identities: &mut [Identity], sort_by: &str, reverse: bool) -> Result<()> {
    match sort_by {
        "name" => identities.sort_by(|a, b| a.name.cmp(&b.name)),
        "type" => identities.sort_by(|a, b| a.identity_type.cmp(&b.identity_type)),
        "created" => identities.sort_by(|a, b| a.created.cmp(&b.created)),
        "modified" => identities.sort_by(|a, b| a.modified.cmp(&b.modified)),
        _ => anyhow::bail!("Invalid sort field: {}", sort_by),
    }

    if reverse {
        identities.reverse();
    }

    Ok(())
}

fn display_table(identities: &[Identity], detailed: bool) -> Result<()> {
    if detailed {
        let rows: Vec<DetailedIdentityRow> = identities
            .iter()
            .map(|id| DetailedIdentityRow {
                name: if id.active {
                    format!("{} {}", id.name, "●".green())
                } else {
                    id.name.clone()
                },
                identity_type: id.identity_type.clone(),
                description: truncate_string(&id.description, 30),
                email: id.email.as_deref().unwrap_or("-").to_string(),
                phone: id.phone.as_deref().unwrap_or("-").to_string(),
                tags: id.tags.join(", "),
                active: if id.active {
                    "Yes".green().to_string()
                } else {
                    "No".dimmed().to_string()
                },
                created: id.created.clone(),
                modified: id.modified.clone(),
            })
            .collect();

        let table = Table::new(rows);
        println!("{}", table);
    } else {
        let rows: Vec<IdentityRow> = identities
            .iter()
            .map(|id| IdentityRow {
                name: if id.active {
                    format!("{} {}", id.name, "●".green())
                } else {
                    id.name.clone()
                },
                identity_type: id.identity_type.clone(),
                email: id.email.as_deref().unwrap_or("-").to_string(),
                phone: id.phone.as_deref().unwrap_or("-").to_string(),
                active: if id.active {
                    "Yes".green().to_string()
                } else {
                    "No".dimmed().to_string()
                },
                created: id.created.clone(),
            })
            .collect();

        let table = Table::new(rows);
        println!("{}", table);
    }

    Ok(())
}

fn display_json(identities: &[Identity]) -> Result<()> {
    let json = serde_json::to_string_pretty(identities)?;
    println!("{}", json);
    Ok(())
}

fn display_yaml(identities: &[Identity]) -> Result<()> {
    let yaml = serde_yaml::to_string(identities)?;
    println!("{}", yaml);
    Ok(())
}

fn display_csv(identities: &[Identity], detailed: bool) -> Result<()> {
    if detailed {
        println!("Name,Type,Description,Email,Phone,Tags,Active,Created,Modified");
        for id in identities {
            println!(
                "{},{},{},{},{},{},{},{},{}",
                id.name,
                id.identity_type,
                id.description,
                id.email.as_deref().unwrap_or(""),
                id.phone.as_deref().unwrap_or(""),
                id.tags.join(";"),
                id.active,
                id.created,
                id.modified
            );
        }
    } else {
        println!("Name,Type,Email,Phone,Active,Created");
        for id in identities {
            println!(
                "{},{},{},{},{},{}",
                id.name,
                id.identity_type,
                id.email.as_deref().unwrap_or(""),
                id.phone.as_deref().unwrap_or(""),
                id.active,
                id.created
            );
        }
    }
    Ok(())
}

fn show_summary(identities: &[Identity]) -> Result<()> {
    let total = identities.len();
    let active_count = identities.iter().filter(|id| id.active).count();

    // Count by type
    let mut type_counts = HashMap::new();
    for identity in identities {
        *type_counts.entry(&identity.identity_type).or_insert(0) += 1;
    }

    println!("{}", "Summary:".yellow().bold());
    println!("  Total identities: {}", total.to_string().cyan());
    println!("  Active identities: {}", active_count.to_string().green());

    if !type_counts.is_empty() {
        println!("  By type:");
        for (identity_type, count) in type_counts {
            println!("    {}: {}", identity_type, count.to_string().cyan());
        }
    }

    Ok(())
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use persona_core::models::{Identity as CoreIdentityModel, IdentityType};
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

    #[allow(clippy::too_many_arguments)]
    fn args(
        identity_type: Option<&str>,
        tag: Option<&str>,
        search: Option<&str>,
        format: &str,
        detailed: bool,
        active_only: bool,
        sort_by: &str,
        reverse: bool,
    ) -> ListArgs {
        ListArgs {
            identity_type: identity_type.map(String::from),
            tag: tag.map(String::from),
            search: search.map(String::from),
            format: format.to_string(),
            detailed,
            active_only,
            sort_by: sort_by.to_string(),
            reverse,
        }
    }

    fn sample(name: &str, identity_type: &str, active: bool) -> Identity {
        Identity {
            name: name.to_string(),
            identity_type: identity_type.to_string(),
            description: String::new(),
            email: None,
            phone: None,
            tags: vec![],
            active,
            created: "2024-01-01 00:00:00".to_string(),
            modified: "2024-01-01 00:00:00".to_string(),
            attributes: HashMap::new(),
        }
    }

    /// Creates a migrated database in `dir` and inserts `n` identities.
    async fn seed_identities(dir: &TempDir, names: &[&str]) {
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = persona_core::storage::IdentityRepository::new(db);
        for name in names {
            repo.create(&CoreIdentityModel::new(
                name.to_string(),
                IdentityType::Personal,
            ))
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn list_formats_filters_and_empty_state_without_users() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identities(&dir, &["alice", "bob", "carol"]).await;

        // Every output format renders.
        for format in ["table", "json", "yaml", "csv"] {
            execute(
                args(None, None, None, format, false, false, "name", false),
                &config,
            )
            .await
            .unwrap_or_else(|e| panic!("format {} must work: {}", format, e));
        }

        // Detailed table and active-only both take their branches.
        execute(
            args(None, None, None, "table", true, true, "created", true),
            &config,
        )
        .await
        .unwrap();

        // Unsupported format fails.
        let err = execute(
            args(None, None, None, "xml", false, false, "name", false),
            &config,
        )
        .await
        .expect_err("unsupported format must fail");
        assert!(err.to_string().contains("Unsupported output format: xml"));

        // Invalid sort field fails.
        let err = execute(
            args(None, None, None, "json", false, false, "bogus", false),
            &config,
        )
        .await
        .expect_err("invalid sort must fail");
        assert!(err.to_string().contains("Invalid sort field: bogus"));

        // Empty database prints the hint instead of failing.
        let empty = TempDir::new().unwrap();
        execute(
            args(None, None, None, "table", false, false, "name", false),
            &config_for(&empty),
        )
        .await
        .expect("empty list must succeed");
    }

    #[tokio::test]
    async fn list_authenticated_path_rejects_wrong_and_accepts_right_password() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identities(&dir, &["dave"]).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }

        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let err = execute(
            args(None, None, None, "json", false, false, "name", false),
            &config,
        )
        .await
        .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        execute(
            args(None, None, None, "csv", false, false, "modified", false),
            &config,
        )
        .await
        .expect("correct password must list identities");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[test]
    fn apply_filters_narrows_by_type_tag_search_and_active() {
        let mut work = sample("alice", "personal", true);
        work.tags = vec!["work".to_string()];
        let home = sample("bob", "work", false);
        let mut described = sample("carol", "server", true);
        described.description = "production box".to_string();

        let base = vec![work, home, described];

        let by_type = apply_filters(
            base.clone(),
            &args(
                Some("work"),
                None,
                None,
                "table",
                false,
                false,
                "name",
                false,
            ),
        )
        .unwrap();
        assert_eq!(by_type.len(), 1);
        assert_eq!(by_type[0].name, "bob");

        let by_tag = apply_filters(
            base.clone(),
            &args(
                None,
                Some("work"),
                None,
                "table",
                false,
                false,
                "name",
                false,
            ),
        )
        .unwrap();
        assert_eq!(by_tag.len(), 1);
        assert_eq!(by_tag[0].name, "alice");

        let by_search = apply_filters(
            base.clone(),
            &args(
                None,
                None,
                Some("production"),
                "table",
                false,
                false,
                "name",
                false,
            ),
        )
        .unwrap();
        assert_eq!(by_search.len(), 1);
        assert_eq!(by_search[0].name, "carol");

        let active = apply_filters(
            base.clone(),
            &args(None, None, None, "table", false, true, "name", false),
        )
        .unwrap();
        assert_eq!(active.len(), 2);
        assert!(active.iter().all(|id| id.active));
    }

    #[test]
    fn sort_identities_orders_by_every_field_and_reverses() {
        let mut list = vec![
            sample("carol", "server", true),
            sample("alice", "personal", true),
        ];
        list[1].created = "2023-01-01 00:00:00".to_string();
        list[0].modified = "2025-01-01 00:00:00".to_string();

        sort_identities(&mut list, "name", false).unwrap();
        assert_eq!(list[0].name, "alice");

        sort_identities(&mut list, "type", false).unwrap();
        assert_eq!(list[0].identity_type, "personal");

        sort_identities(&mut list, "created", false).unwrap();
        assert_eq!(list[0].name, "alice"); // 2023 < 2024

        sort_identities(&mut list, "modified", false).unwrap();
        assert_eq!(list[0].name, "alice"); // 2024 < 2025

        sort_identities(&mut list, "name", true).unwrap();
        assert_eq!(list[0].name, "carol"); // reversed

        let err = sort_identities(&mut list, "bogus", false).unwrap_err();
        assert!(err.to_string().contains("Invalid sort field"));
    }

    #[test]
    fn truncate_string_respects_limit() {
        assert_eq!(truncate_string("short", 10), "short");
        let truncated = truncate_string("a-very-long-identity-name", 10);
        assert_eq!(truncated.len(), 10);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn detailed_rendering_covers_active_inactive_tags_and_csv() {
        let mut active = sample("ada", "personal", true);
        active.tags = vec!["ops".to_string(), "oncall".to_string()];
        active.description = "a description long enough to be truncated by the table".to_string();
        active.email = Some("ada@example.com".to_string());
        active.phone = Some("+49123456789".to_string());
        let inactive = sample("ben", "work", false);

        // Detailed and plain tables, with both an active and an inactive row.
        display_table(&[active.clone(), inactive.clone()], true).unwrap();
        display_table(&[active.clone(), inactive], false).unwrap();

        // CSV in both variants.
        display_csv(&[active.clone()], true).unwrap();
        display_csv(std::slice::from_ref(&active), false).unwrap();

        // Summary counts by type.
        show_summary(&[active]).unwrap();
    }
}
