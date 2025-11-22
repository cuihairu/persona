use anyhow::{anyhow, Result};
use clap::Args;
use colored::*;
use serde::{Serialize};
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
    println!("{}", "📋 Listing identities...".cyan().bold());
    println!();

    // Fetch identities from database
    let mut identities = fetch_identities(config).await?;

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

async fn fetch_identities(config: &CliConfig) -> Result<Vec<Identity>> {
    use dialoguer::Password;
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
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
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

fn sort_identities(identities: &mut Vec<Identity>, sort_by: &str, reverse: bool) -> Result<()> {
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
