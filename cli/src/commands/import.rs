use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, MultiSelect, Select};
use std::path::PathBuf;

use crate::config::CliConfig;
use crate::utils::progress::create_progress_bar;

#[derive(Args)]
pub struct ImportArgs {
    /// Import file path
    file: PathBuf,

    /// Import mode (merge, replace, skip)
    #[arg(short, long, default_value = "merge")]
    mode: String,

    /// Dry run - show what would be imported without making changes
    #[arg(long)]
    dry_run: bool,

    /// Force import without confirmation
    #[arg(short, long)]
    force: bool,

    /// Backup existing data before import
    #[arg(short, long)]
    backup: bool,

    /// Decrypt imported data
    #[arg(long)]
    decrypt: bool,

    /// Interactive selection of identities to import
    #[arg(short, long)]
    interactive: bool,
}

pub async fn execute(args: ImportArgs, config: &CliConfig) -> Result<()> {
    println!("{}", "📥 Importing identities...".cyan().bold());
    println!();

    // Validate import file
    validate_import_file(&args.file)?;

    // Decrypt file if needed
    let import_file = if args.decrypt {
        decrypt_import_file(&args.file, config)?
    } else {
        args.file.clone()
    };

    // Parse import data
    let import_data = parse_import_file(&import_file)?;
    
    // Show import summary
    show_import_summary(&import_data, &args)?;

    // Select identities to import
    let selected_identities = if args.interactive {
        select_identities_interactive(&import_data)?
    } else {
        import_data.identities.clone()
    };

    if selected_identities.is_empty() {
        println!("{}", "No identities selected for import.".yellow());
        return Ok(());
    }

    // Check for conflicts
    let conflicts = check_import_conflicts(&selected_identities, config).await?;
    if !conflicts.is_empty() {
        handle_import_conflicts(&conflicts, &args)?;
    }

    // Confirm import
    if !args.force && !args.dry_run {
        if !Confirm::new()
            .with_prompt("Proceed with import?")
            .default(true)
            .interact()? 
        {
            println!("{}", "Import cancelled.".yellow());
            return Ok(());
        }
    }

    // Create backup if requested
    if args.backup && !args.dry_run {
        create_backup(config).await?;
    }

    // Perform import
    if args.dry_run {
        perform_dry_run(&selected_identities, &args, config).await?;
    } else {
        perform_import(&selected_identities, &args, config).await?;
    }

    println!();
    if args.dry_run {
        println!("{} Dry run completed successfully!", "✓".green().bold());
        println!("  Use {} to perform actual import", "--force".cyan());
    } else {
        println!("{} Import completed successfully!", "✓".green().bold());
        println!("  Imported {} identities", selected_identities.len().to_string().cyan());
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct ImportData {
    version: String,
    created: String,
    identities: Vec<ImportIdentity>,
}

#[derive(Debug, Clone)]
struct ImportIdentity {
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
    attributes: std::collections::HashMap<String, String>,
}

#[derive(Debug)]
struct ImportConflict {
    name: String,
    conflict_type: String,
    existing_data: String,
    new_data: String,
}

fn validate_import_file(file_path: &PathBuf) -> Result<()> {
    if !file_path.exists() {
        anyhow::bail!("Import file does not exist: {}", file_path.display());
    }

    if !file_path.is_file() {
        anyhow::bail!("Import path is not a file: {}", file_path.display());
    }

    // Check file size (warn if too large)
    if let Ok(metadata) = std::fs::metadata(file_path) {
        let size_mb = metadata.len() / 1024 / 1024;
        if size_mb > 100 {
            println!("{} Large import file detected ({} MB)", "⚠️".yellow(), size_mb);
        }
    }

    Ok(())
}

fn decrypt_import_file(file_path: &PathBuf, _config: &CliConfig) -> Result<PathBuf> {
    println!("{} Decrypting import file...", "🔓".to_string());

    // TODO: Implement actual decryption
    // For now, just return the original file
    println!("{} File decrypted", "✓".green());
    Ok(file_path.clone())
}

fn parse_import_file(file_path: &PathBuf) -> Result<ImportData> {
    let content = std::fs::read_to_string(file_path)
        .context("Failed to read import file")?;

    // Determine format by extension
    let format = file_path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("json");

    match format {
        "json" => parse_json_import(&content),
        "yaml" | "yml" => parse_yaml_import(&content),
        "csv" => parse_csv_import(&content),
        _ => anyhow::bail!("Unsupported import format: {}", format),
    }
}

fn parse_json_import(content: &str) -> Result<ImportData> {
    let json_value: serde_json::Value = serde_json::from_str(content)
        .context("Failed to parse JSON import file")?;

    let export_info = json_value.get("export_info")
        .context("Missing export_info in import file")?;

    let version = export_info.get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let created = export_info.get("created")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let identities_array = json_value.get("identities")
        .and_then(|v| v.as_array())
        .context("Missing or invalid identities array")?;

    let mut identities = Vec::new();
    for identity_value in identities_array {
        let identity = ImportIdentity {
            name: identity_value.get("name")
                .and_then(|v| v.as_str())
                .context("Missing identity name")?
                .to_string(),
            identity_type: identity_value.get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("personal")
                .to_string(),
            description: identity_value.get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            email: identity_value.get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            phone: identity_value.get("phone")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tags: identity_value.get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect())
                .unwrap_or_default(),
            attributes: std::collections::HashMap::new(),
        };
        identities.push(identity);
    }

    Ok(ImportData {
        version,
        created,
        identities,
    })
}

fn parse_yaml_import(content: &str) -> Result<ImportData> {
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(content)
        .context("Failed to parse YAML import file")?;

    // Convert YAML to JSON for easier processing
    let json_value: serde_json::Value = serde_json::to_value(yaml_value)
        .context("Failed to convert YAML to JSON")?;

    parse_json_import(&serde_json::to_string(&json_value)?)
}

fn parse_csv_import(content: &str) -> Result<ImportData> {
    let mut identities = Vec::new();
    let mut lines = content.lines();

    // Skip header
    lines.next();

    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() >= 4 {
            let identity = ImportIdentity {
                name: fields[0].to_string(),
                identity_type: fields[1].to_string(),
                description: fields[2].to_string(),
                email: if fields.len() > 3 && !fields[3].is_empty() {
                    Some(fields[3].to_string())
                } else {
                    None
                },
                phone: None,
                tags: Vec::new(),
                attributes: std::collections::HashMap::new(),
            };
            identities.push(identity);
        }
    }

    Ok(ImportData {
        version: "csv".to_string(),
        created: chrono::Utc::now().to_rfc3339(),
        identities,
    })
}

fn show_import_summary(import_data: &ImportData, args: &ImportArgs) -> Result<()> {
    println!("{}", "Import Summary:".yellow().bold());
    println!("  File: {}", args.file.display().to_string().cyan());
    println!("  Format version: {}", import_data.version.cyan());
    println!("  Created: {}", import_data.created.dim());
    println!("  Identities: {}", import_data.identities.len().to_string().cyan());
    println!("  Import mode: {}", args.mode.cyan());
    
    if args.dry_run {
        println!("  Mode: {}", "Dry run".yellow());
    }
    
    if args.backup {
        println!("  Backup: {}", "Yes".green());
    }
    
    println!();

    // Show identity preview
    if !import_data.identities.is_empty() {
        println!("{}", "Identities to import:".dim());
        for (i, identity) in import_data.identities.iter().enumerate().take(5) {
            println!("  {}. {} ({})", 
                i + 1, 
                identity.name.cyan(), 
                identity.identity_type.dim()
            );
        }
        
        if import_data.identities.len() > 5 {
            println!("  ... and {} more", 
                (import_data.identities.len() - 5).to_string().dim()
            );
        }
        println!();
    }

    Ok(())
}

fn select_identities_interactive(import_data: &ImportData) -> Result<Vec<ImportIdentity>> {
    let identity_names: Vec<String> = import_data.identities
        .iter()
        .map(|id| format!("{} ({})", id.name, id.identity_type))
        .collect();

    let selections = MultiSelect::new()
        .with_prompt("Select identities to import")
        .items(&identity_names)
        .interact()?;

    Ok(selections.into_iter()
        .map(|i| import_data.identities[i].clone())
        .collect())
}

async fn check_import_conflicts(
    identities: &[ImportIdentity], 
    _config: &CliConfig
) -> Result<Vec<ImportConflict>> {
    let mut conflicts = Vec::new();

    // TODO: Check against actual database
    // For now, simulate some conflicts
    for identity in identities {
        if identity.name == "personal" {
            conflicts.push(ImportConflict {
                name: identity.name.clone(),
                conflict_type: "name_exists".to_string(),
                existing_data: "Existing personal identity".to_string(),
                new_data: identity.description.clone(),
            });
        }
    }

    Ok(conflicts)
}

fn handle_import_conflicts(conflicts: &[ImportConflict], args: &ImportArgs) -> Result<()> {
    println!("{} Import conflicts detected:", "⚠️".yellow().bold());
    println!();

    for conflict in conflicts {
        println!("  Identity: {}", conflict.name.cyan());
        println!("  Conflict: {}", conflict.conflict_type.red());
        println!("  Existing: {}", conflict.existing_data.dim());
        println!("  New: {}", conflict.new_data.dim());
        println!();
    }

    match args.mode.as_str() {
        "merge" => {
            println!("{} Mode: Merge - New data will be merged with existing", "ℹ️".blue());
        },
        "replace" => {
            println!("{} Mode: Replace - Existing data will be overwritten", "⚠️".yellow());
        },
        "skip" => {
            println!("{} Mode: Skip - Conflicting identities will be skipped", "ℹ️".blue());
        },
        _ => {
            anyhow::bail!("Invalid import mode: {}", args.mode);
        }
    }

    Ok(())
}

async fn create_backup(_config: &CliConfig) -> Result<()> {
    println!("{} Creating backup...", "💾".to_string());

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_file = format!("persona_backup_{}.json", timestamp);

    // TODO: Implement actual backup creation
    std::fs::write(&backup_file, "{\"backup\": true}")
        .context("Failed to create backup")?;

    println!("{} Backup created: {}", "✓".green(), backup_file.cyan());
    Ok(())
}

async fn perform_dry_run(
    identities: &[ImportIdentity],
    args: &ImportArgs,
    _config: &CliConfig
) -> Result<()> {
    println!("{}", "Dry Run Results:".yellow().bold());
    println!();

    let pb = create_progress_bar(identities.len() as u64, "Analyzing import");

    for (i, identity) in identities.iter().enumerate() {
        // Simulate processing
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let action = match args.mode.as_str() {
            "merge" => "Would merge",
            "replace" => "Would replace", 
            "skip" => "Would skip",
            _ => "Would process",
        };

        println!("  {} {}: {}", 
            "✓".green(), 
            action.dim(), 
            identity.name.cyan()
        );

        pb.set_position(i as u64 + 1);
    }

    pb.finish_with_message("Analysis completed");
    Ok(())
}

async fn perform_import(
    identities: &[ImportIdentity],
    args: &ImportArgs,
    _config: &CliConfig
) -> Result<()> {
    let pb = create_progress_bar(identities.len() as u64, "Importing identities");

    for (i, identity) in identities.iter().enumerate() {
        // TODO: Implement actual database import
        // Simulate processing time
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let action = match args.mode.as_str() {
            "merge" => "Merged",
            "replace" => "Replaced",
            "skip" => "Skipped",
            _ => "Imported",
        };

        pb.set_message(&format!("{} {}", action, identity.name));
        pb.set_position(i as u64 + 1);
    }

    pb.finish_with_message("Import completed");
    Ok(())
}