use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, MultiSelect};
use std::path::PathBuf;

use crate::config::CliConfig;
use crate::utils::file_crypto::encrypt_file_inplace;
use crate::utils::progress::create_progress_bar;
use dialoguer::Password;
use persona_core::Repository;
use persona_core::{Database, PersonaService};

#[derive(Args)]
pub struct ExportArgs {
    /// Identity names to export (leave empty for all)
    names: Vec<String>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Export format (json, yaml, csv)
    #[arg(short, long, default_value = "json")]
    format: String,

    /// Include sensitive data
    #[arg(long)]
    include_sensitive: bool,

    /// Encrypt exported data
    #[arg(short, long)]
    encrypt: bool,

    /// Compression level (0-9, 0=no compression)
    #[arg(long, default_value = "6")]
    compression: u8,

    /// Interactive selection mode
    #[arg(short, long)]
    interactive: bool,
}

pub async fn execute(args: ExportArgs, config: &CliConfig) -> Result<()> {
    println!("{}", "📤 Exporting identities...".cyan().bold());
    println!();

    // Determine which identities to export
    let identity_names = if args.interactive {
        select_identities_interactive(config).await?
    } else if args.names.is_empty() {
        get_all_identity_names(config).await?
    } else {
        validate_identity_names(&args.names, config).await?;
        args.names.clone()
    };

    if identity_names.is_empty() {
        println!("{}", "No identities to export.".yellow());
        return Ok(());
    }

    // Determine output file
    let output_path = determine_output_path(&args, &identity_names)?;

    // Show export summary
    show_export_summary(&identity_names, &output_path, &args)?;

    // Confirm export
    if !Confirm::new()
        .with_prompt("Proceed with export?")
        .default(true)
        .interact()?
    {
        println!("{}", "Export cancelled.".yellow());
        return Ok(());
    }

    // Warn about sensitive data
    if args.include_sensitive {
        println!();
        println!(
            "{}",
            "⚠️  Warning: Export will include sensitive data!"
                .red()
                .bold()
        );
        if !Confirm::new()
            .with_prompt("Are you sure you want to include sensitive data?")
            .default(false)
            .interact()?
        {
            println!("{}", "Export cancelled.".yellow());
            return Ok(());
        }
    }

    // Perform export
    perform_export(&identity_names, &output_path, &args, config).await?;

    println!();
    println!("{} Export completed successfully!", "✓".green().bold());
    println!(
        "  Output file: {}",
        output_path.display().to_string().cyan()
    );

    // Show file info
    show_export_info(&output_path)?;

    Ok(())
}

async fn select_identities_interactive(config: &CliConfig) -> Result<Vec<String>> {
    let all_identities = get_all_identity_names(config).await?;

    if all_identities.is_empty() {
        anyhow::bail!("No identities found to export");
    }

    let selections = MultiSelect::new()
        .with_prompt("Select identities to export")
        .items(&all_identities)
        .interact()?;

    Ok(selections
        .into_iter()
        .map(|i| all_identities[i].clone())
        .collect())
}

async fn get_all_identity_names(config: &CliConfig) -> Result<Vec<String>> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create service: {}", e))?;
    let items = if service
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
            .map_err(|e| anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => service
                .get_identities()
                .await
                .map_err(|e| anyhow!("Failed to fetch identities: {}", e))?,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        // If no users configured yet, read via repository
        persona_core::storage::IdentityRepository::new(db)
            .find_all()
            .await
            .map_err(|e| anyhow!("Failed to fetch identities: {}", e))?
    };
    Ok(items.into_iter().map(|i| i.name).collect())
}

async fn validate_identity_names(names: &[String], config: &CliConfig) -> Result<()> {
    let all_identities = get_all_identity_names(config).await?;

    for name in names {
        if !all_identities.contains(name) {
            anyhow::bail!("Identity '{}' not found", name);
        }
    }

    Ok(())
}

fn determine_output_path(args: &ExportArgs, identity_names: &[String]) -> Result<PathBuf> {
    if let Some(ref output) = args.output {
        return Ok(output.clone());
    }

    // Generate default filename
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = if identity_names.len() == 1 {
        format!(
            "persona_export_{}_{}.{}",
            identity_names[0], timestamp, args.format
        )
    } else {
        format!(
            "persona_export_{}_{}.{}",
            identity_names.len(),
            timestamp,
            args.format
        )
    };

    Ok(PathBuf::from(filename))
}

fn show_export_summary(
    identity_names: &[String],
    output_path: &PathBuf,
    args: &ExportArgs,
) -> Result<()> {
    println!("{}", "Export Summary:".yellow().bold());
    println!(
        "  Identities: {} ({})",
        identity_names.len().to_string().cyan(),
        identity_names.join(", ").dimmed()
    );
    println!(
        "  Output file: {}",
        output_path.display().to_string().cyan()
    );
    println!("  Format: {}", args.format.cyan());
    println!(
        "  Include sensitive: {}",
        if args.include_sensitive {
            "Yes".red()
        } else {
            "No".green()
        }
    );
    println!(
        "  Encryption: {}",
        if args.encrypt {
            "Yes".green()
        } else {
            "No".dimmed()
        }
    );
    if args.compression > 0 {
        println!(
            "  Compression: Level {}",
            args.compression.to_string().cyan()
        );
    }
    println!();

    Ok(())
}

async fn perform_export(
    identity_names: &[String],
    output_path: &PathBuf,
    args: &ExportArgs,
    config: &CliConfig,
) -> Result<()> {
    let pb = create_progress_bar(identity_names.len() as u64, "Exporting identities");

    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create output directory")?;
    }

    // Export based on format
    match args.format.as_str() {
        "json" => export_json(identity_names, output_path, args, config, &pb).await?,
        "yaml" => export_yaml(identity_names, output_path, args, config, &pb).await?,
        "csv" => export_csv(identity_names, output_path, args, config, &pb).await?,
        _ => anyhow::bail!("Unsupported export format: {}", args.format),
    }

    pb.finish_with_message("Export completed");

    // Apply compression if requested
    if args.compression > 0 {
        compress_file(output_path, args.compression)?;
    }

    // Apply encryption if requested
    if args.encrypt {
        let passphrase = Password::new()
            .with_prompt("Enter export passphrase")
            .with_confirmation("Confirm passphrase", "Passphrases do not match")
            .interact()?;
        encrypt_file_inplace(output_path, &passphrase, None)?;
    }

    Ok(())
}

async fn export_json(
    identity_names: &[String],
    output_path: &PathBuf,
    args: &ExportArgs,
    config: &CliConfig,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    // Open service (may require unlock)
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create service: {}", e))?;
    let unlocked = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        let password = Password::new()
            .with_prompt("Enter master password to unlock (for credential export)")
            .interact()?;
        matches!(
            service
                .authenticate_user(&password)
                .await
                .map_err(|e| anyhow!("Auth failed: {}", e))?,
            persona_core::auth::authentication::AuthResult::Success
        )
    } else {
        true
    };

    let mut export_data = serde_json::json!({
        "export_info": {
            "version": "1.0",
            "created": chrono::Utc::now().to_rfc3339(),
            "identities_count": identity_names.len(),
            "include_sensitive": args.include_sensitive
        },
        "identities": []
    });

    for (i, name) in identity_names.iter().enumerate() {
        // Load identity detail
        let identity = if unlocked {
            service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
        } else {
            persona_core::storage::IdentityRepository::new(db.clone())
                .find_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
        }
        .with_context(|| format!("Identity '{}' not found", name))?;

        // Collect credentials metadata and optionally data
        let mut credentials_json = Vec::new();
        if unlocked {
            let creds = service
                .get_credentials_for_identity(&identity.id)
                .await
                .unwrap_or_default();
            for cred in creds {
                let mut entry = serde_json::json!({
                    "id": cred.id.to_string(),
                    "name": cred.name,
                    "type": cred.credential_type.to_string(),
                    "security_level": cred.security_level.to_string(),
                    "url": cred.url,
                    "username": cred.username,
                    "notes": cred.notes,
                    "tags": cred.tags,
                    "metadata": cred.metadata,
                    "created": cred.created_at.to_rfc3339(),
                    "updated": cred.updated_at.to_rfc3339(),
                    "last_accessed": cred.last_accessed.map(|d| d.to_rfc3339()),
                    "is_active": cred.is_active,
                    "is_favorite": cred.is_favorite,
                });
                if args.include_sensitive {
                    if let Some(data) = service
                        .get_credential_data(&cred.id)
                        .await
                        .map_err(|e| anyhow!("Failed to load credential data: {}", e))?
                    {
                        let json_data = serde_json::to_value(&data)
                            .unwrap_or(serde_json::json!({"raw": "unserializable"}));
                        entry
                            .as_object_mut()
                            .unwrap()
                            .insert("data".to_string(), json_data);
                    }
                } else {
                    // include encrypted bytes hex to allow offline re-import if needed
                    entry.as_object_mut().unwrap().insert(
                        "encrypted_data".to_string(),
                        serde_json::json!(hex::encode(&cred.encrypted_data)),
                    );
                }
                credentials_json.push(entry);
            }
        }

        let identity_data = serde_json::json!({
            "id": identity.id.to_string(),
            "name": identity.name,
            "type": identity.identity_type.to_string(),
            "description": identity.description,
            "email": identity.email,
            "phone": identity.phone,
            "tags": identity.tags,
            "attributes": identity.attributes,
            "active": identity.is_active,
            "created": identity.created_at.to_rfc3339(),
            "modified": identity.updated_at.to_rfc3339(),
            "credentials": credentials_json,
        });

        export_data["identities"]
            .as_array_mut()
            .unwrap()
            .push(identity_data);
        pb.set_position(i as u64 + 1);
    }

    let json_content = serde_json::to_string_pretty(&export_data)?;
    std::fs::write(output_path, json_content).context("Failed to write JSON export file")?;

    Ok(())
}

async fn export_yaml(
    identity_names: &[String],
    output_path: &PathBuf,
    args: &ExportArgs,
    config: &CliConfig,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    // First export as JSON, then convert to YAML
    let temp_json = output_path.with_extension("temp.json");
    export_json(identity_names, &temp_json, args, config, pb).await?;

    let json_content = std::fs::read_to_string(&temp_json)?;
    let json_value: serde_json::Value = serde_json::from_str(&json_content)?;
    let yaml_content = serde_yaml::to_string(&json_value)?;

    std::fs::write(output_path, yaml_content).context("Failed to write YAML export file")?;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_json);

    Ok(())
}

async fn export_csv(
    identity_names: &[String],
    output_path: &PathBuf,
    _args: &ExportArgs,
    config: &CliConfig,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create service: {}", e))?;
    if service
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
            .map_err(|e| anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }
    let mut csv_content = String::new();
    csv_content.push_str("Name,Type,Description,Email,Created,Modified\n");

    for (i, name) in identity_names.iter().enumerate() {
        let identity = service
            .get_identity_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
            .with_context(|| format!("Identity '{}' not found", name))?;
        csv_content.push_str(&format!(
            "{},{},{},{},{},{}\n",
            identity.name,
            identity.identity_type.to_string(),
            identity.description.unwrap_or_default().replace(',', " "),
            identity.email.unwrap_or_default(),
            identity.created_at.format("%Y-%m-%d %H:%M:%S"),
            identity.updated_at.format("%Y-%m-%d %H:%M:%S")
        ));

        pb.set_position(i as u64 + 1);
    }

    std::fs::write(output_path, csv_content).context("Failed to write CSV export file")?;

    Ok(())
}

fn compress_file(file_path: &PathBuf, level: u8) -> Result<()> {
    println!("{} Compressing file...", "🗜️".to_string());

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs::File;
    use std::io::Write;

    let src_path = file_path;
    let compressed_path = src_path.with_extension(format!(
        "{}.gz",
        src_path.extension().unwrap_or_default().to_string_lossy()
    ));

    let mut input = std::fs::read(src_path).context("Failed to read file for compression")?;
    let mut encoder = GzEncoder::new(
        File::create(&compressed_path).context("Failed to create gzip file")?,
        Compression::new(level.min(9) as u32),
    );
    encoder
        .write_all(&input)
        .context("Failed to write gzip data")?;
    encoder.finish().context("Failed to finish gzip")?;
    // Remove original
    std::fs::remove_file(src_path).ok();

    println!("{} File compressed (level {})", "✓".green(), level);
    Ok(())
}

// legacy helper removed; kept for back-compat if referenced

fn show_export_info(output_path: &PathBuf) -> Result<()> {
    if let Ok(metadata) = std::fs::metadata(output_path) {
        let file_size = crate::utils::format_file_size(metadata.len());
        println!("  File size: {}", file_size.cyan());
    }

    println!();
    println!("{}", "Next steps:".dimmed());
    println!("  • Share the export file securely");
    println!(
        "  • Import on another system: {}",
        "persona import <file>".cyan()
    );
    println!("  • Store backup safely");

    Ok(())
}
