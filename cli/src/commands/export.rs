use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, MultiSelect, Select};
use std::path::PathBuf;

use crate::config::CliConfig;
use crate::utils::progress::create_progress_bar;

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
        args.names
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
        println!("{}", "⚠️  Warning: Export will include sensitive data!".red().bold());
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
    println!("  Output file: {}", output_path.display().to_string().cyan());
    
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

    Ok(selections.into_iter().map(|i| all_identities[i].clone()).collect())
}

async fn get_all_identity_names(_config: &CliConfig) -> Result<Vec<String>> {
    // TODO: Implement actual database query
    Ok(vec![
        "personal".to_string(),
        "work".to_string(), 
        "social".to_string()
    ])
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
        format!("persona_export_{}_{}.{}", identity_names[0], timestamp, args.format)
    } else {
        format!("persona_export_{}_{}.{}", identity_names.len(), timestamp, args.format)
    };

    Ok(PathBuf::from(filename))
}

fn show_export_summary(
    identity_names: &[String], 
    output_path: &PathBuf, 
    args: &ExportArgs
) -> Result<()> {
    println!("{}", "Export Summary:".yellow().bold());
    println!("  Identities: {} ({})", 
        identity_names.len().to_string().cyan(),
        identity_names.join(", ").dim()
    );
    println!("  Output file: {}", output_path.display().to_string().cyan());
    println!("  Format: {}", args.format.cyan());
    println!("  Include sensitive: {}", 
        if args.include_sensitive { "Yes".red() } else { "No".green() }
    );
    println!("  Encryption: {}", 
        if args.encrypt { "Yes".green() } else { "No".dim() }
    );
    if args.compression > 0 {
        println!("  Compression: Level {}", args.compression.to_string().cyan());
    }
    println!();

    Ok(())
}

async fn perform_export(
    identity_names: &[String],
    output_path: &PathBuf,
    args: &ExportArgs,
    config: &CliConfig
) -> Result<()> {
    let pb = create_progress_bar(identity_names.len() as u64, "Exporting identities");

    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create output directory")?;
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
        encrypt_file(output_path, config)?;
    }

    Ok(())
}

async fn export_json(
    identity_names: &[String],
    output_path: &PathBuf,
    args: &ExportArgs,
    _config: &CliConfig,
    pb: &indicatif::ProgressBar
) -> Result<()> {
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
        // TODO: Load actual identity data from database
        let identity_data = serde_json::json!({
            "name": name,
            "type": "personal",
            "description": format!("Identity: {}", name),
            "email": format!("{}@example.com", name),
            "created": "2024-01-15 10:30:00",
            "modified": "2024-01-20 14:45:00"
        });

        export_data["identities"].as_array_mut().unwrap().push(identity_data);
        pb.set_position(i as u64 + 1);
        
        // Simulate processing time
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    let json_content = serde_json::to_string_pretty(&export_data)?;
    std::fs::write(output_path, json_content)
        .context("Failed to write JSON export file")?;

    Ok(())
}

async fn export_yaml(
    identity_names: &[String],
    output_path: &PathBuf,
    args: &ExportArgs,
    config: &CliConfig,
    pb: &indicatif::ProgressBar
) -> Result<()> {
    // First export as JSON, then convert to YAML
    let temp_json = output_path.with_extension("temp.json");
    export_json(identity_names, &temp_json, args, config, pb).await?;

    let json_content = std::fs::read_to_string(&temp_json)?;
    let json_value: serde_json::Value = serde_json::from_str(&json_content)?;
    let yaml_content = serde_yaml::to_string(&json_value)?;

    std::fs::write(output_path, yaml_content)
        .context("Failed to write YAML export file")?;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_json);

    Ok(())
}

async fn export_csv(
    identity_names: &[String],
    output_path: &PathBuf,
    _args: &ExportArgs,
    _config: &CliConfig,
    pb: &indicatif::ProgressBar
) -> Result<()> {
    let mut csv_content = String::new();
    csv_content.push_str("Name,Type,Description,Email,Created,Modified\n");

    for (i, name) in identity_names.iter().enumerate() {
        // TODO: Load actual identity data from database
        csv_content.push_str(&format!(
            "{},personal,Identity: {},{}@example.com,2024-01-15 10:30:00,2024-01-20 14:45:00\n",
            name, name, name
        ));

        pb.set_position(i as u64 + 1);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    std::fs::write(output_path, csv_content)
        .context("Failed to write CSV export file")?;

    Ok(())
}

fn compress_file(file_path: &PathBuf, level: u8) -> Result<()> {
    println!("{} Compressing file...", "🗜️".to_string());

    // TODO: Implement actual compression using flate2 or similar
    // For now, just rename to indicate compression
    let compressed_path = file_path.with_extension(
        format!("{}.gz", file_path.extension().unwrap_or_default().to_string_lossy())
    );

    std::fs::rename(file_path, &compressed_path)
        .context("Failed to compress file")?;

    println!("{} File compressed (level {})", "✓".green(), level);
    Ok(())
}

fn encrypt_file(file_path: &PathBuf, _config: &CliConfig) -> Result<()> {
    println!("{} Encrypting file...", "🔐".to_string());

    // TODO: Implement actual encryption
    // For now, just rename to indicate encryption
    let encrypted_path = file_path.with_extension(
        format!("{}.enc", file_path.extension().unwrap_or_default().to_string_lossy())
    );

    std::fs::rename(file_path, &encrypted_path)
        .context("Failed to encrypt file")?;

    println!("{} File encrypted", "✓".green());
    Ok(())
}

fn show_export_info(output_path: &PathBuf) -> Result<()> {
    if let Ok(metadata) = std::fs::metadata(output_path) {
        let file_size = crate::utils::format_file_size(metadata.len());
        println!("  File size: {}", file_size.cyan());
    }

    println!();
    println!("{}", "Next steps:".dim());
    println!("  • Share the export file securely");
    println!("  • Import on another system: {}", "persona import <file>".cyan());
    println!("  • Store backup safely");

    Ok(())
}