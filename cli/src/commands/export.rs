use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, MultiSelect};
use std::path::{Path, PathBuf};

use crate::config::CliConfig;
use crate::utils::file_crypto::encrypt_file_inplace;
use crate::utils::progress::create_progress_bar;
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
        let password = super::service::prompt_master_password()?;
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
    output_path: &Path,
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
    output_path: &Path,
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
        let passphrase = super::service::prompt_payload_passphrase("export")?;
        encrypt_file_inplace(output_path, &passphrase, None)?;
    }

    Ok(())
}

async fn export_json(
    identity_names: &[String],
    output_path: &Path,
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
        let password = super::service::prompt_master_password()?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => true,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        // No users: the service is never unlocked; read via repository.
        false
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
        // Collect passkeys (metadata; private key only when allowed)
        let mut passkeys_json = Vec::new();
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

            // Collect passkeys (metadata; private key only when allowed)
            let passkeys = service
                .list_passkeys(&identity.id)
                .await
                .unwrap_or_default();
            for pk in passkeys {
                let mut entry = serde_json::json!({
                    "id": pk.id.to_string(),
                    "rp_id": pk.rp_id,
                    "rp_name": pk.rp_name,
                    "user_handle": hex::encode(&pk.user_handle),
                    "user_name": pk.user_name,
                    "user_display_name": pk.user_display_name,
                    "credential_id": hex::encode(&pk.credential_id),
                    "public_key_cose": hex::encode(&pk.public_key_cose),
                    "alg": pk.alg,
                    "uv_initialized": pk.uv_initialized,
                    "export_allowed": pk.export_allowed,
                    "created": pk.created_at.to_rfc3339(),
                    "last_used": pk.last_used_at.map(|d| d.to_rfc3339()),
                    "tags": pk.tags,
                });
                if args.include_sensitive {
                    if !pk.export_allowed {
                        eprintln!(
                            "⚠️  Passkey {} for {} is marked non-exportable; skipping private key",
                            pk.id, pk.rp_id
                        );
                    } else if let Ok(scalar) = service.export_passkey_private_key(&pk.id).await {
                        entry.as_object_mut().unwrap().insert(
                            "private_key".to_string(),
                            serde_json::json!(hex::encode(&scalar)),
                        );
                    } else {
                        eprintln!(
                            "⚠️  Could not export private key of passkey {} ({})",
                            pk.id, pk.rp_id
                        );
                    }
                }
                passkeys_json.push(entry);
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
            "passkeys": passkeys_json,
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
    output_path: &Path,
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
    output_path: &Path,
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
    let has_users = service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?;
    if has_users {
        let password = super::service::prompt_master_password()?;
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
        let identity = (if has_users {
            service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
        } else {
            persona_core::storage::IdentityRepository::new(db.clone())
                .find_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
        })
        .with_context(|| format!("Identity '{}' not found", name))?;
        csv_content.push_str(&format!(
            "{},{},{},{},{},{}\n",
            identity.name,
            identity.identity_type,
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

fn compress_file(file_path: &Path, level: u8) -> Result<()> {
    println!("🗜️ Compressing file...");

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs::File;
    use std::io::Write;

    let src_path = file_path;
    let compressed_path = src_path.with_extension(format!(
        "{}.gz",
        src_path.extension().unwrap_or_default().to_string_lossy()
    ));

    let input = std::fs::read(src_path).context("Failed to read file for compression")?;
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

fn show_export_info(output_path: &Path) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use persona_core::models::{Identity as CoreIdentityModel, IdentityType};
    use persona_core::storage::IdentityRepository;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the bridge and service tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK.lock().unwrap(),
            ENV_LOCK.lock().unwrap(),
        )
    }

    fn config_for(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    fn args(names: &[&str], format: &str) -> ExportArgs {
        ExportArgs {
            names: names.iter().map(|s| s.to_string()).collect(),
            output: None,
            format: format.to_string(),
            include_sensitive: false,
            encrypt: false,
            compression: 0,
            interactive: false,
        }
    }

    /// Migrated database with `names` identities inserted.
    async fn seeded_db(dir: &TempDir, names: &[&str]) -> Database {
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        for name in names {
            repo.create(&CoreIdentityModel::new(
                name.to_string(),
                IdentityType::Personal,
            ))
            .await
            .unwrap();
        }
        db
    }

    #[test]
    fn determine_output_path_variants() {
        let out = determine_output_path(
            &ExportArgs {
                output: Some(PathBuf::from("/tmp/out.json")),
                ..args(&["alice"], "json")
            },
            &["alice".to_string()],
        )
        .unwrap();
        assert_eq!(out, PathBuf::from("/tmp/out.json"));

        let single =
            determine_output_path(&args(&["alice"], "json"), &["alice".to_string()]).unwrap();
        let name = single.to_string_lossy();
        assert!(name.starts_with("persona_export_alice_"));
        assert!(name.ends_with(".json"));

        let multi = determine_output_path(
            &args(&["alice"], "json"),
            &["alice".to_string(), "bob".to_string(), "carol".to_string()],
        )
        .unwrap();
        let name = multi.to_string_lossy();
        assert!(name.starts_with("persona_export_3_"));
        assert!(name.ends_with(".json"));
    }

    #[tokio::test]
    async fn get_all_names_and_validation_without_users() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice", "bob"]).await;

        let all = get_all_identity_names(&config).await.unwrap();
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["alice".to_string(), "bob".to_string()]);

        validate_identity_names(&["alice".to_string()], &config)
            .await
            .expect("existing name validates");
        let err = validate_identity_names(&["ghost".to_string()], &config)
            .await
            .expect_err("unknown name must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));
    }

    #[test]
    fn compress_creates_gzip_and_removes_source() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("data.json");
        std::fs::write(&path, b"payload").unwrap();

        compress_file(&path, 6).unwrap();

        let gz = dir.path().join("data.json.gz");
        assert!(gz.exists(), "gzip file created");
        assert!(!path.exists(), "source removed");

        // Decompressing restores the payload.
        let f = std::fs::File::open(&gz).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(f);
        use std::io::Read;
        let mut restored = Vec::new();
        decoder.read_to_end(&mut restored).unwrap();
        assert_eq!(restored, b"payload");
    }

    #[tokio::test]
    async fn perform_export_rejects_unknown_format() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;
        let out = dir.path().join("out.xml");

        let err = perform_export(
            &["alice".to_string()],
            &out,
            &args(&["alice"], "xml"),
            &config,
        )
        .await
        .expect_err("unknown format must fail");
        assert!(err.to_string().contains("Unsupported export format: xml"));
    }

    #[tokio::test]
    async fn export_json_unencrypted_workspace_round_trip() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice", "bob"]).await;
        let out = dir.path().join("nested").join("out.json");

        perform_export(
            &["alice".to_string(), "bob".to_string()],
            &out,
            &args(&["alice", "bob"], "json"),
            &config,
        )
        .await
        .expect("json export must succeed");

        let content = std::fs::read_to_string(&out).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(value["export_info"]["identities_count"], 2);
        let names: Vec<&str> = value["identities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"alice"));
        assert!(names.contains(&"bob"));
    }

    #[tokio::test]
    async fn export_authenticated_path_with_master_password() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["carol"]).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }

        // Wrong password fails before any file is written.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let out = dir.path().join("carol.json");
        let err = perform_export(
            &["carol".to_string()],
            &out,
            &args(&["carol"], "json"),
            &config,
        )
        .await
        .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        // Correct password exports the identity.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        perform_export(
            &["carol".to_string()],
            &out,
            &args(&["carol"], "json"),
            &config,
        )
        .await
        .expect("correct password must export");
        let content = std::fs::read_to_string(&out).unwrap();
        assert!(content.contains("carol"));

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn export_yaml_and_csv_formats_without_users() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;

        let yaml_out = dir.path().join("out.yaml");
        perform_export(
            &["alice".to_string()],
            &yaml_out,
            &args(&["alice"], "yaml"),
            &config,
        )
        .await
        .expect("yaml export must succeed");
        let yaml = std::fs::read_to_string(&yaml_out).unwrap();
        assert!(yaml.contains("alice"), "yaml contains identity");

        let csv_out = dir.path().join("out.csv");
        perform_export(
            &["alice".to_string()],
            &csv_out,
            &args(&["alice"], "csv"),
            &config,
        )
        .await
        .expect("csv export must succeed");
        let csv = std::fs::read_to_string(&csv_out).unwrap();
        assert!(csv.starts_with("Name,Type,Description,Email,Created,Modified"));
        assert!(csv.contains("alice"));
    }
}

#[cfg(test)]
mod summary_tests {
    use super::*;
    use crate::config::CliConfig;
    use tempfile::TempDir;

    #[test]
    fn summary_and_info_render_without_state() {
        let dir = TempDir::new().unwrap();
        let config = CliConfig::default();
        let _ = config;

        let mut args = ExportArgs {
            names: vec!["alice".to_string(), "bob".to_string()],
            output: None,
            format: "json".to_string(),
            include_sensitive: true,
            encrypt: true,
            compression: 9,
            interactive: false,
        };
        args.compression = 9;
        let path = dir.path().join("out.json");
        std::fs::write(&path, "{}").unwrap();

        show_export_summary(&["alice".to_string(), "bob".to_string()], &path, &args).unwrap();
        show_export_info(&path).unwrap();
        // Missing files take the "no metadata" branch.
        show_export_info(&dir.path().join("missing.json")).unwrap();
    }
}
