use anyhow::{anyhow, Context, Result};
use clap::Args;
use colored::*;
use std::path::{Path, PathBuf};

use crate::config::CliConfig;
use crate::utils::file_crypto::encrypt_file_inplace;
use crate::utils::progress::create_progress_bar;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::Database;
use persona_core::Repository;

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
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: ExportArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!("{}", "📤 Exporting identities...".cyan().bold());
    println!();

    // Determine which identities to export
    let identity_names = if args.interactive {
        select_identities_interactive(config, ui).await?
    } else if args.names.is_empty() {
        get_all_identity_names(config, ui).await?
    } else {
        validate_identity_names(&args.names, config, ui).await?;
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
    if !ui.confirm("Proceed with export?", true)? {
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
        if !ui.confirm("Are you sure you want to include sensitive data?", false)? {
            println!("{}", "Export cancelled.".yellow());
            return Ok(());
        }
    }

    // Perform export
    perform_export(&identity_names, &output_path, &args, config, ui).await?;

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

async fn select_identities_interactive(
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<Vec<String>> {
    let all_identities = get_all_identity_names(config, ui).await?;

    if all_identities.is_empty() {
        anyhow::bail!("No identities found to export");
    }

    let selections = ui.multi_select(
        "Select identities to export",
        &all_identities
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;

    Ok(selections
        .into_iter()
        .map(|i| all_identities[i].clone())
        .collect())
}

async fn get_all_identity_names(config: &CliConfig, ui: &dyn PromptUi) -> Result<Vec<String>> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create service: {}", e))?;
    let items = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        let password = super::service::prompt_master_password(ui)?;
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

async fn validate_identity_names(
    names: &[String],
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let all_identities = get_all_identity_names(config, ui).await?;

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
    ui: &dyn PromptUi,
) -> Result<()> {
    let pb = create_progress_bar(identity_names.len() as u64, "Exporting identities");

    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create output directory")?;
    }

    // Export based on format
    match args.format.as_str() {
        "json" => export_json(identity_names, output_path, args, config, ui, &pb).await?,
        "yaml" => export_yaml(identity_names, output_path, args, config, ui, &pb).await?,
        "csv" => export_csv(identity_names, output_path, args, config, ui, &pb).await?,
        _ => anyhow::bail!("Unsupported export format: {}", args.format),
    }

    pb.finish_with_message("Export completed");

    // Apply compression if requested
    if args.compression > 0 {
        compress_file(output_path, args.compression)?;
    }

    // Apply encryption if requested
    if args.encrypt {
        let passphrase = super::service::prompt_payload_passphrase("export", ui)?;
        encrypt_file_inplace(output_path, &passphrase, None)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn export_json(
    identity_names: &[String],
    output_path: &Path,
    args: &ExportArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
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
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create service: {}", e))?;
    let unlocked = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        let password = super::service::prompt_master_password(ui)?;
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
    ui: &dyn PromptUi,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    // First export as JSON, then convert to YAML
    let temp_json = output_path.with_extension("temp.json");
    export_json(identity_names, &temp_json, args, config, ui, pb).await?;

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
    ui: &dyn PromptUi,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create service: {}", e))?;
    let has_users = service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?;
    if has_users {
        let password = super::service::prompt_master_password(ui)?;
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
    use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
    use persona_core::auth::authentication::AuthResult;
    use persona_core::models::{
        ApiKeyData, CredentialData, CredentialType, Identity as CoreIdentityModel, IdentityType,
        PasswordCredentialData,
    };
    use persona_core::storage::{IdentityRepository, PasskeyRepository};
    use std::sync::Arc;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the bridge and service tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
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

        let all = get_all_identity_names(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["alice".to_string(), "bob".to_string()]);

        validate_identity_names(
            &["alice".to_string()],
            &config,
            &crate::utils::prompt::TerminalUi,
        )
        .await
        .expect("existing name validates");
        let err = validate_identity_names(
            &["ghost".to_string()],
            &config,
            &crate::utils::prompt::TerminalUi,
        )
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
            &crate::utils::prompt::TerminalUi,
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
            &crate::utils::prompt::TerminalUi,
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
            let mut service = crate::commands::service::new_service(db).await.unwrap();
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
            &crate::utils::prompt::TerminalUi,
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
            &crate::utils::prompt::TerminalUi,
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
            &crate::utils::prompt::TerminalUi,
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
            &crate::utils::prompt::TerminalUi,
        )
        .await
        .expect("csv export must succeed");
        let csv = std::fs::read_to_string(&csv_out).unwrap();
        assert!(csv.starts_with("Name,Type,Description,Email,Created,Modified"));
        assert!(csv.contains("alice"));
    }

    // ------------------------------------------------------------------
    // Helpers for the interactive/authenticated `execute_with` flows.
    // ------------------------------------------------------------------

    fn with_output(mut a: ExportArgs, out: &Path) -> ExportArgs {
        a.output = Some(out.to_path_buf());
        a
    }

    /// Workspace with an initialized user; identities `alice`/`bob` exist.
    async fn authenticated_workspace(dir: &TempDir, master: &str) -> CliConfig {
        let config = config_for(dir);
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        for name in ["alice", "bob"] {
            repo.create(&CoreIdentityModel::new(
                name.to_string(),
                IdentityType::Personal,
            ))
            .await
            .unwrap();
        }
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user(master).await.unwrap();
        config
    }

    /// Unlock a fresh service and attach one password + one API-key
    /// credential to `alice`. Returns their ids.
    async fn seed_credentials(config: &CliConfig, master: &str) -> (uuid::Uuid, uuid::Uuid) {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        assert!(matches!(
            service.authenticate_user(master).await.unwrap(),
            AuthResult::Success
        ));
        let identity = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();

        let login = service
            .create_credential(
                identity.id,
                "Web login".to_string(),
                CredentialType::Password,
                persona_core::models::SecurityLevel::High,
                &CredentialData::Password(PasswordCredentialData {
                    password: "s3cret!".to_string(),
                    email: Some("alice@example.com".to_string()),
                    security_questions: Vec::new(),
                }),
            )
            .await
            .unwrap();
        let token = service
            .create_credential(
                identity.id,
                "API token".to_string(),
                CredentialType::ApiKey,
                persona_core::models::SecurityLevel::Medium,
                &CredentialData::ApiKey(ApiKeyData {
                    api_key: "key-123".to_string(),
                    api_secret: None,
                    token: None,
                    permissions: Vec::new(),
                    expires_at: None,
                }),
            )
            .await
            .unwrap();
        (login.id, token.id)
    }

    fn passkey_client_data() -> Vec<u8> {
        br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#
            .to_vec()
    }

    /// Attach a passkey to `alice`; `export_allowed` controls whether the
    /// export is allowed to carry its private key.
    async fn seed_passkey(config: &CliConfig, master: &str, export_allowed: bool) -> uuid::Uuid {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db.clone())
            .await
            .unwrap();
        assert!(matches!(
            service.authenticate_user(master).await.unwrap(),
            AuthResult::Success
        ));
        let identity = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let pk = service
            .create_passkey(
                identity.id,
                "example.com".to_string(),
                "https://example.com",
                &passkey_client_data(),
                None,
                Some("alice".to_string()),
                Some("Alice Example".to_string()),
                false,
            )
            .await
            .unwrap();

        if !export_allowed {
            let repo = PasskeyRepository::new(Arc::new(db));
            let mut item = repo.find_by_id(&pk.id).await.unwrap().unwrap();
            item.export_allowed = false;
            repo.update(&item).await.unwrap();
        }
        pk.id
    }

    // ------------------------------------------------------------------
    // execute_with: confirmation gates and identity selection.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn execute_with_json_export_respects_confirm_gate() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;
        let out = dir.path().join("out.json");

        // Declining the confirmation writes nothing.
        let ui = ScriptedUi::new().confirm(false);
        execute_with(with_output(args(&["alice"], "json"), &out), &config, &ui)
            .await
            .expect("cancelling returns success");
        assert!(ui.exhausted());
        assert!(!out.exists(), "cancelled export must not write the file");

        // Accepting writes the file.
        let ui = ScriptedUi::new().confirm(true);
        execute_with(with_output(args(&["alice"], "json"), &out), &config, &ui)
            .await
            .expect("confirmed export succeeds");
        assert!(ui.exhausted());
        let content = std::fs::read_to_string(&out).unwrap();
        assert!(content.contains("alice"));
    }

    #[tokio::test]
    async fn execute_with_sensitive_gate_can_abort_or_proceed() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;
        let out = dir.path().join("sensitive.json");

        // The second (sensitive) confirmation can still abort.
        let mut a = with_output(args(&["alice"], "json"), &out);
        a.include_sensitive = true;
        let ui = ScriptedUi::new().confirm(true).confirm(false);
        execute_with(a, &config, &ui)
            .await
            .expect("aborting at the sensitive gate returns success");
        assert!(ui.exhausted());
        assert!(!out.exists(), "aborted sensitive export writes nothing");

        // Confirming both gates performs the export.
        let mut a = with_output(args(&["alice"], "json"), &out);
        a.include_sensitive = true;
        let ui = ScriptedUi::new().confirm(true).confirm(true);
        execute_with(a, &config, &ui)
            .await
            .expect("double-confirmed sensitive export succeeds");
        assert!(ui.exhausted());
        assert!(out.exists());
    }

    #[tokio::test]
    async fn execute_with_all_identities_and_interactive_selection() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice", "bob", "carol"]).await;
        let out = dir.path().join("all.json");

        // Empty names means "every identity"; no prompts before the confirm.
        let ui = ScriptedUi::new().confirm(true);
        execute_with(with_output(args(&[], "json"), &out), &config, &ui)
            .await
            .expect("exporting every identity succeeds");
        assert!(ui.exhausted());
        let content = std::fs::read_to_string(&out).unwrap();
        for name in ["alice", "bob", "carol"] {
            assert!(content.contains(name), "missing {name}");
        }

        // Interactive mode maps multi_select indices back to names.
        let out_selected = dir.path().join("selected.json");
        let ui = ScriptedUi::new().multi_select(&[0, 2]).confirm(true);
        let mut a = args(&[], "json");
        a.interactive = true;
        execute_with(with_output(a, &out_selected), &config, &ui)
            .await
            .expect("interactive selection exports the picked identities");
        assert!(ui.exhausted());
        let content = std::fs::read_to_string(&out_selected).unwrap();
        assert!(content.contains("alice"));
        assert!(content.contains("carol"));
        assert!(!content.contains("bob"), "unpicked identity stays out");

        // Selecting nothing reports there is nothing to export.
        let out_empty = dir.path().join("empty.json");
        let ui = ScriptedUi::new().multi_select(&[]);
        let mut a = args(&[], "json");
        a.interactive = true;
        execute_with(with_output(a, &out_empty), &config, &ui)
            .await
            .expect("empty selection returns success");
        assert!(ui.exhausted());
        assert!(!out_empty.exists());
    }

    #[tokio::test]
    async fn execute_with_unknown_identity_fails_before_any_prompt() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;

        let ui = ScriptedUi::new();
        let err = execute_with(
            with_output(args(&["ghost"], "json"), &dir.path().join("g.json")),
            &config,
            &ui,
        )
        .await
        .expect_err("unknown identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));
        assert!(ui.exhausted(), "validation fails before any prompt");
    }

    #[tokio::test]
    async fn execute_wrapper_bails_when_no_identities_exist() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);

        // The interactive selection path bails before any prompt when the
        // workspace has no identities at all, so the TerminalUi-backed entry
        // point is safe to exercise here.
        let mut a = args(&[], "json");
        a.interactive = true;
        let err = execute(a, &config)
            .await
            .expect_err("empty workspace must fail");
        assert!(err.to_string().contains("No identities found to export"));
    }

    // ------------------------------------------------------------------
    // execute_with: authenticated workspaces.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn authenticated_sensitive_export_includes_credentials_and_passkey() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = authenticated_workspace(&dir, "master-pin").await;
        seed_credentials(&config, "master-pin").await;
        seed_passkey(&config, "master-pin", true).await;

        let out = dir.path().join("alice.json");
        let mut a = with_output(args(&["alice"], "json"), &out);
        a.include_sensitive = true;
        // The unlock prompt is answered twice: once during name validation,
        // once inside the JSON exporter; include_sensitive adds a second
        // confirmation between them.
        let ui = ScriptedUi::new()
            .password("master-pin")
            .confirm(true)
            .confirm(true)
            .password("master-pin");
        execute_with(a, &config, &ui)
            .await
            .expect("authenticated sensitive export succeeds");
        assert!(ui.exhausted());

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let identities = value["identities"].as_array().unwrap();
        assert_eq!(identities.len(), 1);
        let creds = identities[0]["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 2, "both credentials exported");
        let login = creds
            .iter()
            .find(|c| c["name"] == "Web login")
            .expect("login credential present");
        assert!(
            login.get("data").is_some(),
            "sensitive export decrypts data"
        );
        assert!(login.get("encrypted_data").is_none());
        let token = creds
            .iter()
            .find(|c| c["name"] == "API token")
            .expect("api credential present");
        assert!(token.get("data").is_some());

        let passkeys = identities[0]["passkeys"].as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert!(
            passkeys[0].get("private_key").is_some(),
            "exportable passkey carries its private key"
        );
    }

    #[tokio::test]
    async fn authenticated_sensitive_export_warns_on_corrupt_passkey_key() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = authenticated_workspace(&dir, "master-pin").await;
        let pk_id = seed_passkey(&config, "master-pin", true).await;

        // Corrupt the sealed key material so unsealing fails at export time.
        // (The repository's update() does not persist key columns, so poke
        // the row directly.)
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            sqlx::query("UPDATE passkeys SET encrypted_private_key = $2 WHERE id = $1")
                .bind(pk_id.to_string())
                .bind(vec![0xDEu8, 0xAD, 0xBE, 0xEF])
                .execute(db.pool())
                .await
                .unwrap();
        }

        let out = dir.path().join("alice-corrupt.json");
        let mut a = with_output(args(&["alice"], "json"), &out);
        a.include_sensitive = true;
        let ui = ScriptedUi::new()
            .password("master-pin")
            .confirm(true)
            .confirm(true)
            .password("master-pin");
        execute_with(a, &config, &ui)
            .await
            .expect("export succeeds despite the corrupt passkey");
        assert!(ui.exhausted());

        // The metadata row survives; only the private key is skipped.
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let passkeys = value["identities"][0]["passkeys"].as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert!(
            passkeys[0].get("private_key").is_none(),
            "corrupt key is skipped with a warning"
        );
    }

    #[tokio::test]
    async fn authenticated_export_without_sensitive_keeps_encrypted_blob() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = authenticated_workspace(&dir, "master-pin").await;
        seed_credentials(&config, "master-pin").await;
        // Non-exportable passkey: even a sensitive export skips the key.
        seed_passkey(&config, "master-pin", false).await;

        let out = dir.path().join("alice-safe.json");
        let ui = ScriptedUi::new()
            .password("master-pin")
            .confirm(true)
            .password("master-pin");
        execute_with(with_output(args(&["alice"], "json"), &out), &config, &ui)
            .await
            .expect("authenticated metadata export succeeds");
        assert!(ui.exhausted());

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let identity = &value["identities"][0];
        let login = identity["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "Web login")
            .unwrap()
            .clone();
        assert!(
            login.get("encrypted_data").is_some(),
            "metadata export keeps the encrypted blob"
        );
        assert!(login.get("data").is_none());
        let passkeys = identity["passkeys"].as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert!(passkeys[0].get("private_key").is_none());
    }

    #[tokio::test]
    async fn sensitive_export_warns_for_non_exportable_passkey() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = authenticated_workspace(&dir, "master-pin").await;
        seed_passkey(&config, "master-pin", false).await;

        let out = dir.path().join("alice-warn.json");
        let mut a = with_output(args(&["alice"], "json"), &out);
        a.include_sensitive = true;
        // Two unlocks (validation + JSON exporter) plus the plain and the
        // sensitive confirmations; the non-exportable passkey only warns.
        let ui = ScriptedUi::new()
            .password("master-pin")
            .confirm(true)
            .confirm(true)
            .password("master-pin");
        execute_with(a, &config, &ui)
            .await
            .expect("sensitive export with a non-exportable passkey succeeds");
        assert!(ui.exhausted());

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let passkeys = value["identities"][0]["passkeys"].as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert!(
            passkeys[0].get("private_key").is_none(),
            "non-exportable passkey must not carry its private key"
        );
    }

    #[tokio::test]
    async fn execute_with_wrong_password_fails_during_validation() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = authenticated_workspace(&dir, "master-pin").await;

        // Name validation unlocks the workspace first: a scripted wrong
        // password aborts before any export happens.
        let ui = ScriptedUi::new().password("wrong-pin");
        let err = execute_with(
            with_output(args(&["alice"], "json"), &dir.path().join("x.json")),
            &config,
            &ui,
        )
        .await
        .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));
        assert!(ui.exhausted());
    }

    #[tokio::test]
    async fn authenticated_csv_export_unlocks_with_scripted_password() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = authenticated_workspace(&dir, "master-pin").await;
        seed_credentials(&config, "master-pin").await;

        let out = dir.path().join("alice.csv");
        // Name validation unlocks first, then the confirm gate, then the CSV
        // exporter unlocks again.
        let ui = ScriptedUi::new()
            .password("master-pin")
            .confirm(true)
            .password("master-pin");
        execute_with(with_output(args(&["alice"], "csv"), &out), &config, &ui)
            .await
            .expect("authenticated csv export succeeds");
        assert!(ui.exhausted());

        let csv = std::fs::read_to_string(&out).unwrap();
        assert!(csv.starts_with("Name,Type,Description,Email,Created,Modified"));
        assert!(csv.contains("alice"));
    }

    #[tokio::test]
    async fn authenticated_csv_export_rejects_late_wrong_password() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = authenticated_workspace(&dir, "master-pin").await;
        seed_credentials(&config, "master-pin").await;

        // The name validation unlocks with the right password, then the CSV
        // exporter's own unlock fails — reaching the exporter's bail that a
        // single env-provided password can never hit.
        let out = dir.path().join("alice.csv");
        let ui = ScriptedUi::new()
            .password("master-pin")
            .confirm(true)
            .password("wrong-pin");
        let err = execute_with(with_output(args(&["alice"], "csv"), &out), &config, &ui)
            .await
            .expect_err("late wrong password must abort the csv export");
        assert!(
            err.to_string()
                .contains("Authentication failed: InvalidCredentials"),
            "got: {err}"
        );
        assert!(ui.exhausted());
        assert!(!out.exists(), "failed export writes nothing");
    }

    #[tokio::test]
    async fn encrypted_export_round_trips_through_passphrase_prompt() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;
        let out = dir.path().join("enc.json");

        let mut a = with_output(args(&["alice"], "json"), &out);
        a.encrypt = true;
        let ui = ScriptedUi::new().confirm(true).password("pass-phrase-1");
        execute_with(a, &config, &ui)
            .await
            .expect("encrypted export succeeds");
        assert!(ui.exhausted());

        // The output is no longer plaintext but decrypts back to the JSON.
        let raw = std::fs::read(&out).unwrap();
        assert!(
            raw.starts_with(b"PERSENC1"),
            "output carries the magic header"
        );
        let decrypted = crate::utils::file_crypto::decrypt_file_to_temp(&out, "pass-phrase-1")
            .expect("correct passphrase decrypts");
        let content = std::fs::read_to_string(&decrypted).unwrap();
        assert!(content.contains("alice"));
        std::fs::remove_file(&decrypted).unwrap();

        let err = crate::utils::file_crypto::decrypt_file_to_temp(&out, "wrong")
            .expect_err("wrong passphrase must fail");
        assert!(err.to_string().contains("Decryption failed"));
    }

    #[tokio::test]
    async fn compressed_export_writes_gzip_archive() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice"]).await;
        let out = dir.path().join("out.json");
        let gz = dir.path().join("out.json.gz");

        let mut a = with_output(args(&["alice"], "json"), &out);
        a.compression = 6;
        let ui = ScriptedUi::new().confirm(true);
        execute_with(a, &config, &ui)
            .await
            .expect("compressed export succeeds");
        assert!(ui.exhausted());
        assert!(!out.exists(), "plaintext file is replaced by the archive");
        assert!(gz.exists());

        let f = std::fs::File::open(&gz).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(f);
        use std::io::Read;
        let mut restored = String::new();
        decoder.read_to_string(&mut restored).unwrap();
        assert!(restored.contains("alice"));
    }

    #[tokio::test]
    async fn interactive_selection_maps_multi_select_indices() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seeded_db(&dir, &["alice", "bob", "carol"]).await;

        // The scripted multi-select indices map back onto the listed
        // identities. find_all makes no ordering guarantee, so only the set
        // shape is asserted: indices 0 and 2 resolve to two distinct seeded
        // names.
        let ui = ScriptedUi::new().multi_select(&[0, 2]);
        let selected = select_identities_interactive(&config, &ui)
            .await
            .expect("interactive selection resolves names");
        assert!(ui.exhausted());
        let mut unique = selected.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 2, "indices 0 and 2 must map to distinct rows");
        assert!(selected
            .iter()
            .all(|n| ["alice", "bob", "carol"].contains(&n.as_str())));

        // A failing multi-select prompt propagates instead of panicking.
        let inner = ScriptedUi::new();
        let ui = FailOn::new(&inner, PromptKind::MultiSelect);
        let err = select_identities_interactive(&config, &ui)
            .await
            .expect_err("failing multi-select must abort");
        assert!(err.to_string().contains("failing ui: multi-select prompt"));
    }

    #[tokio::test]
    async fn sensitive_export_skips_locked_passkey_private_keys() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let dir = TempDir::new().unwrap();
        let config = authenticated_workspace(&dir, "master-pin").await;
        seed_passkey(&config, "master-pin", false).await;

        let out = dir.path().join("locked-passkey.json");
        let mut a = with_output(args(&["alice"], "json"), &out);
        a.include_sensitive = true;
        let ui = ScriptedUi::new()
            .password("master-pin")
            .confirm(true)
            .confirm(true)
            .password("master-pin");
        execute_with(a, &config, &ui)
            .await
            .expect("sensitive export with a locked passkey still succeeds");
        assert!(ui.exhausted());

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let passkeys = value["identities"][0]["passkeys"].as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert!(
            passkeys[0].get("private_key").is_none(),
            "non-exportable passkeys must not carry a private key"
        );

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");
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
