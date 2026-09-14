use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use std::path::{Path, PathBuf};

use crate::utils::progress::create_progress_bar;
use crate::utils::prompt::{PromptUi, TerminalUi};
use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use persona_core::{
    models::IdentityType,
    storage::{IdentityRepository, Repository},
    Database, PersonaService,
};

#[derive(Args, Clone)]
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
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: ImportArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!("{}", "📥 Importing identities...".cyan().bold());
    println!();

    // Validate import file
    validate_import_file(&args.file)?;

    // Decrypt file if needed
    let import_file = if args.decrypt {
        decrypt_import_file(&args.file, config, ui)?
    } else {
        args.file.clone()
    };

    // Parse import data
    let import_data = parse_import_file(&import_file)?;

    // Show import summary
    show_import_summary(&import_data, &args)?;

    // Select identities to import
    let selected_identities = if args.interactive {
        select_identities_interactive(&import_data, ui)?
    } else {
        import_data.identities.clone()
    };

    if selected_identities.is_empty() {
        println!("{}", "No identities selected for import.".yellow());
        return Ok(());
    }

    // Check for conflicts
    let conflicts = check_import_conflicts(&selected_identities, config, ui).await?;
    if !conflicts.is_empty() {
        handle_import_conflicts(&conflicts, &args)?;
    }

    // Confirm import
    if !args.force && !args.dry_run && !ui.confirm("Proceed with import?", true)? {
        println!("{}", "Import cancelled.".yellow());
        return Ok(());
    }

    // Create backup if requested
    if args.backup && !args.dry_run {
        create_backup(config).await?;
    }

    // Perform import
    if args.dry_run {
        perform_dry_run(&selected_identities, &args, config, ui).await?;
    } else {
        perform_import(&selected_identities, &args, config, ui).await?;
    }

    println!();
    if args.dry_run {
        println!("{} Dry run completed successfully!", "✓".green().bold());
        println!("  Use {} to perform actual import", "--force".cyan());
    } else {
        println!("{} Import completed successfully!", "✓".green().bold());
        println!(
            "  Imported {} identities",
            selected_identities.len().to_string().cyan()
        );
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
}

#[derive(Debug)]
struct ImportConflict {
    name: String,
    conflict_type: String,
    existing_data: String,
    new_data: String,
}

fn validate_import_file(file_path: &Path) -> Result<()> {
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
            println!(
                "{} Large import file detected ({} MB)",
                "⚠️".yellow(),
                size_mb
            );
        }
    }

    Ok(())
}

fn decrypt_import_file(
    file_path: &Path,
    _config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<PathBuf> {
    use crate::utils::file_crypto::decrypt_file_to_temp;
    println!("🔓 Decrypting import file...");
    let passphrase = super::service::prompt_payload_passphrase("import", ui)?;
    let out = decrypt_file_to_temp(file_path, &passphrase)?;
    println!("{} File decrypted", "✓".green());
    Ok(out)
}

fn parse_import_file(file_path: &Path) -> Result<ImportData> {
    let content = std::fs::read_to_string(file_path).context("Failed to read import file")?;

    // Determine format by extension
    let format = file_path
        .extension()
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
    let json_value: serde_json::Value =
        serde_json::from_str(content).context("Failed to parse JSON import file")?;

    let export_info = json_value
        .get("export_info")
        .context("Missing export_info in import file")?;

    let version = export_info
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let created = export_info
        .get("created")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let identities_array = json_value
        .get("identities")
        .and_then(|v| v.as_array())
        .context("Missing or invalid identities array")?;

    let mut identities = Vec::new();
    for identity_value in identities_array {
        let identity = ImportIdentity {
            name: identity_value
                .get("name")
                .and_then(|v| v.as_str())
                .context("Missing identity name")?
                .to_string(),
            identity_type: identity_value
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("personal")
                .to_string(),
            description: identity_value
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            email: identity_value
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            phone: identity_value
                .get("phone")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tags: identity_value
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default(),
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
    let yaml_value: serde_yaml::Value =
        serde_yaml::from_str(content).context("Failed to parse YAML import file")?;

    // Convert YAML to JSON for easier processing
    let json_value: serde_json::Value =
        serde_json::to_value(yaml_value).context("Failed to convert YAML to JSON")?;

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
    println!("  Created: {}", import_data.created.dimmed());
    println!(
        "  Identities: {}",
        import_data.identities.len().to_string().cyan()
    );
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
        println!("{}", "Identities to import:".dimmed());
        for (i, identity) in import_data.identities.iter().enumerate().take(5) {
            println!(
                "  {}. {} ({})",
                i + 1,
                identity.name.cyan(),
                identity.identity_type.dimmed()
            );
        }

        if import_data.identities.len() > 5 {
            println!(
                "  ... and {} more",
                (import_data.identities.len() - 5).to_string().dimmed()
            );
        }
        println!();
    }

    Ok(())
}

fn select_identities_interactive(
    import_data: &ImportData,
    ui: &dyn PromptUi,
) -> Result<Vec<ImportIdentity>> {
    let identity_names: Vec<String> = import_data
        .identities
        .iter()
        .map(|id| format!("{} ({})", id.name, id.identity_type))
        .collect();

    let selections = ui.multi_select(
        "Select identities to import",
        &identity_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;

    Ok(selections
        .into_iter()
        .map(|i| import_data.identities[i].clone())
        .collect())
}

async fn check_import_conflicts(
    identities: &[ImportIdentity],
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<Vec<ImportConflict>> {
    let mut conflicts = Vec::new();

    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone()).await.into_anyhow()?;
    let names = if service.has_users().await.into_anyhow()? {
        let password = super::service::prompt_master_password(ui)?;
        match service.authenticate_user(&password).await.into_anyhow()? {
            persona_core::auth::authentication::AuthResult::Success => service
                .get_identities()
                .await
                .into_anyhow()?
                .into_iter()
                .map(|i| i.name)
                .collect::<Vec<_>>(),
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        IdentityRepository::new(db)
            .find_all()
            .await
            .into_anyhow()?
            .into_iter()
            .map(|i| i.name)
            .collect()
    };
    let set: std::collections::HashSet<_> = names.into_iter().collect();
    for identity in identities {
        if set.contains(&identity.name) {
            conflicts.push(ImportConflict {
                name: identity.name.clone(),
                conflict_type: "name_exists".to_string(),
                existing_data: "Identity already exists".to_string(),
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
        println!("  Existing: {}", conflict.existing_data.dimmed());
        println!("  New: {}", conflict.new_data.dimmed());
        println!();
    }

    match args.mode.as_str() {
        "merge" => {
            println!(
                "{} Mode: Merge - New data will be merged with existing",
                "ℹ️".blue()
            );
        }
        "replace" => {
            println!(
                "{} Mode: Replace - Existing data will be overwritten",
                "⚠️".yellow()
            );
        }
        "skip" => {
            println!(
                "{} Mode: Skip - Conflicting identities will be skipped",
                "ℹ️".blue()
            );
        }
        _ => {
            anyhow::bail!("Invalid import mode: {}", args.mode);
        }
    }

    Ok(())
}

async fn create_backup(config: &CliConfig) -> Result<()> {
    println!("💾 Creating backup...");

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_file = config
        .backup
        .directory
        .join(format!("persona_backup_{}.db", timestamp));

    if let Some(parent) = backup_file.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // Simple DB file copy backup
    let db_path = config.get_database_path();
    std::fs::copy(&db_path, &backup_file)
        .with_context(|| format!("Failed to create backup file at {}", backup_file.display()))?;

    println!(
        "{} Backup created: {}",
        "✓".green(),
        backup_file.display().to_string().cyan()
    );
    Ok(())
}

async fn perform_dry_run(
    identities: &[ImportIdentity],
    args: &ImportArgs,
    _config: &CliConfig,
    _ui: &dyn PromptUi,
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

        println!(
            "  {} {}: {}",
            "✓".green(),
            action.dimmed(),
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
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let pb = create_progress_bar(identities.len() as u64, "Importing identities");

    // Open DB + service and unlock if needed
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    let mut service = PersonaService::new(db.clone()).await.into_anyhow()?;
    let has_users = service.has_users().await.into_anyhow()?;
    if has_users {
        let password = super::service::prompt_master_password(ui)?;
        match service.authenticate_user(&password).await.into_anyhow()? {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        // If no users configured, initialize one? For import we allow creating identities without encryption.
    }
    let repo = IdentityRepository::new(db.clone());

    for (i, identity) in identities.iter().enumerate() {
        // Check existing (direct read for unencrypted, user-less workspaces)
        let existing = if has_users {
            service
                .get_identity_by_name(&identity.name)
                .await
                .into_anyhow()?
        } else {
            repo.find_by_name(&identity.name).await.into_anyhow()?
        };

        match args.mode.as_str() {
            "skip" if existing.is_some() => {
                pb.set_message(format!("Skipped {}", identity.name));
                pb.set_position(i as u64 + 1);
                continue;
            }
            "replace" if existing.is_some() => {
                let mut current = existing.unwrap();
                // Replace all fields
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
                // attributes: currently not imported from file -> keep current
                current.touch();
                let _ = if has_users {
                    service.update_identity(&current).await.into_anyhow()?
                } else {
                    repo.update(&current).await.into_anyhow()?
                };
            }
            "merge" if existing.is_some() => {
                let mut current = existing.unwrap();
                // Merge non-empty fields
                if !identity.identity_type.is_empty() {
                    current.identity_type = identity
                        .identity_type
                        .parse::<IdentityType>()
                        .unwrap_or(IdentityType::Custom(identity.identity_type.clone()));
                }
                if !identity.description.is_empty() {
                    current.description = Some(identity.description.clone());
                }
                if identity.email.is_some() {
                    current.email = identity.email.clone();
                }
                if identity.phone.is_some() {
                    current.phone = identity.phone.clone();
                }
                if !identity.tags.is_empty() {
                    current.tags = identity.tags.clone();
                }
                current.touch();
                let _ = if has_users {
                    service.update_identity(&current).await.into_anyhow()?
                } else {
                    repo.update(&current).await.into_anyhow()?
                };
            }
            _ => {
                // Create new
                let mut new = persona_core::models::Identity::new(
                    identity.name.clone(),
                    identity
                        .identity_type
                        .parse::<IdentityType>()
                        .unwrap_or(IdentityType::Custom(identity.identity_type.clone())),
                );
                new.description = if identity.description.is_empty() {
                    None
                } else {
                    Some(identity.description.clone())
                };
                new.email = identity.email.clone();
                new.phone = identity.phone.clone();
                new.tags = identity.tags.clone();
                let _ = if has_users {
                    service.create_identity_full(new).await.into_anyhow()?
                } else {
                    repo.create(&new).await.into_anyhow()?
                };
            }
        }

        let action = match args.mode.as_str() {
            "merge" => "Merged",
            "replace" => "Replaced",
            "skip" => "Skipped",
            _ => "Imported",
        };

        pb.set_message(format!("{} {}", action, identity.name));
        pb.set_position(i as u64 + 1);
    }

    pb.finish_with_message("Import completed");
    Ok(())
}

#[cfg(test)]
mod tests {
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

    fn args(file: &Path, force: bool) -> ImportArgs {
        ImportArgs {
            file: file.to_path_buf(),
            mode: "merge".to_string(),
            dry_run: false,
            force,
            backup: false,
            decrypt: false,
            interactive: false,
        }
    }

    fn sample_json() -> String {
        serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-01-01T00:00:00Z"},
            "identities": [
                {"name": "alice", "type": "personal", "description": "first", "email": "a@b.c", "tags": ["work"]},
                {"name": "bob", "type": "work", "description": "second"}
            ]
        })
        .to_string()
    }

    #[test]
    fn validate_reports_missing_and_directory_paths() {
        let dir = TempDir::new().unwrap();
        let err = validate_import_file(&dir.path().join("ghost.json"))
            .expect_err("missing file must fail");
        assert!(err.to_string().contains("does not exist"));

        let err = validate_import_file(dir.path()).expect_err("directory must fail");
        assert!(err.to_string().contains("not a file"));

        let f = dir.path().join("ok.json");
        std::fs::write(&f, "{}").unwrap();
        validate_import_file(&f).expect("regular file validates");
    }

    #[test]
    fn parse_all_three_formats_and_reject_unknown() {
        let dir = TempDir::new().unwrap();

        let json_path = dir.path().join("data.json");
        std::fs::write(&json_path, sample_json()).unwrap();
        let data = parse_import_file(&json_path).unwrap();
        assert_eq!(data.version, "1.0");
        assert_eq!(data.identities.len(), 2);
        assert_eq!(data.identities[0].name, "alice");
        assert_eq!(data.identities[0].email.as_deref(), Some("a@b.c"));
        assert_eq!(data.identities[0].tags, vec!["work".to_string()]);

        let yaml_path = dir.path().join("data.yaml");
        std::fs::write(&yaml_path, sample_yaml()).unwrap();
        let data = parse_import_file(&yaml_path).unwrap();
        assert_eq!(data.identities.len(), 2);
        assert_eq!(data.identities[1].name, "bob");

        let csv_path = dir.path().join("data.csv");
        std::fs::write(&csv_path, sample_csv()).unwrap();
        let data = parse_import_file(&csv_path).unwrap();
        assert_eq!(data.version, "csv");
        assert_eq!(data.identities.len(), 1);
        assert_eq!(data.identities[0].name, "carol");
        assert_eq!(data.identities[0].email.as_deref(), Some("c@d.e"));

        // CSV rows with fewer than 4 fields are skipped.
        let short_csv = dir.path().join("short.csv");
        std::fs::write(&short_csv, "Name,Type\nbroken,row\n").unwrap();
        let data = parse_import_file(&short_csv).unwrap();
        assert!(data.identities.is_empty());

        let txt_path = dir.path().join("data.txt");
        std::fs::write(&txt_path, "junk").unwrap();
        let err = parse_import_file(&txt_path).expect_err("unknown format must fail");
        assert!(err.to_string().contains("Unsupported import format: txt"));
    }

    fn sample_yaml() -> String {
        "export_info:\n  version: \"1.0\"\n  created: \"2024-01-01\"\nidentities:\n  - name: alice\n    type: personal\n  - name: bob\n    type: work\n".to_string()
    }

    fn sample_csv() -> String {
        "Name,Type,Description,Email,Created,Modified\ncarol,personal,desc,c@d.e,2024,2024\n"
            .to_string()
    }

    #[tokio::test]
    async fn import_round_trip_merge_conflicts_and_dry_run() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let json_path = dir.path().join("data.json");
        std::fs::write(&json_path, sample_json()).unwrap();

        // Dry run touches nothing.
        let mut dry_args = args(&json_path, true);
        dry_args.dry_run = true;
        execute(dry_args, &config).await.expect("dry run succeeds");
        assert!(check_import_conflicts(&[], &config, &ScriptedUi::new())
            .await
            .unwrap()
            .is_empty());

        // Real import creates both identities.
        execute(args(&json_path, true), &config)
            .await
            .expect("import succeeds");
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db.clone());
        assert!(repo.find_by_name("alice").await.unwrap().is_some());
        assert!(repo.find_by_name("bob").await.unwrap().is_some());
        drop(db);

        // Re-importing detects conflicts and merge mode updates them.
        let conflicts = check_import_conflicts(
            &[ImportIdentity {
                name: "alice".to_string(),
                identity_type: "personal".to_string(),
                description: "x".to_string(),
                email: None,
                phone: None,
                tags: vec![],
            }],
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, "name_exists");

        // Invalid mode is rejected when conflicts exist.
        let mut bad_args = args(&json_path, true);
        bad_args.mode = "bogus".to_string();
        let err = execute(bad_args, &config)
            .await
            .expect_err("invalid mode must fail");
        assert!(err.to_string().contains("Invalid import mode: bogus"));

        // Missing file fails fast.
        let err = execute(args(&dir.path().join("ghost.json"), true), &config)
            .await
            .expect_err("missing file must fail");
        assert!(err.to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn import_modes_merge_replace_skip() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let json_path = dir.path().join("data.json");
        std::fs::write(&json_path, sample_json()).unwrap();

        // First import creates identities.
        execute(args(&json_path, true), &config).await.unwrap();

        // Updated payload with new description for alice.
        let updated = serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-01-02T00:00:00Z"},
            "identities": [
                {"name": "alice", "type": "personal", "description": "updated-desc", "email": "new@b.c"}
            ]
        })
        .to_string();
        let updated_path = dir.path().join("updated.json");
        std::fs::write(&updated_path, updated).unwrap();

        // Merge keeps existing fields and applies new ones.
        let mut merge_args = args(&updated_path, true);
        merge_args.mode = "merge".to_string();
        execute(merge_args, &config).await.unwrap();
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let repo = IdentityRepository::new(db);
            let alice = repo.find_by_name("alice").await.unwrap().unwrap();
            assert_eq!(alice.description.as_deref(), Some("updated-desc"));
            assert_eq!(alice.email.as_deref(), Some("new@b.c"));
        }

        // Replace overwrites; skip leaves the row untouched.
        let blank = serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-01-03T00:00:00Z"},
            "identities": [
                {"name": "alice", "type": "work", "description": "replaced", "email": "r@b.c"}
            ]
        })
        .to_string();
        let blank_path = dir.path().join("blank.json");
        std::fs::write(&blank_path, blank).unwrap();

        let mut skip_args = args(&blank_path, true);
        skip_args.mode = "skip".to_string();
        execute(skip_args, &config).await.unwrap();
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let repo = IdentityRepository::new(db);
            let alice = repo.find_by_name("alice").await.unwrap().unwrap();
            assert_eq!(alice.description.as_deref(), Some("updated-desc"));
        }

        let mut replace_args = args(&blank_path, true);
        replace_args.mode = "replace".to_string();
        execute(replace_args, &config).await.unwrap();
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let repo = IdentityRepository::new(db);
            let alice = repo.find_by_name("alice").await.unwrap().unwrap();
            assert_eq!(alice.description.as_deref(), Some("replaced"));
            assert_eq!(alice.email.as_deref(), Some("r@b.c"));
        }
    }

    #[tokio::test]
    async fn import_authenticated_path_with_master_password() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let json_path = dir.path().join("data.json");
        std::fs::write(&json_path, sample_json()).unwrap();
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }

        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let err = execute(args(&json_path, true), &config)
            .await
            .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        execute(args(&json_path, true), &config)
            .await
            .expect("correct password must import");
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let service = PersonaService::new(db).await.unwrap();
            // Both identities landed in the encrypted workspace.
            let mut service = service;
            let password =
                crate::commands::service::prompt_master_password(&crate::utils::prompt::TerminalUi)
                    .unwrap();
            let _ = service.authenticate_user(&password).await.unwrap();
            assert!(service
                .get_identity_by_name("alice")
                .await
                .unwrap()
                .is_some());
        }

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn import_interactive_selection_and_confirm_gates() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let json_path = dir.path().join("data.json");
        std::fs::write(&json_path, sample_json()).unwrap();

        // Interactive selection picks only the first identity, then declines
        // the proceed prompt → nothing is imported.
        let mut select_args = args(&json_path, false);
        select_args.interactive = true;
        let ui = ScriptedUi::new().multi_select(&[0]).confirm(false);
        execute_with(select_args.clone(), &config, &ui)
            .await
            .expect("cancelled import returns success");
        assert!(ui.exhausted());
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db.clone());
        assert!(
            repo.find_all().await.unwrap().is_empty(),
            "declined import must not write"
        );
        drop(db);

        // Multi-selecting nothing reports "no identities selected".
        let ui = ScriptedUi::new().multi_select(&[]);
        execute_with(select_args.clone(), &config, &ui)
            .await
            .expect("empty selection returns success");
        assert!(ui.exhausted());

        // Accepting the proceed prompt imports the selected identities.
        let ui = ScriptedUi::new().multi_select(&[0, 1]).confirm(true);
        execute_with(select_args, &config, &ui)
            .await
            .expect("confirmed import succeeds");
        assert!(ui.exhausted());
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db);
        assert!(repo.find_by_name("alice").await.unwrap().is_some());
        assert!(repo.find_by_name("bob").await.unwrap().is_some());
    }
}
