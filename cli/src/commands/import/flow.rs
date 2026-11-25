//! Orchestration of the import flow: validation, decryption, interactive choice,
//! conflict check, backup and execution (dry-run / merge / replace / skip),
//! wiring up PersonaService and the repositories.

use anyhow::{Context, Result};
use colored::*;
use std::path::{Path, PathBuf};

use crate::utils::progress::create_progress_bar;
use crate::utils::prompt::{PromptUi, TerminalUi};
use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use persona_core::{
    models::IdentityType,
    storage::{IdentityRepository, Repository},
    Database,
};

use super::display::{handle_import_conflicts, show_import_summary};
use super::formats::parse_import_file;
use super::{ImportArgs, ImportConflict, ImportData, ImportIdentity};

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

pub(super) fn validate_import_file(file_path: &Path) -> Result<()> {
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

pub(super) fn decrypt_import_file(
    file_path: &Path,
    _config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<PathBuf> {
    use crate::utils::file_crypto::decrypt_file_to_temp;
    println!("🔓 Decrypting import file...");
    let passphrase = crate::commands::service::prompt_payload_passphrase("import", ui)?;
    let out = decrypt_file_to_temp(file_path, &passphrase)?;
    // The decrypted temp file carries a `.tmp` extension; restore the source
    // extension so format detection keeps working.
    let detected = out.with_extension(
        file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("json"),
    );
    let final_path = if detected != out {
        std::fs::rename(&out, &detected)
            .with_context(|| format!("Failed to finalize decrypted file {}", detected.display()))?;
        detected
    } else {
        out
    };
    println!("{} File decrypted", "✓".green());
    Ok(final_path)
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

pub(super) async fn check_import_conflicts(
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
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .into_anyhow()?;
    let names = if service.has_users().await.into_anyhow()? {
        let password = crate::commands::service::prompt_master_password(ui)?;
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

pub(super) async fn perform_import(
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
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .into_anyhow()?;
    let has_users = service.has_users().await.into_anyhow()?;
    if has_users {
        let password = crate::commands::service::prompt_master_password(ui)?;
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
