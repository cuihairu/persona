use super::*;

pub(crate) async fn select_identities_interactive(
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

pub(crate) async fn get_all_identity_names(
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<Vec<String>> {
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
        let password = super::super::service::prompt_master_password(ui)?;
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

pub(crate) async fn validate_identity_names(
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

pub(crate) fn determine_output_path(
    args: &ExportArgs,
    identity_names: &[String],
) -> Result<PathBuf> {
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

pub(crate) fn show_export_summary(
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
