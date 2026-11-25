use super::*;

#[derive(Tabled)]
struct HistoryRow {
    #[tabled(rename = "Version")]
    version: u32,
    #[tabled(rename = "Time")]
    time: String,
    #[tabled(rename = "Change")]
    change_type: String,
    #[tabled(rename = "Fields")]
    fields: String,
}

/// Item history (1Password-aligned): the change timeline of a credential.
/// History rows carry only plaintext metadata diffs — ciphertext changes show up as an
/// `encrypted_data` placeholder. History stays queryable after the credential is
/// deleted (the name degrades to a UUID display).
pub(crate) async fn show_credential_history(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    let credential = service.get_credential(&id).await.into_anyhow()?;
    match &credential {
        Some(cred) => println!("{} {}", "History for:".bold(), cred.name.cyan()),
        None => println!(
            "{} {} (deleted)",
            "History for:".bold(),
            id.to_string().cyan()
        ),
    }

    let history = service
        .get_entity_history(EntityType::Credential, &id)
        .await
        .into_anyhow()
        .context("Failed to fetch credential history")?;

    if history.is_empty() {
        println!("{}", "No recorded changes.".yellow());
        return Ok(());
    }

    let rows: Vec<HistoryRow> = history
        .iter()
        .map(|entry| HistoryRow {
            version: entry.version,
            time: entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            change_type: entry.change_type.to_string(),
            fields: if entry.changes_summary.is_empty() {
                "-".to_string()
            } else {
                entry
                    .changes_summary
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        })
        .collect();
    println!("{}", Table::new(rows));
    Ok(())
}

/// Restore metadata to an earlier item-history version (1Password item history).
/// Secret payload is metadata-only in history and never rolls back: rotating a
/// password stays forward-only.
pub(crate) async fn restore_credential_version_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    version: u32,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    let restored = service
        .restore_credential_version(&id, version)
        .await
        .into_anyhow()
        .context("Failed to restore credential version")?;
    println!(
        "{} Restored metadata of {} to version {} (secrets are never rolled back)",
        "✓".green(),
        restored.name.cyan(),
        version
    );
    Ok(())
}
