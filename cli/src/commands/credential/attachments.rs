use super::*;

/// A human-readable attachment size (B → KB → MB)
pub(crate) fn format_attachment_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Attachments (1Password-aligned): blobs are encrypted under the owning credential's
/// per-item key and stay decryptable after a rewrap. The blob directory is initialized
/// alongside unlock in init_service.
pub(crate) async fn attach_file_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    file: PathBuf,
    encrypt: bool,
) -> Result<()> {
    let mut service = init_service(config, ui).await?;
    let attachment_id = service
        .attach_file(id, &file, encrypt)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to attach {}", file.display()))?;
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file.display().to_string());
    println!(
        "{} Attached {} ({}) as {}",
        "✓".green(),
        filename.cyan(),
        if encrypt {
            "encrypted".green()
        } else {
            "unencrypted".yellow()
        },
        attachment_id
    );
    Ok(())
}

#[derive(Tabled)]
struct AttachmentRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "File")]
    filename: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Encrypted")]
    encrypted: String,
    #[tabled(rename = "Attached")]
    attached: String,
}

pub(crate) async fn list_attachments_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    let attachments = service
        .get_attachments(&id)
        .await
        .into_anyhow()
        .context("Failed to list attachments")?;

    if attachments.is_empty() {
        println!("{}", "No attachments.".yellow());
        return Ok(());
    }

    let rows: Vec<AttachmentRow> = attachments
        .iter()
        .map(|a| AttachmentRow {
            id: a.id.to_string(),
            filename: a.filename.clone(),
            size: format_attachment_size(a.size),
            encrypted: if a.is_encrypted {
                "yes".into()
            } else {
                "no".into()
            },
            attached: a.created_at.format("%Y-%m-%d %H:%M").to_string(),
        })
        .collect();
    println!("{}", Table::new(rows));
    Ok(())
}

pub(crate) async fn save_attachment_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    attachment_id: Uuid,
    output: PathBuf,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    service
        .save_attachment(&attachment_id, &output, true)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to save attachment to {}", output.display()))?;
    println!(
        "{} Saved decrypted attachment to {}",
        "✓".green(),
        output.display().to_string().cyan()
    );
    Ok(())
}

pub(crate) async fn remove_attachment_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    attachment_id: Uuid,
    yes: bool,
) -> Result<()> {
    let mut service = init_service(config, ui).await?;
    if !yes {
        let confirm = ui.confirm(&format!("Remove attachment {}?", attachment_id), false)?;
        if !confirm {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }
    }
    service
        .delete_attachment(&attachment_id)
        .await
        .into_anyhow()
        .context("Failed to remove attachment")?;
    println!("{} Removed attachment {}", "✓".green(), attachment_id);
    Ok(())
}
