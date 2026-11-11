use super::*;

/// 人类可读的附件大小（B → KB → MB）
pub(crate) fn format_attachment_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Attachments（1Password 对齐）：附件经所属凭据的 per-item key 加密封存，
/// 改密（rewrap）后仍可解密。blob 目录在 init_service 里随解锁一起初始化。
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
