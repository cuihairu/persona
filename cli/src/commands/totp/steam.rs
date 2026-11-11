use super::parse::normalize_origin_url;
use super::*;

/// 收集待导入的 .maFile 路径：`--file` 指向单文件或目录（SDA 常把
/// 所有 .maFile 放一个目录，另带 manifest.json——按扩展名过滤，目录内
/// 按文件名排序保证批量导入的确定性）。
pub(crate) fn collect_ma_file_paths(path: &std::path::Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        bail!("{} does not exist", path.display());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(path)
        .with_context(|| format!("Failed to read directory {}", path.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .map(|ext| ext.eq_ignore_ascii_case("mafile"))
                    .unwrap_or(false)
        })
        .collect();
    files.sort();
    if files.is_empty() {
        bail!("No .maFile files found in {}", path.display());
    }
    Ok(files)
}

/// 导入 SDA `.maFile`：单文件或目录批量。
///
/// 流程：先全部解析（坏文件不碰库，批量时逐个汇报并跳过）→ 解锁库
/// （既有 re-auth 闸门）→ 逐文件展示 account_name/类型/入库字段/忽略
/// 字段清单并确认（`--yes` 跳过确认）→ 按 setup-steam 同样的形状落库
/// （GameToken/steam_guard，另带 identity_secret/device_id）。会话字段
/// （Session 对象、access_token 等）永不入库，只出现在忽略清单里。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn import_steam_mafiles(
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
    identity_name: String,
    path: PathBuf,
    display_name: Option<String>,
    url: Option<String>,
    assume_yes: bool,
) -> Result<()> {
    let files = collect_ma_file_paths(&path)?;
    if display_name.is_some() && files.len() > 1 {
        bail!("--name is only valid when --file points to a single .maFile");
    }
    let origin_url = url.map(|s| normalize_origin_url(&s)).transpose()?;

    // 解析阶段：任何失败都不打开库
    let mut parsed_files: Vec<(PathBuf, persona_core::import_mafile::MaFileImport)> = Vec::new();
    let mut failed: Vec<(PathBuf, anyhow::Error)> = Vec::new();
    for file in &files {
        let bytes =
            std::fs::read(file).with_context(|| format!("Failed to read {}", file.display()))?;
        match parse_ma_file(&bytes) {
            Ok(parsed) => parsed_files.push((file.clone(), parsed)),
            Err(e) => failed.push((file.clone(), e)),
        }
    }
    if parsed_files.is_empty() {
        if let Some((path, e)) = failed.first() {
            bail!("No .maFile could be imported; {}: {e:#}", path.display());
        }
        bail!("Nothing to import");
    }

    println!(
        "{}",
        "🔐 Importing Steam Guard token(s) from maFile...".cyan()
    );
    let mut service = init_service(config, ui).await?;
    let identity = resolve_identity(&mut service, &identity_name).await?;

    let mut imported = 0usize;
    for (path, parsed) in &parsed_files {
        println!(
            "{}",
            format!(
                "── {} ──",
                path.file_name()
                    .unwrap_or(path.as_os_str())
                    .to_string_lossy()
            )
            .bold()
        );
        println!("  Account: {}", parsed.account_name.bright_cyan());
        println!("  Type:    Steam Guard (5-char code, 30s period, offline)");
        let mut stores = vec!["shared_secret".to_string()];
        if parsed.identity_secret.is_some() {
            stores.push("identity_secret".to_string());
        }
        if parsed.device_id.is_some() {
            stores.push("device_id".to_string());
        }
        println!("  Stores:  {}", stores.join(", "));
        if parsed.ignored_session_fields.is_empty() {
            println!("  Ignored session fields: (none present)");
        } else {
            println!(
                "  {} {}",
                "Ignored session fields (NOT stored):".yellow(),
                parsed.ignored_session_fields.join(", ")
            );
        }
        if !parsed.ignored_other_fields.is_empty() {
            println!(
                "  Ignored other fields: {}",
                parsed.ignored_other_fields.join(", ")
            );
        }

        if !assume_yes {
            let confirmed = ui.confirm("Import this token into the vault?", true)?;
            if !confirmed {
                println!("  {} Skipped.", "ℹ".yellow());
                continue;
            }
        }

        let game_data = GameTokenData {
            provider: PROVIDER_STEAM_GUARD.to_string(),
            secret_key: parsed.shared_secret.clone(),
            issuer: "Steam".to_string(),
            account_name: parsed.account_name.clone(),
            url: origin_url.clone(),
            identity_secret: parsed.identity_secret.clone(),
            device_id: parsed.device_id.clone(),
        };

        let credential_name = display_name
            .clone()
            .unwrap_or_else(|| format!("Steam ({})", parsed.account_name));
        let mut credential = service
            .create_credential(
                identity.id,
                credential_name.clone(),
                CredentialType::TwoFactor,
                SecurityLevel::High,
                &CredentialData::GameToken(game_data.clone()),
            )
            .await
            .into_anyhow()
            .with_context(|| format!("Failed to create credential for {}", parsed.account_name))?;

        credential.username = Some(parsed.account_name.clone());
        if let Some(url) = &origin_url {
            credential.url = Some(url.clone());
        }
        credential
            .metadata
            .insert("provider".into(), PROVIDER_STEAM_GUARD.into());
        credential.metadata.insert("issuer".into(), "Steam".into());
        service
            .update_credential(&credential)
            .await
            .into_anyhow()
            .with_context(|| format!("Failed to store metadata for {}", parsed.account_name))?;

        let code = generate_game_token_code_now(&game_data)?;
        println!(
            "  {} Imported as '{}'; current code: {} (valid for {}s)",
            "✓".green(),
            credential_name.bright_green(),
            code.code.bold().bright_blue(),
            code.remaining_seconds
        );
        imported += 1;
    }

    println!(
        "{} Imported {} Steam Guard token(s) into identity '{}'",
        "✓".green(),
        imported,
        identity.name.bright_cyan()
    );
    if !failed.is_empty() {
        for (path, e) in &failed {
            println!("{} {}: {e:#}", "✗".red(), path.display());
        }
        bail!("{} file(s) failed to import", failed.len());
    }
    Ok(())
}
