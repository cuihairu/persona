use super::parse::{
    decode_qr_file, generate_hotp_code, generate_totp_code, normalize_origin_url, parse_otpauth_uri,
};
use super::template::TotpTemplate;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn setup_totp(
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
    identity_name: String,
    display_name: Option<String>,
    qr: Option<PathBuf>,
    otpauth: Option<String>,
    secret: Option<String>,
    issuer_override: Option<String>,
    account_override: Option<String>,
    url: Option<String>,
    digits_override: Option<u8>,
    period_override: Option<u32>,
    algorithm_override: Option<String>,
    hotp_flag: bool,
    counter_override: Option<u64>,
) -> Result<()> {
    let mut service = init_service(config, ui).await?;
    let identity = resolve_identity(&mut service, &identity_name).await?;

    let mut template = TotpTemplate::default();
    if let Some(path) = qr {
        let uri = decode_qr_file(&path)?;
        template.merge(parse_otpauth_uri(&uri)?);
    }
    if let Some(uri) = otpauth {
        template.merge(parse_otpauth_uri(&uri)?);
    }
    if let Some(secret) = secret {
        template.secret = Some(secret);
    }
    if let Some(issuer) = issuer_override {
        template.issuer = Some(issuer);
    }
    if let Some(account) = account_override {
        template.account = Some(account);
    }
    if let Some(digits) = digits_override {
        template.digits = Some(digits);
    }
    if let Some(period) = period_override {
        template.period = Some(period);
    }
    if let Some(algo) = algorithm_override {
        template.algorithm = Some(algo);
    }
    if hotp_flag {
        template.hotp = Some(true);
    }
    if let Some(counter) = counter_override {
        template.counter = Some(counter);
    }
    let kind = if template.hotp.unwrap_or(false) {
        "HOTP"
    } else {
        "TOTP"
    };
    println!("{}", format!("🔐 Setting up {kind} credential...").cyan());

    let final_template = template.finalize()?;
    let origin_url = url.map(|s| normalize_origin_url(&s)).transpose()?;

    let credential_name = display_name
        .or_else(|| {
            if final_template.issuer.is_empty() {
                None
            } else {
                Some(format!(
                    "{} ({})",
                    final_template.issuer, final_template.account
                ))
            }
        })
        .unwrap_or_else(|| final_template.account.clone());

    let data = CredentialData::TwoFactor(TwoFactorData {
        secret_key: final_template.secret.clone(),
        issuer: final_template.issuer.clone(),
        account_name: final_template.account.clone(),
        algorithm: final_template.algorithm.clone(),
        digits: final_template.digits,
        period: final_template.period,
        hotp: Some(final_template.hotp),
        initial_counter: final_template.counter,
    });

    let mut credential = service
        .create_credential(
            identity.id,
            credential_name.clone(),
            CredentialType::TwoFactor,
            SecurityLevel::High,
            &data,
        )
        .await
        .into_anyhow()
        .context(format!("Failed to create {kind} credential"))?;

    credential.username = Some(final_template.account.clone());
    if let Some(url) = origin_url {
        credential.url = Some(url);
    }
    credential
        .metadata
        .insert("issuer".into(), final_template.issuer.clone());
    credential
        .metadata
        .insert("algorithm".into(), final_template.algorithm.clone());
    credential
        .metadata
        .insert("digits".into(), final_template.digits.to_string());
    credential.metadata.insert("type".into(), kind.to_string());
    service
        .update_credential(&credential)
        .await
        .into_anyhow()
        .context(format!("Failed to update {kind} metadata"))?;

    println!(
        "{} Saved {kind} credential '{}' for identity '{}'",
        "✓".green(),
        credential_name.bright_green(),
        identity.name.bright_cyan()
    );

    if final_template.hotp {
        let counter = final_template.counter.unwrap_or(0);
        let code = generate_hotp_code(&final_template, counter)?;
        println!(
            "Current code (counter {counter}): {} — next counter: {}",
            code.bold().bright_blue(),
            counter + 1
        );
    } else {
        let (code, remaining) = generate_totp_code(&final_template)?;
        println!(
            "Current code: {} (valid for {}s)",
            code.bold().bright_blue(),
            remaining
        );
    }

    Ok(())
}

/// 录入 Steam Guard 令牌：secret 为 base64 shared_secret，固定 5 位码/30 秒
pub(crate) async fn setup_steam_token(
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
    identity_name: String,
    display_name: Option<String>,
    secret: String,
    account: String,
    url: Option<String>,
) -> Result<()> {
    println!("{}", "🔐 Setting up Steam Guard token...".cyan());
    // 入库前先验证密钥可解码，坏密钥不该等到取码时才失败
    let secret = secret.trim().to_string();
    if decode_steam_secret(&secret).is_err() {
        bail!("Invalid Steam shared_secret (must be standard base64)");
    }
    let origin_url = url.map(|s| normalize_origin_url(&s)).transpose()?;

    let mut service = init_service(config, ui).await?;
    let identity = resolve_identity(&mut service, &identity_name).await?;

    let game_data = GameTokenData {
        provider: PROVIDER_STEAM_GUARD.to_string(),
        secret_key: secret.clone(),
        issuer: "Steam".to_string(),
        account_name: account.clone(),
        url: origin_url.clone(),
        identity_secret: None,
        device_id: None,
    };

    let credential_name = display_name.unwrap_or_else(|| format!("Steam ({})", account));
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
        .context("Failed to create Steam Guard credential")?;

    credential.username = Some(account.clone());
    if let Some(url) = origin_url {
        credential.url = Some(url);
    }
    credential
        .metadata
        .insert("provider".into(), PROVIDER_STEAM_GUARD.into());
    credential.metadata.insert("issuer".into(), "Steam".into());
    service
        .update_credential(&credential)
        .await
        .into_anyhow()
        .context("Failed to update Steam Guard metadata")?;

    println!(
        "{} Saved Steam Guard token '{}' for identity '{}'",
        "✓".green(),
        credential_name.bright_green(),
        identity.name.bright_cyan()
    );

    let code = generate_game_token_code_now(&game_data)?;
    println!(
        "Current code: {} (valid for {}s)",
        code.code.bold().bright_blue(),
        code.remaining_seconds
    );

    Ok(())
}

/// 录入游戏令牌记录：离线可算的 provider（当前仅 Steam）各有专用 setup
/// 命令；厂商绑定型（腾讯安全中心/网易大神/米哈游安全令等，密钥在厂商
/// 服务端配发进官方 App，无法离线出码）只做记录——不伪造动态码，出码
/// 仍走厂商 App（todo.md G2 调研结论）。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn setup_game_token(
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
    identity_name: String,
    provider_raw: String,
    display_name: Option<String>,
    secret: Option<String>,
    account: String,
    issuer_override: Option<String>,
    url: Option<String>,
) -> Result<()> {
    println!("{}", "🔐 Recording game token entry...".cyan());
    let provider = provider_raw.trim().to_lowercase();
    if provider.is_empty()
        || !provider
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        bail!("Provider must be a non-empty slug of [a-z0-9_] (e.g. tencent_security)");
    }
    if is_supported_provider(&provider) {
        bail!(
            "Provider '{}' supports offline generation; use its dedicated setup command instead (e.g. `persona totp setup-steam`)",
            provider
        );
    }
    let secret = secret
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let origin_url = url.map(|s| normalize_origin_url(&s)).transpose()?;

    let mut service = init_service(config, ui).await?;
    let identity = resolve_identity(&mut service, &identity_name).await?;

    let issuer = issuer_override.unwrap_or_else(|| provider.clone());
    let game_data = GameTokenData {
        provider: provider.clone(),
        secret_key: secret.unwrap_or_default(),
        issuer: issuer.clone(),
        account_name: account.clone(),
        url: origin_url.clone(),
        identity_secret: None,
        device_id: None,
    };

    let credential_name = display_name.unwrap_or_else(|| format!("{} ({})", issuer, account));
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
        .context("Failed to create game token record")?;

    credential.username = Some(account.clone());
    if let Some(url) = origin_url {
        credential.url = Some(url);
    }
    credential.metadata.insert("provider".into(), provider);
    credential.metadata.insert("issuer".into(), issuer);
    service
        .update_credential(&credential)
        .await
        .into_anyhow()
        .context("Failed to update game token metadata")?;

    println!(
        "{} Saved game token record '{}' for identity '{}'",
        "✓".green(),
        credential_name.bright_green(),
        identity.name.bright_cyan()
    );
    println!(
        "{} Vendor-bound provider: dynamic codes must be generated in the vendor's official app — this entry is a vault record, not an offline generator",
        "ℹ".yellow()
    );

    Ok(())
}
