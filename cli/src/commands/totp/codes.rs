use super::*;

pub(crate) async fn generate_codes(
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
    id: Uuid,
    watch: bool,
    counter: Option<u64>,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    let credential = service
        .get_credential(&id)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Credential {} not found", id))?;
    if !matches!(credential.credential_type, CredentialType::TwoFactor) {
        bail!("Credential {} is not a TOTP entry", id);
    }
    let data = match service
        .get_credential_data(&id)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Unable to decrypt credential {}", id))?
    {
        // RFC TOTP 与游戏令牌（如 Steam Guard）都经 core 调度器取码
        d @ (CredentialData::TwoFactor(_) | CredentialData::GameToken(_)) => d,
        _ => bail!("Credential {} does not contain TOTP data", id),
    };

    // HOTP（RFC 4226）是计数器型：调度器不知道调用方计数器，故在此分流到
    // core hotp_code；core 侧对 HOTP 报不支持离线生成，消费方漏判时不会
    // 静默出错误码。
    if let CredentialData::TwoFactor(tf) = &data {
        if tf.hotp.unwrap_or(false) {
            if watch {
                bail!(
                    "watch mode is for time-based TOTP entries; HOTP codes advance per use — use --counter instead"
                );
            }
            let counter = counter.unwrap_or_else(|| tf.initial_counter.unwrap_or(0));
            let code = hotp_code(tf, counter)?;
            println!(
                "HOTP code for {} (counter {}): {} — next counter: {}",
                credential.name.bright_cyan(),
                counter,
                code.bold().bright_blue(),
                counter + 1
            );
            return Ok(());
        }
    }
    if counter.is_some() {
        bail!("--counter applies to HOTP entries only");
    }

    if watch {
        loop {
            let generated = generate_code_now(&data)?;
            println!(
                "{} → {} ({}s remaining)",
                chrono::Utc::now().format("%H:%M:%S"),
                generated.code.bold().bright_blue(),
                generated.remaining_seconds
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    } else {
        let generated = generate_code_now(&data)?;
        println!(
            "TOTP code for {}: {} ({}s remaining)",
            credential.name.bright_cyan(),
            generated.code.bold().bright_blue(),
            generated.remaining_seconds
        );
    }
    // unreachable if watch loop
    // but keep Ok for completeness
    #[allow(unreachable_code)]
    Ok(())
}
