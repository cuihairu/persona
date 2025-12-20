use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use image::GenericImageView;
use persona_core::{
    models::{CredentialData, CredentialType, SecurityLevel, TwoFactorData},
    Database, PersonaService,
};
use rqrr::PreparedImage;
use uuid::Uuid;

use crate::{config::CliConfig, utils::core_ext::CoreResultExt};

#[derive(Args, Debug)]
pub struct TotpArgs {
    #[command(subcommand)]
    command: TotpCommand,
}

#[derive(Subcommand, Debug)]
pub enum TotpCommand {
    /// Set up a new TOTP credential from QR/otpauth URI/secret
    Setup {
        /// Identity name to store credential under
        #[arg(short, long)]
        identity: String,
        /// Credential display name (defaults to issuer/account)
        #[arg(short, long)]
        name: Option<String>,
        /// Path to QR code image (PNG/JPEG)
        #[arg(long)]
        qr: Option<PathBuf>,
        /// Raw otpauth URI (otpauth://totp/Issuer:Account?secret=...)
        #[arg(long)]
        otpauth: Option<String>,
        /// Base32 secret (fallback if no QR/otpauth provided)
        #[arg(long)]
        secret: Option<String>,
        /// Issuer override
        #[arg(long)]
        issuer: Option<String>,
        /// Account name override
        #[arg(long)]
        account: Option<String>,
        /// Associate this TOTP with a website origin (enables browser extension matching)
        ///
        /// Accepts full URL (https://github.com) or a bare host (github.com).
        #[arg(long)]
        url: Option<String>,
        /// Digits override
        #[arg(long)]
        digits: Option<u8>,
        /// Period override
        #[arg(long)]
        period: Option<u32>,
        /// Hash algorithm (SHA1/SHA256/SHA512)
        #[arg(long)]
        algorithm: Option<String>,
    },
    /// Generate a TOTP code for a stored credential
    Code {
        /// Credential UUID (must be TwoFactor)
        #[arg(long)]
        id: Uuid,
        /// Continuous watch output (refresh every period)
        #[arg(long)]
        watch: bool,
    },
}

pub async fn execute(args: TotpArgs, config: &CliConfig) -> Result<()> {
    match args.command {
        TotpCommand::Setup {
            identity,
            name,
            qr,
            otpauth,
            secret,
            issuer,
            account,
            url,
            digits,
            period,
            algorithm,
        } => {
            setup_totp(
                config, identity, name, qr, otpauth, secret, issuer, account, url, digits, period,
                algorithm,
            )
            .await?
        }
        TotpCommand::Code { id, watch } => generate_codes(config, id, watch).await?,
    }
    Ok(())
}

async fn setup_totp(
    config: &CliConfig,
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
) -> Result<()> {
    println!("{}", "🔐 Setting up TOTP credential...".cyan());
    let mut service = init_service(config).await?;
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
        .context("Failed to create TOTP credential")?;

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
    service
        .update_credential(&credential)
        .await
        .into_anyhow()
        .context("Failed to update TOTP metadata")?;

    println!(
        "{} Saved TOTP credential '{}' for identity '{}'",
        "✓".green(),
        credential_name.bright_green(),
        identity.name.bright_cyan()
    );

    let (code, remaining) = generate_totp_code(&final_template)?;
    println!(
        "Current code: {} (valid for {}s)",
        code.bold().bright_blue(),
        remaining
    );

    Ok(())
}

fn normalize_origin_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("URL cannot be empty");
    }

    let url = url::Url::parse(trimmed).or_else(|_| url::Url::parse(&format!("https://{trimmed}")))?;
    let scheme = url.scheme();
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("Invalid URL: missing host"))?;

    Ok(format!("{scheme}://{host}"))
}

async fn generate_codes(config: &CliConfig, id: Uuid, watch: bool) -> Result<()> {
    let mut service = init_service(config).await?;
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
        CredentialData::TwoFactor(data) => data,
        _ => bail!("Credential {} does not contain TOTP data", id),
    };

    if watch {
        loop {
            let (code, remaining) = generate_totp_code_from_data(&data)?;
            println!(
                "{} → {} ({}s remaining)",
                chrono::Utc::now().format("%H:%M:%S"),
                code.bold().bright_blue(),
                remaining
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    } else {
        let (code, remaining) = generate_totp_code_from_data(&data)?;
        println!(
            "TOTP code for {}: {} ({}s remaining)",
            credential.name.bright_cyan(),
            code.bold().bright_blue(),
            remaining
        );
    }
    // unreachable if watch loop
    // but keep Ok for completeness
    #[allow(unreachable_code)]
    Ok(())
}

#[derive(Default)]
struct TotpTemplate {
    secret: Option<String>,
    issuer: Option<String>,
    account: Option<String>,
    algorithm: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
}

impl TotpTemplate {
    fn merge(&mut self, other: TotpTemplate) {
        if self.secret.is_none() {
            self.secret = other.secret;
        }
        if self.issuer.is_none() {
            self.issuer = other.issuer;
        }
        if self.account.is_none() {
            self.account = other.account;
        }
        if self.algorithm.is_none() {
            self.algorithm = other.algorithm;
        }
        if self.digits.is_none() {
            self.digits = other.digits;
        }
        if self.period.is_none() {
            self.period = other.period;
        }
    }

    fn finalize(self) -> Result<FinalTotpConfig> {
        let secret = self
            .secret
            .ok_or_else(|| anyhow!("Secret not provided via QR/otpauth/--secret"))?;
        let issuer = self.issuer.unwrap_or_default();
        let account = self.account.unwrap_or_else(|| "TOTP".into());
        let algorithm = self.algorithm.unwrap_or_else(|| "SHA1".into());
        let digits = self.digits.unwrap_or(6);
        let period = self.period.unwrap_or(30);
        Ok(FinalTotpConfig {
            secret,
            issuer,
            account,
            algorithm: algorithm.to_uppercase(),
            digits,
            period,
        })
    }
}

struct FinalTotpConfig {
    secret: String,
    issuer: String,
    account: String,
    algorithm: String,
    digits: u8,
    period: u32,
}

fn parse_otpauth_uri(uri: &str) -> Result<TotpTemplate> {
    let url = url::Url::parse(uri).context("Invalid otpauth URI")?;
    if url.scheme() != "otpauth" {
        bail!("URI must start with otpauth://");
    }
    if url.host_str() != Some("totp") {
        bail!("Only otpauth TOTP URIs are supported");
    }
    let path = url.path().trim_start_matches('/');
    let (issuer_label, account_label) = if let Some(pos) = path.find(':') {
        (
            path[..pos].trim().to_string(),
            path[pos + 1..].trim().to_string(),
        )
    } else {
        ("".into(), path.to_string())
    };

    let mut secret = None;
    let mut issuer = if issuer_label.is_empty() {
        None
    } else {
        Some(issuer_label)
    };
    let mut account = if account_label.is_empty() {
        None
    } else {
        Some(account_label)
    };
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.to_string()),
            "issuer" => issuer = Some(value.to_string()),
            "account" => account = Some(value.to_string()),
            "algorithm" => algorithm = Some(value.to_string()),
            "digits" => digits = value.parse().ok(),
            "period" => period = value.parse().ok(),
            _ => {}
        }
    }

    Ok(TotpTemplate {
        secret,
        issuer,
        account,
        algorithm,
        digits,
        period,
    })
}

fn decode_qr_file(path: &PathBuf) -> Result<String> {
    let img =
        image::open(path).with_context(|| format!("Failed to open QR image {}", path.display()))?;
    let gray = img.to_luma8();
    let mut prepared = PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        bail!("No QR code detected in {}", path.display());
    }
    let (_, content) = grids[0]
        .decode()
        .map_err(|e| anyhow!("Failed to decode QR: {}", e))?;
    Ok(content)
}

fn generate_totp_code(template: &FinalTotpConfig) -> Result<(String, u32)> {
    let data = TwoFactorData {
        secret_key: template.secret.clone(),
        issuer: template.issuer.clone(),
        account_name: template.account.clone(),
        algorithm: template.algorithm.clone(),
        digits: template.digits,
        period: template.period,
    };
    generate_totp_code_from_data(&data)
}

fn generate_totp_code_from_data(data: &TwoFactorData) -> Result<(String, u32)> {
    let secret_bytes = decode_secret(&data.secret_key)?;
    let now = chrono::Utc::now();
    let period = data.period.max(1) as u64;
    let timestamp = now.timestamp().max(0) as u64;
    let counter = timestamp / period;
    let digits = data.digits.clamp(4, 10) as u32;
    let code_num = hotp(&secret_bytes, counter, &data.algorithm)?;
    let modulo = 10_u32.pow(digits);
    let value = code_num % modulo;
    let code = format!("{:0width$}", value, width = digits as usize);
    let remaining = (period - (timestamp % period)) as u32;
    Ok((code, remaining))
}

fn hotp(secret: &[u8], counter: u64, algorithm: &str) -> Result<u32> {
    let msg = counter.to_be_bytes();
    let algo = algorithm.to_ascii_uppercase();
    let hash = if algo == "SHA256" {
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).context("Invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else if algo == "SHA512" {
        type HmacSha512 = Hmac<sha2::Sha512>;
        let mut mac = HmacSha512::new_from_slice(secret).context("Invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else {
        type HmacSha1 = Hmac<sha1::Sha1>;
        let mut mac = HmacSha1::new_from_slice(secret).context("Invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    };

    let offset = (hash.last().copied().unwrap_or(0) & 0x0f) as usize;
    if offset + 4 > hash.len() {
        bail!("Invalid HMAC output");
    }
    let slice = &hash[offset..offset + 4];
    let binary = ((slice[0] as u32 & 0x7f) << 24)
        | ((slice[1] as u32) << 16)
        | ((slice[2] as u32) << 8)
        | slice[3] as u32;
    Ok(binary)
}

fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect::<String>()
        .trim_matches('=')
        .to_string();
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32.decode(normalized.as_bytes()))
        .map_err(|e| anyhow!("Invalid base32 secret: {}", e))
}

async fn init_service(config: &CliConfig) -> Result<PersonaService> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to connect to database: {}", db_path.display()))?;
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run database migrations")?;
    let mut service = PersonaService::new(db)
        .await
        .into_anyhow()
        .context("Failed to create PersonaService")?;

    if service
        .has_users()
        .await
        .into_anyhow()
        .context("Failed to check users")?
    {
        let password = dialoguer::Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .into_anyhow()
            .context("Failed to authenticate user")?
        {
            persona_core::auth::authentication::AuthResult::Success => Ok(service),
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        anyhow::bail!("Workspace not initialized. Run `persona init` first");
    }
}

async fn resolve_identity(service: &mut PersonaService, name: &str) -> Result<Identity> {
    service
        .get_identity_by_name(name)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Identity '{}' not found", name))
}

type Identity = persona_core::models::Identity;

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE32_NOPAD;
    use proptest::string::string_regex;
    use proptest::{collection, prelude::*, sample::select};
    use url::form_urlencoded;

    const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    fn label_strategy() -> impl Strategy<Value = String> {
        string_regex("[A-Za-z0-9._-]{1,20}").unwrap()
    }

    fn base32_secret_strategy() -> impl Strategy<Value = String> {
        collection::vec(0usize..BASE32_ALPHABET.len(), 16..=40).prop_map(|indices| {
            indices
                .into_iter()
                .map(|i| BASE32_ALPHABET[i] as char)
                .collect::<String>()
        })
    }

    fn encode_component(value: &str) -> String {
        form_urlencoded::byte_serialize(value.as_bytes()).collect()
    }

    proptest! {
        #[test]
        fn otpauth_uri_roundtrip(
            issuer in label_strategy(),
            account in label_strategy(),
            secret in base32_secret_strategy(),
            digits in 6u8..=8,
            period in 15u32..=60,
            algorithm in select(vec![
                "SHA1".to_string(),
                "SHA256".to_string(),
                "SHA512".to_string()
            ])
        ) {
            let path = format!(
                "{}:{}",
                encode_component(&issuer),
                encode_component(&account)
            );
            let uri = format!(
                "otpauth://totp/{}?secret={}&issuer={}&account={}&algorithm={}&digits={}&period={}",
                path,
                secret,
                encode_component(&issuer),
                encode_component(&account),
                algorithm,
                digits,
                period
            );

            let template = parse_otpauth_uri(&uri).unwrap();
            prop_assert_eq!(template.secret.as_deref(), Some(secret.as_str()));
            prop_assert_eq!(template.issuer.as_deref(), Some(issuer.as_str()));
            prop_assert_eq!(template.account.as_deref(), Some(account.as_str()));
            prop_assert_eq!(
                template.algorithm.as_deref().map(|s| s.to_ascii_uppercase()),
                Some(algorithm.clone())
            );
            prop_assert_eq!(template.digits, Some(digits));
            prop_assert_eq!(template.period, Some(period));
        }
    }

    proptest! {
        #[test]
        fn base32_secret_roundtrip(bytes in collection::vec(any::<u8>(), 8..=64)) {
            let encoded = BASE32_NOPAD.encode(&bytes);
            let decoded = decode_secret(&encoded).unwrap();
            prop_assert_eq!(decoded, bytes);
        }
    }
}
