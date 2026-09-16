use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use persona_core::{
    crypto::totp::totp_now,
    models::{CredentialData, CredentialType, SecurityLevel, TwoFactorData},
    PersonaService,
};
use rqrr::PreparedImage;
use uuid::Uuid;

use super::service::init_service;
use crate::{config::CliConfig, utils::core_ext::CoreResultExt};

#[derive(Args, Debug)]
pub struct TotpArgs {
    #[command(subcommand)]
    command: TotpCommand,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
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
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: TotpArgs,
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
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
                config, ui, identity, name, qr, otpauth, secret, issuer, account, url, digits,
                period, algorithm,
            )
            .await?
        }
        TotpCommand::Code { id, watch } => generate_codes(config, ui, id, watch).await?,
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn setup_totp(
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
) -> Result<()> {
    println!("{}", "🔐 Setting up TOTP credential...".cyan());
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

    let url =
        url::Url::parse(trimmed).or_else(|_| url::Url::parse(&format!("https://{trimmed}")))?;
    let scheme = url.scheme();
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("Invalid URL: missing host"))?;

    Ok(format!("{scheme}://{host}"))
}

async fn generate_codes(
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
    id: Uuid,
    watch: bool,
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
    // 协议逻辑统一下沉到 core（RFC 4226/6238），CLI 只做调用。
    let code = totp_now(data)?;
    Ok((code.code, code.remaining_seconds))
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
    use persona_core::crypto::totp::{decode_base32_secret, hotp};
    use persona_core::storage::IdentityRepository;
    use persona_core::Database;
    use persona_core::Repository;
    use proptest::string::string_regex;
    use proptest::{collection, prelude::*, sample::select};
    use tempfile::TempDir;
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
            let decoded = decode_base32_secret(&encoded).unwrap();
            prop_assert_eq!(decoded, bytes);
        }
    }

    // ------------------------------------------------------------------
    // Unit coverage for the command paths (normalize/finalize/hotp/setup).
    // ------------------------------------------------------------------

    #[test]
    fn normalize_origin_url_variants() {
        assert_eq!(
            normalize_origin_url("https://github.com/path?q=1").unwrap(),
            "https://github.com"
        );
        assert_eq!(
            normalize_origin_url("  github.com  ").unwrap(),
            "https://github.com"
        );
        // Host is normalized to lowercase; the port is dropped by design.
        assert_eq!(
            normalize_origin_url("http://Example.COM:8443/x").unwrap(),
            "http://example.com"
        );

        assert!(normalize_origin_url("").is_err());
        assert!(normalize_origin_url("   ").is_err());
        // A scheme-only URL falls through to the https:// prefix retry
        // and yields a (harmless) host named "https".
        let weird = normalize_origin_url("https://").unwrap();
        assert!(weird.starts_with("https://"), "unexpected: {}", weird);
    }

    #[test]
    fn template_merge_keeps_first_value_and_finalize_applies_defaults() {
        let mut template = TotpTemplate::default();
        assert!(
            TotpTemplate::default().finalize().is_err(),
            "missing secret must fail"
        );

        template.secret = Some("FIRST".to_string());
        template.merge(TotpTemplate {
            secret: Some("SECOND".to_string()),
            issuer: Some("GitHub".to_string()),
            account: None,
            algorithm: Some("sha256".to_string()),
            digits: Some(8),
            period: None,
        });

        assert_eq!(template.secret.as_deref(), Some("FIRST"));
        assert_eq!(template.issuer.as_deref(), Some("GitHub"));
        assert!(template.account.is_none());

        let secret = template.secret.clone().unwrap();
        let final_cfg = template.finalize().unwrap();
        assert_eq!(final_cfg.secret, secret);
        assert_eq!(final_cfg.issuer, "GitHub");
        assert_eq!(final_cfg.account, "TOTP");
        assert_eq!(final_cfg.algorithm, "SHA256");
        assert_eq!(final_cfg.digits, 8);
        assert_eq!(final_cfg.period, 30);
    }

    #[test]
    fn hotp_supports_all_algorithms_and_rejects_bad_secrets() {
        let secret = b"0123456789abcdef";
        for algo in ["SHA1", "sha256", "SHA512"] {
            let code = hotp(secret, 7, algo).unwrap();
            let _ = code; // any u32 is a valid truncation
        }
        // Empty secret is rejected before HMAC.
        assert!(hotp(b"", 1, "SHA1").is_err());
    }

    #[test]
    fn decode_secret_accepts_case_whitespace_padding_and_reports_errors() {
        assert_eq!(decode_base32_secret("ME").unwrap(), b"a");
        assert_eq!(decode_base32_secret("me").unwrap(), b"a");
        assert_eq!(decode_base32_secret("M E").unwrap(), b"a");
        assert_eq!(decode_base32_secret("ME======").unwrap(), b"a");
        assert!(decode_base32_secret("not base32!!").is_err());
        assert!(decode_base32_secret("").is_err());
    }

    #[test]
    fn generate_totp_code_clamps_digits_and_period() {
        let cfg = FinalTotpConfig {
            secret: BASE32_NOPAD.encode(b"0123456789abcdef"),
            issuer: "T".into(),
            account: "a@b.c".into(),
            algorithm: "SHA1".into(),
            digits: 99,
            period: 0,
        };
        let (code, remaining) = generate_totp_code(&cfg).unwrap();
        assert_eq!(code.len(), 10, "digits clamped to 10");
        assert!(remaining <= 1, "period clamped to 1s");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn decode_qr_file_reports_missing_files() {
        let err = decode_qr_file(&PathBuf::from("/nonexistent/qr.png")).unwrap_err();
        assert!(err.to_string().contains("Failed to open QR image"));
    }

    #[test]
    fn decode_qr_file_reports_images_without_codes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("blank.png");
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            200,
            200,
            image::Rgb([200, 200, 200]),
        ));
        img.save(&path).expect("blank png written");

        let err = decode_qr_file(&path).unwrap_err();
        assert!(err.to_string().contains("No QR code detected"));
    }

    #[test]
    fn parse_otpauth_uri_rejects_bad_scheme_host_and_garbage() {
        // Not an otpauth URI at all.
        let err = parse_otpauth_uri("https://totp/GitHub:alice?secret=ABC")
            .err()
            .expect("https scheme must be rejected");
        assert!(err.to_string().contains("otpauth://"));

        // otpauth but not TOTP.
        let err = parse_otpauth_uri("otpauth://hotp/GitHub:alice?secret=ABC")
            .err()
            .expect("hotp must be rejected");
        assert!(err.to_string().contains("Only otpauth TOTP URIs"));

        // Unparseable garbage.
        assert!(parse_otpauth_uri("::not a url::").is_err());
    }

    #[test]
    fn parse_otpauth_uri_supports_account_only_labels() {
        let template = parse_otpauth_uri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(template.secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(template.issuer.is_none(), "no issuer label");
        assert_eq!(template.account.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_otpauth_uri_handles_labelless_paths_and_unknown_params() {
        // No path label at all: both issuer and account stay unset.
        let template =
            parse_otpauth_uri("otpauth://totp/?secret=JBSWY3DPEHPK3PXP&x-custom=ignored").unwrap();
        assert_eq!(template.secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(template.issuer.is_none());
        assert!(template.account.is_none());

        // Unknown query parameters are ignored instead of rejected.
        let template = parse_otpauth_uri(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&image=https://x/y.png",
        )
        .unwrap();
        assert_eq!(template.issuer.as_deref(), Some("GitHub"));
        assert_eq!(template.account.as_deref(), Some("alice"));
    }

    #[test]
    fn generate_totp_code_clamps_digits_lower_bound() {
        let cfg = FinalTotpConfig {
            secret: BASE32_NOPAD.encode(b"0123456789abcdef"),
            issuer: "T".into(),
            account: "a@b.c".into(),
            algorithm: "SHA1".into(),
            digits: 1,
            period: 30,
        };
        let (code, _) = generate_totp_code(&cfg).unwrap();
        assert_eq!(code.len(), 4, "digits clamped up to 4");
    }

    fn config_for(dir: &TempDir) -> crate::config::CliConfig {
        let mut config = crate::config::CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// Serializes env mutations against the bridge and service tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        // Recover from a poisoned lock: a panicking sibling test must not
        // cascade into every other env-gated test.
        fn lock_or_recover(lock: &std::sync::Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
            lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }
        (
            lock_or_recover(&crate::commands::bridge::tests::ENV_LOCK),
            lock_or_recover(&ENV_LOCK),
        )
    }

    #[tokio::test]
    async fn setup_then_generate_code_round_trip() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(dir.path().join("identities.db"))
                .await
                .unwrap();
            db.migrate().await.unwrap();
            IdentityRepository::new(db)
                .create(&Identity::new(
                    "alice".to_string(),
                    persona_core::models::IdentityType::Personal,
                ))
                .await
                .unwrap();
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        // Unknown identity is reported before any credential work.
        let err = setup_totp(
            &config,
            &crate::utils::prompt::TerminalUi,
            "ghost".to_string(),
            None,
            None,
            None,
            Some(BASE32_NOPAD.encode(b"secret")),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("unknown identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));

        // Successful setup through the raw --secret path.
        setup_totp(
            &config,
            &crate::utils::prompt::TerminalUi,
            "alice".to_string(),
            None,
            None,
            Some("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".to_string()),
            None,
            None,
            None,
            Some("github.com".to_string()),
            None,
            None,
            None,
        )
        .await
        .expect("setup must succeed");

        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let creds = service
            .get_credentials_for_identity(
                &IdentityRepository::new(service_db(&config).await)
                    .find_by_name("alice")
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
            )
            .await
            .into_anyhow()
            .unwrap();
        assert_eq!(creds.len(), 1, "credential stored");
        assert!(creds[0].url.as_deref() == Some("https://github.com"));
        let totp_id = creds[0].id;
        drop(service);

        // A missing credential id and a non-TOTP credential both fail.
        let err = generate_codes(
            &config,
            &crate::utils::prompt::TerminalUi,
            uuid::Uuid::new_v4(),
            false,
        )
        .await
        .expect_err("missing credential must fail");
        assert!(err.to_string().contains("not found"));

        let db = service_db(&config).await;
        let pw_cred = persona_core::models::Credential::new(
            IdentityRepository::new(db.clone())
                .find_by_name("alice")
                .await
                .unwrap()
                .unwrap()
                .id,
            "plain-password".to_string(),
            persona_core::models::CredentialType::Password,
            persona_core::models::SecurityLevel::High,
            b"pw".to_vec(),
            None,
        );
        persona_core::storage::CredentialRepository::new(db)
            .create(&pw_cred)
            .await
            .unwrap();

        let pw_id = {
            let service = init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
            let id = IdentityRepository::new(service_db(&config).await)
                .find_by_name("alice")
                .await
                .unwrap()
                .unwrap()
                .id;
            let all = service
                .get_credentials_for_identity(&id)
                .await
                .into_anyhow()
                .unwrap();
            all.iter()
                .find(|c| c.credential_type == persona_core::models::CredentialType::Password)
                .unwrap()
                .id
        };
        let err = generate_codes(&config, &crate::utils::prompt::TerminalUi, pw_id, false)
            .await
            .expect_err("non-TOTP credential must fail");
        assert!(err.to_string().contains("is not a TOTP entry"));

        // The real TOTP credential generates a 6-digit code.
        generate_codes(&config, &crate::utils::prompt::TerminalUi, totp_id, false)
            .await
            .expect("code generated");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    async fn service_db(config: &crate::config::CliConfig) -> Database {
        Database::from_file(config.get_database_path())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn execute_dispatches_setup_and_code_subcommands() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            IdentityRepository::new(db.clone())
                .create(&Identity::new(
                    "alice".to_string(),
                    persona_core::models::IdentityType::Personal,
                ))
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        // Setup through the public dispatch wrapper.
        execute_with(
            TotpArgs {
                command: TotpCommand::Setup {
                    identity: "alice".to_string(),
                    name: None,
                    qr: None,
                    otpauth: None,
                    secret: Some(BASE32_NOPAD.encode(b"dispatch")),
                    issuer: Some("Dispatch".to_string()),
                    account: Some("alice@dispatch".to_string()),
                    url: None,
                    digits: None,
                    period: None,
                    algorithm: None,
                },
            },
            &config,
            &crate::utils::prompt::TerminalUi,
        )
        .await
        .expect("dispatched setup succeeds");

        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let alice = IdentityRepository::new(service_db(&config).await)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let creds = service
            .get_credentials_for_identity(&alice.id)
            .await
            .into_anyhow()
            .unwrap();
        assert_eq!(creds.len(), 1);
        let totp_id = creds[0].id;
        drop(service);

        // Code generation through the same wrapper.
        execute_with(
            TotpArgs {
                command: TotpCommand::Code {
                    id: totp_id,
                    watch: false,
                },
            },
            &config,
            &crate::utils::prompt::TerminalUi,
        )
        .await
        .expect("dispatched code generation succeeds");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn public_execute_wrapper_dispatches_to_terminal_ui() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            IdentityRepository::new(db.clone())
                .create(&Identity::new(
                    "alice".to_string(),
                    persona_core::models::IdentityType::Personal,
                ))
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        // The production wrapper shares the TerminalUi-backed path; run the
        // Setup subcommand through `execute` end to end.
        execute(
            TotpArgs {
                command: TotpCommand::Setup {
                    identity: "alice".to_string(),
                    name: None,
                    qr: None,
                    otpauth: None,
                    secret: Some(BASE32_NOPAD.encode(b"wrapper")),
                    issuer: None,
                    account: None,
                    url: None,
                    digits: None,
                    period: None,
                    algorithm: None,
                },
            },
            &config,
        )
        .await
        .expect("public execute wrapper performs the setup");

        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let alice = IdentityRepository::new(service_db(&config).await)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let creds = service
            .get_credentials_for_identity(&alice.id)
            .await
            .into_anyhow()
            .unwrap();
        assert_eq!(creds.len(), 1, "credential stored through the wrapper");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    /// `generate_codes` refuses credentials whose decrypted payload is not
    /// TOTP data even when the row exists.
    #[tokio::test]
    async fn generate_codes_rejects_non_totp_credential_data() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let pw_cred_id: uuid::Uuid;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let identity = IdentityRepository::new(db.clone())
                .create(&Identity::new(
                    "alice".to_string(),
                    persona_core::models::IdentityType::Personal,
                ))
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
            // A password credential: type says TwoFactor is required below.
            let mut cred = service
                .create_credential(
                    identity.id,
                    "pw entry".to_string(),
                    persona_core::CredentialType::Password,
                    persona_core::SecurityLevel::Medium,
                    &persona_core::CredentialData::Password(
                        persona_core::PasswordCredentialData {
                            password: "hunter2".to_string(),
                            email: None,
                            security_questions: vec![],
                        },
                    ),
                )
                .await
                .unwrap();
            // Mislabel the row as TwoFactor so the type gate passes and the
            // decrypted payload mismatch is what surfaces.
            use persona_core::Repository;
            cred.credential_type = persona_core::CredentialType::TwoFactor;
            persona_core::storage::CredentialRepository::new(service_db(&config).await)
                .update(&cred)
                .await
                .unwrap();
            pw_cred_id = cred.id;
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        let err = generate_codes(
            &config,
            &crate::utils::prompt::TerminalUi,
            pw_cred_id,
            false,
        )
        .await
        .expect_err("password payload must not be shown as TOTP");
        assert!(
            err.to_string().contains("does not contain TOTP data"),
            "got: {err}"
        );

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn setup_totp_applies_overrides_and_display_name_precedence() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            IdentityRepository::new(db.clone())
                .create(&Identity::new(
                    "alice".to_string(),
                    persona_core::models::IdentityType::Personal,
                ))
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        // Raw secret with no issuer anywhere: the display name wins over the
        // account fallback, and every override lands in the stored credential.
        setup_totp(
            &config,
            &crate::utils::prompt::TerminalUi,
            "alice".to_string(),
            Some("my authenticator".to_string()),
            None,
            None,
            Some("jbswy3dpehpk3pxp".to_string()), // lowercase → must normalize internally
            None,
            None,
            Some("  https://example.org/login  ".to_string()),
            Some(8),
            Some(60),
            Some("sha512".to_string()),
        )
        .await
        .expect("setup with overrides must succeed");

        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let alice = IdentityRepository::new(service_db(&config).await)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let creds = service
            .get_credentials_for_identity(&alice.id)
            .await
            .into_anyhow()
            .unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].name, "my authenticator");
        assert_eq!(creds[0].url.as_deref(), Some("https://example.org"));
        assert_eq!(creds[0].username.as_deref(), Some("TOTP")); // default account
        assert_eq!(
            creds[0].metadata.get("algorithm").map(String::as_str),
            Some("SHA512")
        );
        assert_eq!(
            creds[0].metadata.get("digits").map(String::as_str),
            Some("8")
        );

        let data = service
            .get_credential_data(&creds[0].id)
            .await
            .into_anyhow()
            .unwrap()
            .expect("two-factor data present");
        match data {
            CredentialData::TwoFactor(totp) => {
                assert_eq!(totp.algorithm, "SHA512");
                assert_eq!(totp.digits, 8);
                assert_eq!(totp.period, 60);
            }
            other => panic!("unexpected data: {:?}", other),
        }
        drop(service);

        // Second credential: no display name and no issuer → the account
        // label becomes the credential name.
        setup_totp(
            &config,
            &crate::utils::prompt::TerminalUi,
            "alice".to_string(),
            None,
            None,
            Some("otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("issuer-less setup must succeed");

        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let creds = service
            .get_credentials_for_identity(&alice.id)
            .await
            .into_anyhow()
            .unwrap();
        assert_eq!(creds.len(), 2);
        let names: Vec<_> = creds.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"alice@example.com"),
            "account fallback used as name: {:?}",
            names
        );

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn setup_requires_unlocked_workspace() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        // No users: init_service bails before any TOTP work.
        let err = setup_totp(
            &config,
            &crate::utils::prompt::TerminalUi,
            "alice".to_string(),
            None,
            None,
            None,
            Some("JBSWY3DPEHPK3PXP".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("uninitialized workspace must fail");
        assert!(err.to_string().contains("Workspace not initialized"));

        // Wrong password is reported instead of prompting.
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let err = setup_totp(
            &config,
            &crate::utils::prompt::TerminalUi,
            "alice".to_string(),
            None,
            None,
            None,
            Some("JBSWY3DPEHPK3PXP".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Authentication failed"));

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }
}
