use super::template::{FinalTotpConfig, TotpTemplate};
use super::*;

pub(crate) fn parse_otpauth_uri(uri: &str) -> Result<TotpTemplate> {
    let url = url::Url::parse(uri).context("Invalid otpauth URI")?;
    if url.scheme() != "otpauth" {
        bail!("URI must start with otpauth://");
    }
    let host = url.host_str().unwrap_or_default();
    if host != "totp" && host != "hotp" {
        bail!("Only otpauth TOTP/HOTP URIs are supported");
    }
    let is_hotp = host == "hotp";
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
    let mut counter = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.to_string()),
            "issuer" => issuer = Some(value.to_string()),
            "account" => account = Some(value.to_string()),
            "algorithm" => algorithm = Some(value.to_string()),
            "digits" => digits = value.parse().ok(),
            "period" => period = value.parse().ok(),
            "counter" => counter = value.parse().ok(),
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
        hotp: Some(is_hotp),
        counter,
    })
}

pub(crate) fn decode_qr_file(path: &PathBuf) -> Result<String> {
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

fn two_factor_from_template(template: &FinalTotpConfig) -> TwoFactorData {
    // 仅供入库前的预览取码：hotp 恒为 None，避免预览路径经 core 调度器
    // 的 HOTP 门禁（预览按调用方显式选择的路径取码，不依赖条目标记）。
    TwoFactorData {
        secret_key: template.secret.clone(),
        issuer: template.issuer.clone(),
        account_name: template.account.clone(),
        algorithm: template.algorithm.clone(),
        digits: template.digits,
        period: template.period,
        hotp: None,
        initial_counter: None,
    }
}

pub(crate) fn generate_totp_code(template: &FinalTotpConfig) -> Result<(String, u32)> {
    let data = two_factor_from_template(template);
    generate_totp_code_from_data(&data)
}

pub(crate) fn generate_hotp_code(template: &FinalTotpConfig, counter: u64) -> Result<String> {
    hotp_code(&two_factor_from_template(template), counter)
}

fn generate_totp_code_from_data(data: &TwoFactorData) -> Result<(String, u32)> {
    // 协议逻辑统一下沉到 core（RFC 4226/6238），CLI 只做调用。
    let code = totp_now(data)?;
    Ok((code.code, code.remaining_seconds))
}
pub(crate) fn normalize_origin_url(raw: &str) -> Result<String> {
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
