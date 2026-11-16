//! 字段级提取：section 字段检索、 concealed 值探测、TOTP 值收集与
//! otpauth:// URI / 裸 base32 密钥解析。

use anyhow::{bail, Context, Result};

use crate::models::credential::TwoFactorData;

use super::{FieldValue, Item, TotpParams};

pub(super) fn infer_key_type(public_key: Option<&str>) -> String {
    if let Some(pk) = public_key {
        let first = pk.split_whitespace().next().unwrap_or("");
        if first.starts_with("ssh-") || first.starts_with("ecdsa-") || first.starts_with("sk-") {
            return first.to_string();
        }
    }
    "unknown".to_string()
}

/// First section-field value whose id or title contains any keyword.
///
/// 1Password-generated fields carry a stable id; user-defined fields often
/// only have a title, so both are matched (id first).
pub(super) fn find_section_value(item: &Item, keywords: &[&str]) -> Option<String> {
    section_fields(item).find_map(|(id, title, value)| {
        let label = match (id, title) {
            (Some(id), _) if !id.trim().is_empty() => id,
            (_, Some(t)) if !t.trim().is_empty() => t,
            _ => return None,
        };
        let label_lower = label.to_lowercase();
        if keywords.iter().any(|k| label_lower.contains(k)) {
            value
        } else {
            None
        }
    })
}

/// First concealed (hidden) section-field value — common for secret material.
pub(super) fn find_concealed_value(item: &Item) -> Option<String> {
    for section in &item.details.sections {
        for f in &section.fields {
            if f.id.as_deref() == Some("credential") {
                continue;
            }
            if let Some(FieldValue::Concealed { concealed }) = &f.value {
                if !concealed.trim().is_empty() {
                    return Some(concealed.trim().to_string());
                }
            }
        }
    }
    None
}

fn section_fields(
    item: &Item,
) -> impl Iterator<Item = (Option<&String>, Option<&String>, Option<String>)> {
    item.details
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .map(|f| {
            (
                f.id.as_ref(),
                f.title.as_ref(),
                f.value
                    .as_ref()
                    .map(|v| v.as_str().trim().to_string())
                    .filter(|v| !v.is_empty()),
            )
        })
}

// ---------------------------------------------------------------------------
// TOTP extraction
// ---------------------------------------------------------------------------

/// Collect TOTP secret values: OTP-type login fields plus "One Time Password"
/// section fields. Values are otpauth:// URIs or bare base32 secrets.
pub(super) fn collect_totp_values(item: &Item) -> Vec<String> {
    let mut out = Vec::new();
    for f in &item.details.login_fields {
        if f.field_type.as_deref() == Some("OTP") {
            if let Some(v) = f.value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                out.push(v.to_string());
            }
        }
    }
    for section in &item.details.sections {
        for f in &section.fields {
            let is_totp =
                f.id.as_deref()
                    .is_some_and(|id| id.eq_ignore_ascii_case("ONE_TIME_PASSWORD"))
                    || f.id
                        .as_deref()
                        .is_some_and(|id| id.eq_ignore_ascii_case("totp"))
                    || f.title
                        .as_deref()
                        .is_some_and(|t| t.to_lowercase().contains("one time password"));
            if is_totp {
                if let Some(v) = f
                    .value
                    .as_ref()
                    .map(|v| v.as_str().trim().to_string())
                    .filter(|v| !v.is_empty())
                {
                    out.push(v);
                }
            }
        }
    }
    out
}

pub(crate) fn parse_totp_value(
    value: &str,
    fallback_issuer: &str,
    fallback_account: Option<&str>,
) -> Result<TwoFactorData> {
    let params = if value.starts_with("otpauth://") {
        parse_otpauth_uri(value)?
    } else {
        TotpParams {
            secret_key: Some(value.to_string()),
            issuer: None,
            account_name: None,
            algorithm: None,
            digits: None,
            period: None,
            hotp: None,
            counter: None,
        }
    };

    let secret_key = params
        .secret_key
        .filter(|s| !s.trim().is_empty())
        .context("TOTP secret missing")?;

    Ok(TwoFactorData {
        secret_key,
        issuer: params
            .issuer
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| fallback_issuer.to_string()),
        account_name: params
            .account_name
            .filter(|s| !s.trim().is_empty())
            .or_else(|| fallback_account.map(str::to_string))
            .unwrap_or_default(),
        algorithm: params
            .algorithm
            .map(|a| a.to_uppercase())
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| "SHA1".to_string()),
        digits: params.digits.unwrap_or(6),
        hotp: params.hotp,
        initial_counter: params.counter,
        period: params.period.unwrap_or(30),
    })
}

/// Parse an `otpauth://totp/...` or `otpauth://hotp/...` URI (mirrors the CLI
/// TOTP template parser). HOTP 条目按计数器型入库，`counter` 参数作缺省起点。
pub(super) fn parse_otpauth_uri(uri: &str) -> Result<TotpParams> {
    let url = url::Url::parse(uri).context("invalid otpauth URI")?;
    if url.scheme() != "otpauth" {
        bail!("URI must start with otpauth://");
    }
    let is_hotp = match url.host_str() {
        Some("totp") => false,
        Some("hotp") => true,
        _ => bail!("only otpauth TOTP/HOTP URIs are supported"),
    };
    let path = url.path().trim_start_matches('/');
    let (issuer_label, account_label) = match path.find(':') {
        Some(pos) => (
            path[..pos].trim().to_string(),
            path[pos + 1..].trim().to_string(),
        ),
        None => (String::new(), path.trim().to_string()),
    };

    let mut params = TotpParams {
        secret_key: None,
        issuer: (!issuer_label.is_empty()).then_some(issuer_label),
        account_name: (!account_label.is_empty()).then_some(account_label),
        algorithm: None,
        digits: None,
        period: None,
        hotp: Some(is_hotp),
        counter: None,
    };

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => params.secret_key = Some(value.to_string()),
            "issuer" => params.issuer = Some(value.to_string()),
            "account" => params.account_name = Some(value.to_string()),
            "algorithm" => params.algorithm = Some(value.to_string()),
            "digits" => params.digits = value.parse().ok(),
            "period" => params.period = value.parse().ok(),
            "counter" => params.counter = value.parse().ok(),
            _ => {}
        }
    }

    Ok(params)
}
