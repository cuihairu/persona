use anyhow::{anyhow, Result};
use persona_core::models::credential::CredentialData;

/// 该凭据类型上 `field` 的取值；`None` = 该类型没有此字段。
/// 返回 `Some(None)` 语义用 `Option<Option<String>>` 表达不便，
/// 这里改为：字段存在但未设置 → `Err`（`FieldNotSet`），不存在 → `Ok(None)`。
pub(super) fn extract_data_field(data: &CredentialData, field: &str) -> Result<Option<String>> {
    use CredentialData::*;
    let (exists, value) = match data {
        Password(d) => match field {
            "password" => (true, Some(d.password.clone())),
            "email" => (true, d.email.clone()),
            _ => (false, None),
        },
        ApiKey(d) => match field {
            "api_key" => (true, Some(d.api_key.clone())),
            "api_secret" => (true, d.api_secret.clone()),
            "token" => (true, d.token.clone()),
            _ => (false, None),
        },
        TwoFactor(d) => match field {
            "secret_key" => (true, Some(d.secret_key.clone())),
            "issuer" => (true, Some(d.issuer.clone())),
            "account_name" => (true, Some(d.account_name.clone())),
            _ => (false, None),
        },
        SshKey(d) => match field {
            "private_key" => (true, Some(d.private_key.clone())),
            "public_key" => (true, Some(d.public_key.clone())),
            "key_type" => (true, Some(d.key_type.clone())),
            "passphrase" => (true, d.passphrase.clone()),
            _ => (false, None),
        },
        BankCard(d) => match field {
            "card_number" => (true, Some(d.card_number.clone())),
            "cardholder_name" => (true, Some(d.cardholder_name.clone())),
            "expiry_date" => (true, Some(d.expiry_date.clone())),
            "cvv" => (true, Some(d.cvv.clone())),
            "bank_name" => (true, Some(d.bank_name.clone())),
            _ => (false, None),
        },
        ServerConfig(d) => match field {
            "hostname" => (true, Some(d.hostname.clone())),
            "ip_address" => (true, d.ip_address.clone()),
            "port" => (true, Some(d.port.to_string())),
            "protocol" => (true, Some(d.protocol.clone())),
            "username" => (true, Some(d.username.clone())),
            "password" => (true, d.password.clone()),
            _ => (false, None),
        },
        SecureNote(d) => match field {
            "note" => (true, Some(d.note.clone())),
            _ => (false, None),
        },
        CryptoWallet(d) => match field {
            "wallet_type" => (true, Some(d.wallet_type.clone())),
            "mnemonic_phrase" => (true, d.mnemonic_phrase.clone()),
            "private_key" => (true, d.private_key.clone()),
            "public_key" => (true, Some(d.public_key.clone())),
            "address" => (true, Some(d.address.clone())),
            "network" => (true, Some(d.network.clone())),
            _ => (false, None),
        },
        SoftwareLicense(d) => match field {
            "license_key" => (true, Some(d.license_key.clone())),
            "version" => (true, d.version.clone()),
            "publisher" => (true, d.publisher.clone()),
            "purchase_date" => (true, d.purchase_date.clone()),
            "order_number" => (true, d.order_number.clone()),
            "support_email" => (true, d.support_email.clone()),
            "download_url" => (true, d.download_url.clone()),
            _ => (false, None),
        },
        // GameToken/Identity/Raw：没有面向自动化的稳定字段词汇
        _ => (false, None),
    };
    if !exists {
        return Ok(None);
    }
    value.map(Some).ok_or_else(|| {
        anyhow!(
            "field {field:?} is not set on this item (secret refs do not \
                 substitute empty strings)"
        )
    })
}

/// 各类型支持的字段清单（错误提示用）。
pub(super) fn data_fields_of(data: &CredentialData) -> &'static [&'static str] {
    use CredentialData::*;
    match data {
        Password(_) => &["password", "email"],
        ApiKey(_) => &["api_key", "api_secret", "token"],
        TwoFactor(_) => &["secret_key", "issuer", "account_name"],
        SshKey(_) => &["private_key", "public_key", "key_type", "passphrase"],
        BankCard(_) => &[
            "card_number",
            "cardholder_name",
            "expiry_date",
            "cvv",
            "bank_name",
        ],
        ServerConfig(_) => &[
            "hostname",
            "ip_address",
            "port",
            "protocol",
            "username",
            "password",
        ],
        SecureNote(_) => &["note"],
        CryptoWallet(_) => &[
            "wallet_type",
            "mnemonic_phrase",
            "private_key",
            "public_key",
            "address",
            "network",
        ],
        SoftwareLicense(_) => &[
            "license_key",
            "version",
            "publisher",
            "purchase_date",
            "order_number",
            "support_email",
            "download_url",
        ],
        _ => &[],
    }
}

/// `secret` 别名：各类型的主秘密字段。
pub(super) fn primary_secret_field(data: &CredentialData) -> Option<&'static str> {
    use CredentialData::*;
    Some(match data {
        Password(_) => "password",
        ApiKey(_) => "api_key",
        TwoFactor(_) => "secret_key",
        SshKey(_) => "private_key",
        ServerConfig(_) => "password",
        SecureNote(_) => "note",
        CryptoWallet(_) => "private_key",
        SoftwareLicense(_) => "license_key",
        _ => return None,
    })
}
