// ---------------------------------------------------------------------------
// Bitwarden JSON schema (plaintext export; lenient: missing fields read as None)
// ---------------------------------------------------------------------------

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::import_1pux::{ImportPlan, PlannedCredential, SkippedItem};
use crate::models::credential::{
    BankCardData, CredentialData, CredentialType, SecureNoteData, SecurityLevel, SshKeyData,
};

use super::plan::{generic_identity, plan_login_like};
use super::{strip_utf8_bom, BitwardenExport, GENERIC_VAULT_KEY};

#[derive(Debug, Clone, Deserialize)]
struct BitwardenFile {
    #[serde(default)]
    folders: Vec<BitwardenFolder>,
    #[serde(default)]
    items: Vec<BitwardenItem>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenFolder {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenItem {
    #[serde(rename = "type")]
    kind: i64,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    favorite: Option<bool>,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(default)]
    login: Option<BitwardenLogin>,
    #[serde(default)]
    card: Option<BitwardenCard>,
    #[serde(default)]
    ssh_key: Option<BitwardenSshKey>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BitwardenUri>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenUri {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenCard {
    #[serde(default)]
    cardholder_name: Option<String>,
    #[serde(default)]
    brand: Option<String>,
    #[serde(default)]
    number: Option<String>,
    #[serde(default)]
    exp_month: Option<StringOrNumber>,
    #[serde(default)]
    exp_year: Option<StringOrNumber>,
    #[serde(default)]
    code: Option<StringOrNumber>,
}

/// Bitwarden's exp_month/exp_year/code are usually strings in a plaintext JSON,
/// but some exporters write them as numbers — accept both.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum StringOrNumber {
    Text(String),
    Number(serde_json::Number),
}

impl StringOrNumber {
    fn as_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            StringOrNumber::Text(s) => std::borrow::Cow::Borrowed(s),
            StringOrNumber::Number(n) => std::borrow::Cow::Owned(n.to_string()),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenSshKey {
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
}

pub(super) fn parse_bitwarden_json(bytes: &[u8]) -> Result<BitwardenExport> {
    let value: serde_json::Value =
        serde_json::from_slice(strip_utf8_bom(bytes)).context("Bitwarden JSON 解析失败")?;

    // A password-protected export must be intercepted before items: every field is
    // ciphertext, so parsing is pointless.
    if value.get("encrypted").and_then(|e| e.as_bool()) == Some(true) {
        bail!(
            "该 Bitwarden JSON 是密码保护导出（encrypted: true），内容为密文；\
             请在 Bitwarden 导出时不设置导出密码（明文 JSON）后重试"
        );
    }

    let file: BitwardenFile = if value.is_array() {
        BitwardenFile {
            folders: Vec::new(),
            items: serde_json::from_value(value).context("Bitwarden items 解析失败")?,
        }
    } else {
        serde_json::from_value(value).context("Bitwarden 导出结构解析失败")?
    };

    Ok(BitwardenExport {
        folders: file.folders,
        items: file.items,
    })
}

pub(super) fn plan_bitwarden(
    export: &BitwardenExport,
    identity_name: &str,
    source_label: &str,
) -> ImportPlan {
    let folders: HashMap<String, String> = export
        .folders
        .iter()
        .filter_map(|f| {
            let id = f.id.as_ref()?.clone();
            let name = f.name.clone().unwrap_or(id.clone());
            Some((id, name))
        })
        .collect();

    let mut plan = ImportPlan {
        identities: vec![generic_identity(identity_name, source_label)],
        ..ImportPlan::default()
    };

    for item in &export.items {
        let name = item
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("Untitled ({})", item.id.as_deref().unwrap_or("unknown")));
        let notes = item.notes.clone().filter(|n| !n.trim().is_empty());
        let tags: Vec<String> = item
            .folder_id
            .as_ref()
            .and_then(|id| folders.get(id).cloned())
            .into_iter()
            .collect();
        let is_favorite = item.favorite.unwrap_or(false);

        match item.kind {
            1 => {
                let login = item.login.clone().unwrap_or_default();
                let uris: Vec<String> = login
                    .uris
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|u| u.uri)
                    .filter(|u| !u.trim().is_empty())
                    .collect();
                let url = uris.first().cloned();
                let mut metadata = HashMap::new();
                if uris.len() > 1 {
                    metadata.insert("alt_urls".to_string(), uris[1..].join("\n"));
                }
                let totp = login.totp.clone().filter(|t| !t.trim().is_empty());
                plan_login_like(
                    &mut plan,
                    name,
                    login.username.clone().filter(|u| !u.trim().is_empty()),
                    login.password.clone().filter(|p| !p.trim().is_empty()),
                    totp,
                    url,
                    notes,
                    tags,
                    is_favorite,
                    metadata,
                );
            }
            2 => plan.credentials.push(PlannedCredential {
                vault_uuid: GENERIC_VAULT_KEY.to_string(),
                name,
                credential_type: CredentialType::SecureNote,
                security_level: SecurityLevel::High,
                credential_data: CredentialData::SecureNote(SecureNoteData {
                    note: notes.unwrap_or_default(),
                }),
                url: None,
                username: None,
                notes: None,
                tags,
                metadata: HashMap::new(),
                is_favorite,
            }),
            3 => {
                let card = item.card.clone().unwrap_or_default();
                let expiry_date = match (&card.exp_month, &card.exp_year) {
                    (Some(month), Some(year)) => {
                        format!("{}/{}", month.as_str().trim(), year.as_str().trim())
                    }
                    (Some(month), None) => month.as_str().trim().to_string(),
                    (None, Some(year)) => year.as_str().trim().to_string(),
                    (None, None) => String::new(),
                };
                let brand = card.brand.clone().unwrap_or_default();
                plan.credentials.push(PlannedCredential {
                    vault_uuid: GENERIC_VAULT_KEY.to_string(),
                    name,
                    credential_type: CredentialType::BankCard,
                    security_level: SecurityLevel::High,
                    credential_data: CredentialData::BankCard(BankCardData {
                        card_number: card.number.unwrap_or_default(),
                        cardholder_name: card.cardholder_name.unwrap_or_default(),
                        expiry_date,
                        cvv: card
                            .code
                            .map(|c| c.as_str().to_string())
                            .unwrap_or_default(),
                        // Bitwarden exports carry no bank name; the brand goes into card_type.
                        bank_name: String::new(),
                        card_type: brand,
                    }),
                    url: None,
                    username: None,
                    notes,
                    tags,
                    metadata: HashMap::new(),
                    is_favorite,
                });
            }
            4 => plan.skipped.push(SkippedItem {
                vault_name: identity_name.to_string(),
                title: name,
                category: "Bitwarden Identity".to_string(),
                reason: "身份条目字段与 persona 模型差异大，强行映射会有损；未导入".to_string(),
            }),
            5 => {
                let ssh = item.ssh_key.clone().unwrap_or_default();
                let public_key = ssh.public_key.unwrap_or_default();
                let private_key = ssh.private_key.unwrap_or_default();
                if public_key.trim().is_empty() && private_key.trim().is_empty() {
                    plan.skipped.push(SkippedItem {
                        vault_name: identity_name.to_string(),
                        title: name,
                        category: "Bitwarden SSH Key".to_string(),
                        reason: "SSH key 条目没有密钥材料".to_string(),
                    });
                    continue;
                }
                // The first token of the public key is the algorithm name ("ssh-ed25519 AAAA...")
                let key_type = public_key
                    .split_whitespace()
                    .next()
                    .unwrap_or("ssh")
                    .to_string();
                plan.credentials.push(PlannedCredential {
                    vault_uuid: GENERIC_VAULT_KEY.to_string(),
                    name,
                    credential_type: CredentialType::SshKey,
                    security_level: SecurityLevel::High,
                    credential_data: CredentialData::SshKey(SshKeyData {
                        private_key,
                        public_key,
                        key_type,
                        passphrase: None,
                    }),
                    url: None,
                    username: None,
                    notes,
                    tags,
                    metadata: HashMap::new(),
                    is_favorite,
                });
            }
            unknown => plan.skipped.push(SkippedItem {
                vault_name: identity_name.to_string(),
                title: name,
                category: format!("Bitwarden type {unknown}"),
                reason: "未知的 Bitwarden 条目类型".to_string(),
            }),
        }
    }

    plan
}
