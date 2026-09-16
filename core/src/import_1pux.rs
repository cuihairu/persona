//! 1Password 1PUX export parsing and import planning.
//!
//! A `.1pux` file is an unencrypted ZIP archive containing `export.attributes`
//! (metadata) and `export.data` (accounts → vaults → items). This module parses
//! that container into a typed snapshot ([`OnePasswordExport`]) and turns it
//! into an [`ImportPlan`] — a pure, side-effect-free mapping that the CLI (and
//! later the desktop app) can preview, confirm, and apply.
//!
//! Mapping policy: every 1Password vault becomes one persona identity; only
//! categories with a clean persona equivalent are imported (Login → password
//! credential with the TOTP split out, API Credential, SSH Key); everything
//! else is reported as skipped instead of being forced into a lossy shape.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::models::credential::{
    ApiKeyData, CredentialData, CredentialType, PasswordCredentialData, SecurityLevel, SshKeyData,
    TwoFactorData,
};

// 1Password categoryUuid values we understand. Everything else is skipped.
const CATEGORY_LOGIN: &str = "001";
const CATEGORY_API_CREDENTIAL: &str = "112";
const CATEGORY_SSH_KEY: &str = "114";

/// Readable names for skip reports (subset of the 1Password category table).
fn category_name(uuid: &str) -> String {
    let name = match uuid {
        "001" => "Login",
        "002" => "Credit Card",
        "003" => "Secure Note",
        "004" => "Identity",
        "005" => "Password",
        "006" => "Document",
        "100" => "Software License",
        "101" => "Bank Account",
        "103" => "Driver License",
        "105" => "Membership",
        "106" => "Passport",
        "107" => "Reward",
        "108" => "SSN",
        "109" => "Wireless Router",
        "110" => "Server",
        "112" => "API Credential",
        "114" => "SSH Key",
        _ => return format!("Unknown category ({uuid})"),
    };
    name.to_string()
}

// ---------------------------------------------------------------------------
// 1PUX schema (lenient: unknown fields ignored, everything optional-ish)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportAttributes {
    version: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExportData {
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Debug, Clone, Deserialize)]
struct Account {
    #[serde(default)]
    vaults: Vec<Vault>,
}

#[derive(Debug, Clone, Deserialize)]
struct Vault {
    attrs: VaultAttrs,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultAttrs {
    uuid: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    uuid: String,
    #[serde(default)]
    fav_index: Option<i64>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    category_uuid: Option<String>,
    #[serde(default)]
    overview: Overview,
    #[serde(default)]
    details: ItemDetails,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Overview {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urls: Vec<UrlEntry>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UrlEntry {
    #[serde(default)]
    href: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ItemDetails {
    #[serde(default)]
    login_fields: Vec<LoginField>,
    #[serde(default)]
    notes_plain: Option<String>,
    #[serde(default)]
    sections: Vec<Section>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginField {
    #[serde(rename = "type")]
    #[serde(default)]
    field_type: Option<String>,
    #[serde(default)]
    designation: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Section {
    #[serde(default)]
    fields: Vec<SectionField>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SectionField {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    value: Option<FieldValue>,
}

/// Section field values are either plain strings or concealed objects.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum FieldValue {
    Concealed {
        concealed: String,
    },
    Plain(String),
    #[allow(dead_code)] // keeps untagged deserialization from failing on numeric values
    Number(f64),
}

impl FieldValue {
    fn as_str(&self) -> &str {
        match self {
            FieldValue::Concealed { concealed } => concealed,
            FieldValue::Plain(s) => s,
            FieldValue::Number(_) => "",
        }
    }
}

/// A parsed 1PUX archive: the account/vault/item tree.
///
/// Format attributes (including the version check) are validated during
/// [`parse_1pux`] and not retained.
#[derive(Debug, Clone)]
pub struct OnePasswordExport {
    accounts: Vec<Account>,
}

// ---------------------------------------------------------------------------
// Container parsing
// ---------------------------------------------------------------------------

/// Parse the raw bytes of a `.1pux` file (unencrypted ZIP).
pub fn parse_1pux(bytes: &[u8]) -> Result<OnePasswordExport> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .context("not a valid 1PUX archive (expected an unencrypted ZIP)")?;
    let attributes_json = read_zip_entry(&mut zip, "export.attributes")?;
    let data_json = read_zip_entry(&mut zip, "export.data")?;

    let attributes: ExportAttributes =
        serde_json::from_str(&attributes_json).context("export.attributes is not valid JSON")?;
    let data: ExportData =
        serde_json::from_str(&data_json).context("export.data is not valid JSON")?;

    // 1PUX version 3 is the only documented format; other versions are parsed
    // leniently with a warning rather than rejected.
    if attributes.version != Some(3) {
        tracing::warn!(
            version = ?attributes.version,
            "unexpected 1PUX format version (expected 3); parsing anyway"
        );
    }

    Ok(OnePasswordExport {
        accounts: data.accounts,
    })
}

fn read_zip_entry(zip: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<String> {
    let mut file = zip
        .by_name(name)
        .with_context(|| format!("missing {name} in 1PUX archive"))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .with_context(|| format!("failed to read {name} from 1PUX archive"))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Import planning
// ---------------------------------------------------------------------------

/// A persona identity to create for a 1Password vault.
#[derive(Debug, Clone)]
pub struct PlannedIdentity {
    /// 1Password vault UUID, used to link planned credentials back to this identity.
    pub vault_uuid: String,
    pub name: String,
    pub description: String,
}

/// A persona credential to create, with all fields the importer can fill.
#[derive(Debug, Clone)]
pub struct PlannedCredential {
    /// Owning vault UUID (links to [`PlannedIdentity::vault_uuid`]).
    pub vault_uuid: String,
    pub name: String,
    pub credential_type: CredentialType,
    pub security_level: SecurityLevel,
    pub credential_data: CredentialData,
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub is_favorite: bool,
}

/// An item that will not be imported, with a human-readable reason.
#[derive(Debug, Clone)]
pub struct SkippedItem {
    pub vault_name: String,
    pub title: String,
    pub category: String,
    pub reason: String,
}

/// The full result of mapping a 1PUX export onto persona structures.
#[derive(Debug, Clone, Default)]
pub struct ImportPlan {
    pub identities: Vec<PlannedIdentity>,
    pub credentials: Vec<PlannedCredential>,
    pub skipped: Vec<SkippedItem>,
}

/// Map a parsed 1PUX export onto persona identities/credentials.
///
/// Pure logic, no IO: the caller applies the plan (creating identities and
/// credentials) after showing it for confirmation.
pub fn plan_import(export: &OnePasswordExport) -> ImportPlan {
    let mut plan = ImportPlan::default();

    for account in &export.accounts {
        for vault in &account.vaults {
            let vault_name = vault.attrs.name.clone();
            plan.identities.push(PlannedIdentity {
                vault_uuid: vault.attrs.uuid.clone(),
                name: vault_name.clone(),
                description: format!("Imported from 1Password vault {}", vault.attrs.uuid),
            });

            for item in &vault.items {
                plan_item(&vault.attrs.uuid, &vault_name, item, &mut plan);
            }
        }
    }

    plan
}

fn plan_item(vault_uuid: &str, vault_name: &str, item: &Item, plan: &mut ImportPlan) {
    let title = item
        .overview
        .title
        .clone()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| format!("Untitled ({})", item.uuid));
    let category = item
        .category_uuid
        .as_deref()
        .map(category_name)
        .unwrap_or_else(|| "Unknown category".to_string());

    if item
        .state
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("ARCHIVED"))
    {
        plan.skipped.push(SkippedItem {
            vault_name: vault_name.to_string(),
            title,
            category,
            reason: "archived item".to_string(),
        });
        return;
    }

    let outcome = match item.category_uuid.as_deref() {
        Some(CATEGORY_LOGIN) => Ok(map_login(vault_uuid, vault_name, item, &title)),
        Some(CATEGORY_API_CREDENTIAL) => map_api_key(vault_uuid, item, &title)
            .map(|c| (vec![c], Vec::new()))
            .map_err(|reason| (title.clone(), reason)),
        Some(CATEGORY_SSH_KEY) => map_ssh_key(vault_uuid, item, &title)
            .map(|c| (vec![c], Vec::new()))
            .map_err(|reason| (title.clone(), reason)),
        _ => Err((
            title.clone(),
            format!(
                "category {} is not supported for import",
                item.category_uuid.as_deref().unwrap_or("(missing)")
            ),
        )),
    };

    match outcome {
        Ok((credentials, mut skipped)) => {
            plan.credentials.extend(credentials);
            plan.skipped.append(&mut skipped);
        }
        Err((skip_title, reason)) => plan.skipped.push(SkippedItem {
            vault_name: vault_name.to_string(),
            title: skip_title,
            category,
            reason,
        }),
    }
}

/// Common presentation fields shared by every mapped credential.
#[derive(Clone)]
struct ItemShell {
    vault_uuid: String,
    name: String,
    url: Option<String>,
    username: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    is_favorite: bool,
    /// Secondary URLs beyond the first one, joined with newlines.
    alt_urls: Option<String>,
}

fn item_shell(vault_uuid: &str, item: &Item, name: String) -> ItemShell {
    let mut hrefs: Vec<String> = item
        .overview
        .urls
        .iter()
        .filter_map(|u| u.href.clone())
        .filter(|h| !h.trim().is_empty())
        .collect();
    if hrefs.is_empty() {
        if let Some(url) = item.overview.url.clone().filter(|h| !h.trim().is_empty()) {
            hrefs.push(url);
        }
    }
    let alt_urls = if hrefs.len() > 1 {
        Some(hrefs[1..].join("\n"))
    } else {
        None
    };

    ItemShell {
        vault_uuid: vault_uuid.to_string(),
        name,
        url: hrefs.into_iter().next(),
        username: login_designation_value(item, "username"),
        notes: item
            .details
            .notes_plain
            .clone()
            .filter(|n| !n.trim().is_empty()),
        tags: item
            .overview
            .tags
            .iter()
            .map(|t| t.trim().to_string())
            .collect(),
        is_favorite: item.fav_index.unwrap_or(0) > 0,
        alt_urls,
    }
}

fn finish_credential(
    shell: ItemShell,
    credential_type: CredentialType,
    security_level: SecurityLevel,
    credential_data: CredentialData,
) -> PlannedCredential {
    let mut metadata = HashMap::new();
    if let Some(alt) = &shell.alt_urls {
        metadata.insert("alt_urls".to_string(), alt.clone());
    }
    PlannedCredential {
        vault_uuid: shell.vault_uuid,
        name: shell.name,
        credential_type,
        security_level,
        credential_data,
        url: shell.url.clone(),
        username: shell.username.clone(),
        notes: shell.notes.clone(),
        tags: shell.tags.clone(),
        metadata,
        is_favorite: shell.is_favorite,
    }
}

fn login_designation_value(item: &Item, designation: &str) -> Option<String> {
    item.details
        .login_fields
        .iter()
        .find(|f| f.designation.as_deref() == Some(designation))
        .and_then(|f| f.value.clone())
        .filter(|v| !v.trim().is_empty())
}

// ---------------------------------------------------------------------------
// Category mappings
// ---------------------------------------------------------------------------

fn map_login(
    vault_uuid: &str,
    vault_name: &str,
    item: &Item,
    title: &str,
) -> (Vec<PlannedCredential>, Vec<SkippedItem>) {
    let shell = item_shell(vault_uuid, item, title.to_string());
    let mut skipped = Vec::new();

    // Email: an email-type login field wins, otherwise an @-shaped username.
    let email = item
        .details
        .login_fields
        .iter()
        .find(|f| f.field_type.as_deref() == Some("E"))
        .and_then(|f| f.value.clone())
        .filter(|v| !v.trim().is_empty())
        .or_else(|| shell.username.as_ref().filter(|u| u.contains('@')).cloned());

    let mut credentials = vec![finish_credential(
        shell.clone(),
        CredentialType::Password,
        SecurityLevel::High,
        CredentialData::Password(PasswordCredentialData {
            password: login_designation_value(item, "password").unwrap_or_default(),
            email,
            security_questions: Vec::new(),
        }),
    )];

    // TOTP lives in a dedicated "One Time Password" field; split it out as its
    // own credential so the login stays a plain password item.
    for value in collect_totp_values(item) {
        let totp_name = format!("{title} (TOTP)");
        match parse_totp_value(&value, title, shell.username.as_deref()) {
            Ok(data) => credentials.push(finish_credential(
                item_shell(vault_uuid, item, totp_name),
                CredentialType::TwoFactor,
                SecurityLevel::High,
                CredentialData::TwoFactor(data),
            )),
            Err(err) => skipped.push(SkippedItem {
                vault_name: vault_name.to_string(),
                title: totp_name,
                category: category_name(CATEGORY_LOGIN),
                reason: format!("TOTP field skipped: {err:#}"),
            }),
        }
    }

    (credentials, skipped)
}

fn map_api_key(
    vault_uuid: &str,
    item: &Item,
    title: &str,
) -> std::result::Result<PlannedCredential, String> {
    let shell = item_shell(vault_uuid, item, title.to_string());

    // Best-effort key lookup: the dedicated "credential" section field, any
    // concealed field, then the password login field.
    let api_key = find_section_value(item, &["credential"])
        .or_else(|| find_concealed_value(item))
        .or_else(|| login_designation_value(item, "password"))
        .ok_or_else(|| "API key value not found in sections or login fields".to_string())?;

    let mut credential = finish_credential(
        shell,
        CredentialType::ApiKey,
        SecurityLevel::High,
        CredentialData::ApiKey(ApiKeyData {
            api_key,
            api_secret: None,
            token: None,
            permissions: Vec::new(),
            expires_at: None,
        }),
    );
    if let Some(username) = &credential.username {
        credential
            .metadata
            .insert("username".to_string(), username.clone());
    }
    Ok(credential)
}

fn map_ssh_key(
    vault_uuid: &str,
    item: &Item,
    title: &str,
) -> std::result::Result<PlannedCredential, String> {
    let shell = item_shell(vault_uuid, item, title.to_string());

    let private_key = find_section_value(item, &["private key"])
        .ok_or_else(|| "private key not found in sections".to_string())?;
    let public_key = find_section_value(item, &["public key"]);
    let key_type = find_section_value(item, &["key type"])
        .unwrap_or_else(|| infer_key_type(public_key.as_deref()));

    Ok(finish_credential(
        shell,
        CredentialType::SshKey,
        SecurityLevel::High,
        CredentialData::SshKey(SshKeyData {
            private_key,
            public_key: public_key.unwrap_or_default(),
            key_type,
            passphrase: find_section_value(item, &["passphrase"]),
        }),
    ))
}

fn infer_key_type(public_key: Option<&str>) -> String {
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
fn find_section_value(item: &Item, keywords: &[&str]) -> Option<String> {
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
fn find_concealed_value(item: &Item) -> Option<String> {
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
fn collect_totp_values(item: &Item) -> Vec<String> {
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

#[derive(Debug)]
struct TotpParams {
    secret_key: Option<String>,
    issuer: Option<String>,
    account_name: Option<String>,
    algorithm: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
}

fn parse_totp_value(
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
        period: params.period.unwrap_or(30),
    })
}

/// Parse an `otpauth://totp/...` URI (mirrors the CLI TOTP template parser).
fn parse_otpauth_uri(uri: &str) -> Result<TotpParams> {
    let url = url::Url::parse(uri).context("invalid otpauth URI")?;
    if url.scheme() != "otpauth" {
        bail!("URI must start with otpauth://");
    }
    if url.host_str() != Some("totp") {
        bail!("only otpauth://totp URIs are supported");
    }
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
    };

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => params.secret_key = Some(value.to_string()),
            "issuer" => params.issuer = Some(value.to_string()),
            "account" => params.account_name = Some(value.to_string()),
            "algorithm" => params.algorithm = Some(value.to_string()),
            "digits" => params.digits = value.parse().ok(),
            "period" => params.period = value.parse().ok(),
            _ => {}
        }
    }

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;
    use std::io::Write;

    fn make_1pux(attributes: &str, data: &str) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("export.attributes", options).unwrap();
        writer.write_all(attributes.as_bytes()).unwrap();
        writer.start_file("export.data", options).unwrap();
        writer.write_all(data.as_bytes()).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn attributes_json(version: u64) -> String {
        json!({ "version": version, "description": "test export", "createdAt": 0 }).to_string()
    }

    fn export_data(items: serde_json::Value) -> String {
        json!({
            "accounts": [{
                "attrs": { "uuid": "acc-1", "name": "Account" },
                "vaults": [{
                    "attrs": { "uuid": "vault-1", "name": "Personal" },
                    "items": items
                }]
            }]
        })
        .to_string()
    }

    fn plan_from_items(items: serde_json::Value) -> ImportPlan {
        let bytes = make_1pux(&attributes_json(3), &export_data(items));
        let export = parse_1pux(&bytes).unwrap();
        plan_import(&export)
    }

    fn login_item() -> serde_json::Value {
        json!({
            "uuid": "item-1",
            "categoryUuid": "001",
            "state": "ACTIVE",
            "favIndex": 2,
            "createdAt": 1600000000,
            "updatedAt": 1600000100,
            "overview": {
                "title": "Example",
                "url": "https://example.com",
                "urls": [
                    { "label": "website", "href": "https://example.com" },
                    { "label": "login", "href": "https://example.com/login" }
                ],
                "tags": ["web", " work "]
            },
            "details": {
                "loginFields": [
                    { "id": "username", "type": "T", "designation": "username", "value": "alice@example.com" },
                    { "id": "password", "type": "P", "designation": "password", "value": "hunter2" }
                ],
                "notesPlain": "note text",
                "sections": []
            }
        })
    }

    #[test]
    fn login_maps_to_password_credential() {
        let plan = plan_from_items(json!([login_item()]));
        assert_eq!(plan.identities.len(), 1);
        assert_eq!(plan.identities[0].name, "Personal");
        assert_eq!(
            plan.identities[0].description,
            "Imported from 1Password vault vault-1"
        );
        assert_eq!(plan.skipped.len(), 0);

        let cred = &plan.credentials[0];
        assert_eq!(cred.vault_uuid, "vault-1");
        assert_eq!(cred.name, "Example");
        assert_eq!(cred.credential_type, CredentialType::Password);
        assert_eq!(cred.security_level, SecurityLevel::High);
        assert_eq!(cred.url.as_deref(), Some("https://example.com"));
        assert_eq!(cred.username.as_deref(), Some("alice@example.com"));
        assert_eq!(cred.notes.as_deref(), Some("note text"));
        assert_eq!(cred.tags, vec!["web".to_string(), "work".to_string()]);
        assert_eq!(
            cred.metadata.get("alt_urls").map(String::as_str),
            Some("https://example.com/login")
        );
        assert!(cred.is_favorite);
        match &cred.credential_data {
            CredentialData::Password(p) => {
                assert_eq!(p.password, "hunter2");
                assert_eq!(p.email.as_deref(), Some("alice@example.com"));
            }
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    #[test]
    fn totp_otpauth_uri_splits_into_two_factor_credential() {
        let item = json!({
            "uuid": "item-2",
            "categoryUuid": "001",
            "overview": { "title": "Example", "urls": [{ "href": "https://example.com" }] },
            "details": {
                "loginFields": [
                    { "id": "username", "type": "T", "designation": "username", "value": "alice" },
                    { "id": "password", "type": "P", "designation": "password", "value": "hunter2" }
                ],
                "sections": [{
                    "title": "",
                    "fields": [{
                        "id": "ONE_TIME_PASSWORD",
                        "title": "One Time Password",
                        "value": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60"
                    }]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        assert_eq!(plan.credentials.len(), 2);
        let totp = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::TwoFactor)
            .expect("TOTP credential");
        assert_eq!(totp.name, "Example (TOTP)");
        assert_eq!(totp.url.as_deref(), Some("https://example.com"));
        match &totp.credential_data {
            CredentialData::TwoFactor(t) => {
                assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
                assert_eq!(t.issuer, "Example");
                assert_eq!(t.account_name, "alice");
                assert_eq!(t.algorithm, "SHA256");
                assert_eq!(t.digits, 8);
                assert_eq!(t.period, 60);
            }
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    #[test]
    fn totp_bare_base32_gets_defaults() {
        let item = json!({
            "uuid": "item-3",
            "categoryUuid": "001",
            "overview": { "title": "Bare" },
            "details": {
                "loginFields": [
                    { "id": "username", "type": "T", "designation": "username", "value": "bob" },
                    { "id": "password", "type": "P", "designation": "password", "value": "pw" },
                    { "id": "totp", "type": "OTP", "designation": null, "value": "JBSWY3DPEHPK3PXP" }
                ]
            }
        });
        let plan = plan_from_items(json!([item]));

        let totp = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::TwoFactor)
            .expect("TOTP credential");
        assert_eq!(totp.name, "Bare (TOTP)");
        match &totp.credential_data {
            CredentialData::TwoFactor(t) => {
                assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
                assert_eq!(t.issuer, "Bare");
                assert_eq!(t.account_name, "bob");
                assert_eq!(t.algorithm, "SHA1");
                assert_eq!(t.digits, 6);
                assert_eq!(t.period, 30);
            }
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    #[test]
    fn unparseable_totp_is_reported_but_login_imports() {
        let item = json!({
            "uuid": "item-4",
            "categoryUuid": "001",
            "overview": { "title": "Broken" },
            "details": {
                "loginFields": [
                    { "id": "password", "type": "P", "designation": "password", "value": "pw" }
                ],
                "sections": [{
                    "fields": [{
                        "id": "ONE_TIME_PASSWORD",
                        "value": "otpauth://totp/NoSecret"
                    }]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        assert_eq!(plan.credentials.len(), 1);
        assert_eq!(
            plan.credentials[0].credential_type,
            CredentialType::Password
        );
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].title, "Broken (TOTP)");
        assert!(plan.skipped[0].reason.contains("secret"));
    }

    #[test]
    fn api_key_category_maps_with_concealed_value() {
        let item = json!({
            "uuid": "item-5",
            "categoryUuid": "112",
            "overview": { "title": "Service token", "urls": [{ "href": "https://api.example.com" }] },
            "details": {
                "loginFields": [
                    { "id": "username", "type": "T", "designation": "username", "value": "svc-user" }
                ],
                "sections": [{
                    "title": "",
                    "fields": [
                        { "id": "credential", "title": "Credential", "value": { "concealed": "sk-live-123" } },
                        { "id": "service", "title": "Service", "value": "Example API" }
                    ]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        assert_eq!(plan.credentials.len(), 1);
        let cred = &plan.credentials[0];
        assert_eq!(cred.credential_type, CredentialType::ApiKey);
        assert_eq!(cred.name, "Service token");
        match &cred.credential_data {
            CredentialData::ApiKey(a) => {
                assert_eq!(a.api_key, "sk-live-123");
                assert!(a.permissions.is_empty());
            }
            other => panic!("unexpected credential data: {other:?}"),
        }
        assert_eq!(
            cred.metadata.get("username").map(String::as_str),
            Some("svc-user")
        );
    }

    #[test]
    fn api_key_without_value_is_skipped() {
        let item = json!({
            "uuid": "item-6",
            "categoryUuid": "112",
            "overview": { "title": "Empty" },
            "details": { "sections": [] }
        });
        let plan = plan_from_items(json!([item]));

        assert!(plan.credentials.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert!(plan.skipped[0].reason.contains("not found"));
    }

    #[test]
    fn ssh_key_category_maps_sections() {
        let item = json!({
            "uuid": "item-7",
            "categoryUuid": "114",
            "overview": { "title": "Server key" },
            "details": {
                "sections": [{
                    "fields": [
                        { "id": "private key", "value": { "concealed": "-----BEGIN OPENSSH PRIVATE KEY-----" } },
                        { "id": "public key", "value": "ssh-ed25519 AAAAC3Nza me@host" },
                        { "id": "key type", "value": "ed25519" },
                        { "id": "passphrase", "value": { "concealed": "pp" } }
                    ]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        assert_eq!(plan.credentials.len(), 1);
        let cred = &plan.credentials[0];
        assert_eq!(cred.credential_type, CredentialType::SshKey);
        match &cred.credential_data {
            CredentialData::SshKey(k) => {
                assert_eq!(k.private_key, "-----BEGIN OPENSSH PRIVATE KEY-----");
                assert_eq!(k.public_key, "ssh-ed25519 AAAAC3Nza me@host");
                assert_eq!(k.key_type, "ed25519");
                assert_eq!(k.passphrase.as_deref(), Some("pp"));
            }
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    #[test]
    fn ssh_key_type_inferred_from_public_key() {
        let item = json!({
            "uuid": "item-8",
            "categoryUuid": "114",
            "overview": { "title": "RSA key" },
            "details": {
                "sections": [{
                    "fields": [
                        { "id": "private key", "value": "RSA PRIVATE KEY DATA" },
                        { "id": "public key", "value": "ssh-rsa AAAAB3Nza root@host" }
                    ]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        match &plan.credentials[0].credential_data {
            CredentialData::SshKey(k) => {
                assert_eq!(k.key_type, "ssh-rsa");
                assert_eq!(k.passphrase, None);
            }
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    #[test]
    fn ssh_key_without_private_key_is_skipped() {
        let item = json!({
            "uuid": "item-9",
            "categoryUuid": "114",
            "overview": { "title": "Only public" },
            "details": {
                "sections": [{
                    "fields": [{ "id": "public key", "value": "ssh-ed25519 AAAA" }]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        assert!(plan.credentials.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert!(plan.skipped[0].reason.contains("private key"));
    }

    #[test]
    fn archived_and_unmapped_categories_are_skipped() {
        let archived = json!({
            "uuid": "a-1", "categoryUuid": "001", "state": "ARCHIVED",
            "overview": { "title": "Old login" }, "details": {}
        });
        let card = json!({
            "uuid": "c-1", "categoryUuid": "002",
            "overview": { "title": "My card" }, "details": {}
        });
        let note = json!({
            "uuid": "n-1", "categoryUuid": "003",
            "overview": { "title": "My note" }, "details": {}
        });
        let plan = plan_from_items(json!([archived, card, note]));

        assert!(plan.credentials.is_empty());
        assert_eq!(plan.skipped.len(), 3);
        assert_eq!(plan.skipped[0].title, "Old login");
        assert!(plan.skipped[0].reason.contains("archived"));
        assert_eq!(plan.skipped[1].title, "My card");
        assert_eq!(plan.skipped[1].category, "Credit Card");
        assert!(plan.skipped[1].reason.contains("not supported"));
        assert_eq!(plan.skipped[2].category, "Secure Note");
        // The vault still becomes an identity even if nothing imports.
        assert_eq!(plan.identities.len(), 1);
    }

    #[test]
    fn missing_title_falls_back_to_uuid() {
        let item = json!({
            "uuid": "anon-1", "categoryUuid": "004",
            "overview": {}, "details": {}
        });
        let plan = plan_from_items(json!([item]));

        assert_eq!(plan.skipped[0].title, "Untitled (anon-1)");
    }

    #[test]
    fn empty_export_yields_empty_plan() {
        let bytes = make_1pux(&attributes_json(3), &json!({ "accounts": [] }).to_string());
        let export = parse_1pux(&bytes).unwrap();
        let plan = plan_import(&export);
        assert!(plan.identities.is_empty());
        assert!(plan.credentials.is_empty());
        assert!(plan.skipped.is_empty());
    }

    #[test]
    fn non_zip_input_is_rejected() {
        assert!(parse_1pux(b"definitely not a zip file").is_err());
    }

    #[test]
    fn invalid_json_is_rejected() {
        let bytes = make_1pux(&attributes_json(3), "not json at all");
        let err = parse_1pux(&bytes).unwrap_err().to_string();
        assert!(err.contains("export.data"), "unexpected error: {err}");
    }

    #[test]
    fn missing_export_data_is_rejected() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "export.attributes",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(attributes_json(3).as_bytes()).unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let err = parse_1pux(&bytes).unwrap_err().to_string();
        assert!(err.contains("export.data"), "unexpected error: {err}");
    }

    #[test]
    fn unexpected_version_parses_with_warning() {
        let bytes = make_1pux(&attributes_json(2), &json!({ "accounts": [] }).to_string());
        assert!(parse_1pux(&bytes).is_ok());
    }

    #[test]
    fn unsupported_category_reports_unknown_category_name() {
        let item = json!({
            "uuid": "item-x",
            "categoryUuid": "999",
            "overview": { "title": "Mystery" },
            "details": { "sections": [] }
        });
        let plan = plan_from_items(json!([item]));

        assert!(plan.credentials.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].title, "Mystery");
        assert_eq!(plan.skipped[0].category, "Unknown category (999)");
        assert!(plan.skipped[0].reason.contains("not supported"));
    }

    #[test]
    fn api_key_number_field_value_is_filtered_to_empty() {
        // A numeric section value deserializes (untagged Number) but renders
        // as an empty string, so no key can be extracted and the item is
        // reported as skipped instead of importing an empty secret.
        let item = json!({
            "uuid": "item-n",
            "categoryUuid": "112",
            "overview": { "title": "Numeric" },
            "details": {
                "sections": [{ "fields": [{ "title": "Credential", "value": 7 }] }]
            }
        });
        let plan = plan_from_items(json!([item]));

        assert!(plan.credentials.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert!(plan.skipped[0].reason.contains("not found"));
    }

    #[test]
    fn api_key_concealed_fallback_skips_credential_id_and_blanks() {
        let item = json!({
            "uuid": "item-c",
            "categoryUuid": "112",
            "overview": { "title": "Concealed" },
            "details": {
                "sections": [{
                    "fields": [
                        { "id": "credential", "value": "   " },
                        { "title": "blank", "value": { "concealed": "   " } },
                        { "title": "real", "value": { "concealed": "  the-secret  " } }
                    ]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        let cred = &plan.credentials[0];
        match &cred.credential_data {
            CredentialData::ApiKey(a) => assert_eq!(a.api_key, "the-secret"),
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    #[test]
    fn login_urls_fall_back_to_overview_url() {
        let missing = json!({
            "uuid": "item-u1",
            "categoryUuid": "001",
            "overview": { "title": "NoUrls", "url": "https://fallback.example" },
            "details": { "loginFields": [] }
        });
        let blank = json!({
            "uuid": "item-u2",
            "categoryUuid": "001",
            "overview": {
                "title": "BlankUrls",
                "url": "https://blank.example",
                "urls": [
                    { "label": "spaces", "href": "   " },
                    { "label": "empty", "href": "" }
                ]
            },
            "details": { "loginFields": [] }
        });
        let plan = plan_from_items(json!([missing, blank]));

        assert_eq!(plan.credentials.len(), 2);
        let by_name = |n: &str| {
            plan.credentials
                .iter()
                .find(|c| c.name == n)
                .unwrap_or_else(|| panic!("credential {n} missing"))
        };
        assert_eq!(
            by_name("NoUrls").url.as_deref(),
            Some("https://fallback.example")
        );
        assert_eq!(
            by_name("BlankUrls").url.as_deref(),
            Some("https://blank.example")
        );
        // Neither item produced secondary URLs.
        assert!(!by_name("NoUrls").metadata.contains_key("alt_urls"));
    }

    #[test]
    fn ssh_key_type_inference_from_public_key_prefix() {
        let mk = |uuid: &str, title: &str, public: &str| {
            json!({
                "uuid": uuid,
                "categoryUuid": "114",
                "overview": { "title": title },
                "details": {
                    "sections": [{
                        "fields": [
                            { "id": "private key", "value": "-----BEGIN OPENSSH PRIVATE KEY-----" },
                            { "id": "public key", "value": public }
                        ]
                    }]
                }
            })
        };
        let plan = plan_from_items(json!([
            mk(
                "item-k1",
                "Prefixed",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI comment"
            ),
            mk("item-k2", "Unprefixed", "not-a-known-key-format")
        ]));

        assert_eq!(plan.credentials.len(), 2);
        let key_type_of = |name: &str| match &plan
            .credentials
            .iter()
            .find(|c| c.name == name)
            .unwrap()
            .credential_data
        {
            CredentialData::SshKey(k) => k.key_type.clone(),
            other => panic!("unexpected credential data: {other:?}"),
        };
        assert_eq!(key_type_of("Prefixed"), "ssh-ed25519");
        assert_eq!(key_type_of("Unprefixed"), "unknown");
    }

    #[test]
    fn section_values_match_by_title_when_id_is_missing() {
        let item = json!({
            "uuid": "item-t",
            "categoryUuid": "112",
            "overview": { "title": "TitleOnly" },
            "details": {
                "sections": [{
                    "fields": [
                        { "value": "no-label-ignored" },
                        { "title": "Credential", "value": "tok-by-title" }
                    ]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        match &plan.credentials[0].credential_data {
            CredentialData::ApiKey(a) => assert_eq!(a.api_key, "tok-by-title"),
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    #[test]
    fn totp_section_field_matched_by_title_with_blank_filtered() {
        let item = json!({
            "uuid": "item-otp",
            "categoryUuid": "001",
            "overview": { "title": "TitleOtp" },
            "details": {
                "loginFields": [
                    { "id": "password", "type": "P", "designation": "password", "value": "pw" }
                ],
                "sections": [{
                    "fields": [
                        { "id": "totp", "value": "   " },
                        { "id": "custom", "title": "One Time Password", "value": "otpauth://totp/TitleOtp?secret=TITLESECRET" }
                    ]
                }]
            }
        });
        let plan = plan_from_items(json!([item]));

        // The blank `totp` field is filtered out; only the title-matched URI
        // yields a credential.
        assert_eq!(plan.skipped.len(), 0);
        assert_eq!(plan.credentials.len(), 2);
        let totp = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::TwoFactor)
            .expect("TOTP credential");
        match &totp.credential_data {
            CredentialData::TwoFactor(t) => assert_eq!(t.secret_key, "TITLESECRET"),
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    #[test]
    fn parse_otpauth_uri_validates_scheme_and_type() {
        // Unparseable input fails at URL parsing.
        let err = format!("{:#}", parse_otpauth_uri("").unwrap_err());
        assert!(err.contains("invalid otpauth URI"), "{err}");
        // A valid URL with the wrong scheme is rejected.
        let err = format!(
            "{:#}",
            parse_otpauth_uri("https://example.com/x?secret=A").unwrap_err()
        );
        assert!(err.contains("otpauth"), "{err}");
        // Counter-based HOTP URIs are not supported.
        let err = format!(
            "{:#}",
            parse_otpauth_uri("otpauth://hotp/x?secret=A").unwrap_err()
        );
        assert!(err.contains("totp"), "{err}");
    }

    #[test]
    fn parse_otpauth_uri_ignores_unknown_params_and_bad_numbers() {
        let params = parse_otpauth_uri(
            "otpauth://totp/Issuer:acct?secret=ABCD&foo=bar&digits=abc&period=45",
        )
        .unwrap();
        assert_eq!(params.secret_key.as_deref(), Some("ABCD"));
        assert_eq!(params.issuer.as_deref(), Some("Issuer"));
        assert_eq!(params.account_name.as_deref(), Some("acct"));
        assert_eq!(
            params.digits, None,
            "non-numeric digits fall back to the default"
        );
        assert_eq!(params.period, Some(45));
    }

    proptest! {
        #[test]
        fn parse_arbitrary_bytes_never_panics(data in prop::collection::vec(any::<u8>(), 0..8192)) {
            // Whether it parses or errors, arbitrary input must not panic.
            let _ = parse_1pux(&data);
        }
    }
}
