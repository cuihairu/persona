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
//!
//! # 模块布局
//!
//! 类型（1PUX schema、`OnePasswordExport`、plan 类型、`ItemShell`、
//! `TotpParams`）集中在本枢纽——它们的私有字段要被三个子模块与测试共读；
//! 函数体按域拆到子模块。

use std::collections::HashMap;

use serde::Deserialize;

use crate::models::credential::{CredentialData, CredentialType, SecurityLevel};

mod container;
mod fields;
mod plan;

pub use container::parse_1pux;
pub(crate) use fields::parse_totp_value;
pub use plan::plan_import;

#[cfg(test)]
use fields::parse_otpauth_uri;

#[cfg(test)]
mod tests;
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

#[derive(Debug)]
pub(crate) struct TotpParams {
    secret_key: Option<String>,
    issuer: Option<String>,
    account_name: Option<String>,
    algorithm: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
    /// Some(true) = HOTP（计数器型，RFC 4226）；None/false = TOTP。
    hotp: Option<bool>,
    /// otpauth://hotp/ URI 的 `counter` 参数，入库作缺省起点。
    counter: Option<u64>,
}
