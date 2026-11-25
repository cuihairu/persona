//! Import planning: mapping a parsed 1Password export onto a plan of persona
//! identities/credentials
//! (a pure function with no IO; unsupported categories are honestly reported as
//! skipped, never lossily converted).

use std::collections::HashMap;

use crate::models::credential::{
    ApiKeyData, CredentialData, CredentialType, PasswordCredentialData, SecurityLevel, SshKeyData,
};

use super::fields::{
    collect_totp_values, find_concealed_value, find_section_value, infer_key_type, parse_totp_value,
};
use super::{
    ImportPlan, Item, ItemShell, OnePasswordExport, PlannedCredential, PlannedIdentity, SkippedItem,
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
// Import planning
// ---------------------------------------------------------------------------

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
