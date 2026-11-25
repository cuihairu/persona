use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;

use persona_core::models::Credential;
use persona_core::PersonaService;

use super::fields::{data_fields_of, extract_data_field, primary_secret_field};

// -----------------------------------------------------------------------
// Reference resolution and field extraction
// -----------------------------------------------------------------------

/// The three-segment `IDENTITY/ITEM/FIELD` reference. ITEM matches the credential `name`
/// (unique within the same identity; duplicate names produce an ambiguity error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretRef {
    pub identity: String,
    pub item: String,
    pub field: String,
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.identity, self.item, self.field)
    }
}

impl SecretRef {
    pub(super) fn parse(raw: &str) -> Result<Self> {
        let parts: Vec<&str> = raw.split('/').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.trim().is_empty()) {
            bail!(
                "invalid secret reference {raw:?} (expected IDENTITY/ITEM/FIELD, \
                 e.g. work/deploy/api_key)"
            );
        }
        Ok(Self {
            identity: parts[0].trim().to_string(),
            item: parts[1].trim().to_string(),
            field: parts[2].trim().to_string(),
        })
    }
}

/// The credential `name` metadata field (retrievable without decryption).
const METADATA_FIELDS: [&str; 4] = ["name", "username", "url", "notes"];

/// Resolve a reference into plaintext. The decryption path automatically records a
/// `CredentialDecrypted` audit (existing service-side semantics; not recorded twice).
pub(crate) async fn resolve_ref(
    service: &PersonaService,
    secret_ref: &SecretRef,
) -> Result<String> {
    let identity = service
        .get_identity_by_name(&secret_ref.identity)
        .await
        .map_err(|e| anyhow!("Failed to load identity: {}", e))?
        .with_context(|| format!("Identity '{}' not found", secret_ref.identity))?;

    let credentials = service
        .get_credentials_for_identity(&identity.id)
        .await
        .map_err(|e| anyhow!("Failed to load credentials: {}", e))?;
    let matches: Vec<&Credential> = credentials
        .iter()
        .filter(|c| c.name == secret_ref.item)
        .collect();
    let credential = match matches.len() {
        0 => anyhow::bail!(
            "Credential '{}' not found in identity '{}'",
            secret_ref.item,
            secret_ref.identity
        ),
        1 => matches[0],
        _ => anyhow::bail!(
            "Credential name '{}' is ambiguous in identity '{}' ({} items share it); \
             rename or reference by a unique name",
            secret_ref.item,
            secret_ref.identity,
            matches.len()
        ),
    };

    // Metadata fields are not decrypted
    let metadata_value: Option<String> = match secret_ref.field.as_str() {
        "name" => Some(credential.name.clone()),
        "username" => match credential.username.clone() {
            Some(v) => Some(v),
            None => anyhow::bail!("field \"username\" is not set on this item"),
        },
        "url" => match credential.url.clone() {
            Some(v) => Some(v),
            None => anyhow::bail!("field \"url\" is not set on this item"),
        },
        "notes" => match credential.notes.clone() {
            Some(v) => Some(v),
            None => anyhow::bail!("field \"notes\" is not set on this item"),
        },
        _ => None,
    };
    if let Some(value) = metadata_value {
        return Ok(value);
    }

    let data = service
        .get_credential_data(&credential.id)
        .await
        .map_err(|e| anyhow!("Failed to decrypt credential: {}", e))?
        .with_context(|| format!("Credential '{}' has no payload", secret_ref.item))?;

    // The `secret` alias → the type's primary secret field
    let field = if secret_ref.field == "secret" {
        primary_secret_field(&data).with_context(|| {
            format!(
                "type {:?} has no primary secret field (use one of: {})",
                data,
                data_fields_of(&data).join(", ")
            )
        })?
    } else {
        secret_ref.field.as_str()
    };

    extract_data_field(&data, field)?.with_context(|| {
        format!(
            "unknown field {field:?} for this item type (valid: {} plus metadata \
             {})",
            data_fields_of(&data).join(", "),
            METADATA_FIELDS.join(", ")
        )
    })
}

/// Parse a `NAME=REF` injection item.
pub(super) fn parse_env_assignments(specs: &[String]) -> Result<Vec<(String, SecretRef)>> {
    specs
        .iter()
        .map(|spec| {
            let (name, raw) = spec
                .split_once('=')
                .with_context(|| format!("--env {spec:?} must be NAME=REF"))?;
            if name.trim().is_empty()
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                bail!("--env {spec:?} has an invalid variable name (use [A-Za-z0-9_])");
            }
            if name.starts_with(|c: char| c.is_ascii_digit()) {
                bail!("--env {spec:?} variable name must not start with a digit");
            }
            Ok((name.to_string(), SecretRef::parse(raw)?))
        })
        .collect()
}

/// Manifest key validity (the k8s object key charset). `allow_slash` covers the
/// `prefix/name` form of labels/annotations; data keys/object names do not allow slashes.
pub(super) fn valid_key(key: &str, allow_slash: bool) -> bool {
    !key.is_empty()
        && key.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') || (allow_slash && c == '/')
        })
}

pub(super) fn parse_kv_pairs(specs: &[String], flag: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for spec in specs {
        let (k, v) = spec
            .split_once('=')
            .with_context(|| format!("--{flag} {spec:?} must be KEY=VALUE"))?;
        if !valid_key(k, true) {
            bail!("--{flag} {spec:?} has an invalid key (use [A-Za-z0-9._/-])");
        }
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}
