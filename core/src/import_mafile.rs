//! Steam Desktop Authenticator (SDA) `.maFile` import parsing.
//!
//! A maFile is the plain-text JSON exported by SDA: the OTP secret
//! (`shared_secret`), the trade-confirmation secret (`identity_secret`),
//! the device ID (`device_id`), the account name, and a pile of
//! **high-risk session credentials** (OAuthToken / SteamLoginSecure /
//! WebCookie in the `Session` object, plus `access_token` from newer
//! exports) all in one file. This module only picks the fields the
//! authenticator needs; session fields are always rejected from storage
//! and explicitly listed in the result, so they cannot silently land in
//! the vault via import. See [`crate::crypto::steam`] for the OTP
//! algorithm and library compatibility.

use crate::crypto::steam::decode_steam_secret;
use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Result of one maFile parse: fields to store + explicit ignore list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaFileImport {
    /// The maFile `account_name` (Steam login name, used as the label)
    pub account_name: String,
    /// OTP secret (standard base64, verified decodable)
    pub shared_secret: String,
    /// Trade-confirmation HMAC secret (standard base64); may be absent in old maFiles
    pub identity_secret: Option<String>,
    /// SDA device ID (e.g. "mobile1234567"); may be absent in old maFiles
    pub device_id: Option<String>,
    /// Ignored session/high-risk field names — never stored, must be shown to the user on import
    pub ignored_session_fields: Vec<String>,
    /// Remaining fields that are neither stored nor session credentials (revocation_code, steamid, etc.)
    pub ignored_other_fields: Vec<String>,
}

/// maFile field names recognized as session credentials (case-insensitive).
///
/// `session` covers SDA's whole Session object (containing OAuthToken,
/// SteamLoginSecure, WebCookie — holding it means taking over the
/// session); the rest are session-token fields seen in SDA /
/// steamguard-cli exports across versions.
const SESSION_FIELD_NAMES: &[&str] = &[
    "session",
    "sessionid",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "oauthtoken",
    "steamlogin",
    "steamloginsecure",
    "webcookie",
];

fn is_session_field(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    SESSION_FIELD_NAMES.iter().any(|name| *name == lowered)
}

/// Parse the bytes of an SDA `.maFile`.
///
/// Rejection paths: malformed JSON, non-object top level, missing
/// `shared_secret`/`account_name` (a missing field is simply not
/// accepted — no guessing defaults), undecodable secret base64.
pub fn parse_ma_file(bytes: &[u8]) -> Result<MaFileImport> {
    let value: Value = serde_json::from_slice(bytes)
        .context("File is not valid JSON — not an SDA .maFile export")?;
    let map = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Not an SDA .maFile export (expected a JSON object)"))?;

    let take_required = |key: &str| -> Result<String> {
        match map.get(key) {
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
            Some(_) => bail!("maFile field `{key}` must be a non-empty string"),
            None => bail!("Missing required maFile field `{key}` — not an SDA export?"),
        }
    };

    let shared_secret = take_required("shared_secret")?;
    // The OTP secret must decode: bad base64 should not blow up only at first code generation
    decode_steam_secret(&shared_secret).context("maFile `shared_secret` is not valid base64")?;
    let account_name = take_required("account_name")?;

    let take_optional_secret = |key: &str| -> Result<Option<String>> {
        match map.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
            Some(Value::String(s)) => {
                let trimmed = s.trim().to_string();
                decode_steam_secret(&trimmed)
                    .with_context(|| format!("maFile `{key}` is not valid base64"))?;
                Ok(Some(trimmed))
            }
            Some(_) => bail!("maFile field `{key}` must be a string when present"),
        }
    };
    let identity_secret = take_optional_secret("identity_secret")?;
    let device_id = match map.get("device_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(Value::String(s)) => Some(s.trim().to_string()),
        Some(_) => bail!("maFile field `device_id` must be a string when present"),
    };

    let imported_keys = [
        "shared_secret",
        "identity_secret",
        "device_id",
        "account_name",
    ];
    let mut ignored_session_fields = Vec::new();
    let mut ignored_other_fields = Vec::new();
    for key in map.keys() {
        if imported_keys.contains(&key.as_str()) {
            continue;
        }
        if is_session_field(key) {
            ignored_session_fields.push(key.clone());
        } else {
            ignored_other_fields.push(key.clone());
        }
    }
    // Sort explicitly: do not rely on JSON deserialization key order, so the import confirmation list renders deterministically
    ignored_session_fields.sort();
    ignored_other_fields.sort();

    Ok(MaFileImport {
        account_name,
        shared_secret,
        identity_secret,
        device_id,
        ignored_session_fields,
        ignored_other_fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape SDA actually exports: authenticator fields + the Session object + miscellaneous fields.
    fn sample_mafile() -> Vec<u8> {
        br#"{
            "account_name": "alice_steam",
            "shared_secret": "MDAxMjM0NTY3ODlhYmNkZWZnaGo=",
            "identity_secret": "cGVyc29uYS12ZWN0b3ItYg==",
            "device_id": "mobile1234567",
            "revocation_code": "R12345",
            "uri": "otpauth://totp/Steam:alice_steam?secret=JBSWY3DPEHPK3PXP",
            "fully_enrolled": true,
            "steamid": "76561198000000000",
            "serial_number": "1234",
            "Session": {
                "SessionID": "deadbeef",
                "SteamLogin": "alice_steam",
                "SteamLoginSecure": "76561198000000000%7C%7Cfake",
                "WebCookie": "cookie-jar",
                "OAuthToken": "eyJhbGciOi...",
                "steamid": "76561198000000000"
            }
        }"#
        .to_vec()
    }

    #[test]
    fn full_mafile_parses_and_lists_ignored_fields() {
        let parsed = parse_ma_file(&sample_mafile()).unwrap();
        assert_eq!(parsed.account_name, "alice_steam");
        assert_eq!(parsed.shared_secret, "MDAxMjM0NTY3ODlhYmNkZWZnaGo=");
        assert_eq!(
            parsed.identity_secret.as_deref(),
            Some("cGVyc29uYS12ZWN0b3ItYg==")
        );
        assert_eq!(parsed.device_id.as_deref(), Some("mobile1234567"));

        assert_eq!(parsed.ignored_session_fields, vec!["Session".to_string()]);
        // The remaining fields are listed in lexicographic order (explicitly sorted by the parser) for display at import confirmation
        assert_eq!(
            parsed.ignored_other_fields,
            vec![
                "fully_enrolled".to_string(),
                "revocation_code".to_string(),
                "serial_number".to_string(),
                "steamid".to_string(),
                "uri".to_string(),
            ]
        );
    }

    /// Session fields never reach storage: no stored field in the parse result may
    /// contain content of the Session object (OAuthToken / SteamLoginSecure /
    /// WebCookie fragments).
    #[test]
    fn session_content_never_reaches_imported_fields() {
        let parsed = parse_ma_file(&sample_mafile()).unwrap();
        let serialized = format!("{parsed:?}");
        for leak in [
            "deadbeef",
            "OAuthToken",
            "SteamLoginSecure",
            "cookie-jar",
            "eyJhbGciOi",
        ] {
            assert!(
                !serialized.contains(leak),
                "session content `{leak}` leaked into the import result"
            );
        }
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        // Missing shared_secret: must not be "guessed" as plain JSON and silently imported
        let missing_secret = br#"{"account_name": "alice"}"#;
        let err = parse_ma_file(missing_secret).unwrap_err();
        assert!(err.to_string().contains("shared_secret"), "got: {err}");

        // Missing account_name: without a label nothing can be stored
        let missing_account = br#"{"shared_secret": "MDAxMjM0NTY3ODlhYmNkZWZnaGo="}"#;
        let err = parse_ma_file(missing_account).unwrap_err();
        assert!(err.to_string().contains("account_name"), "got: {err}");

        // A field that is present but an empty string is also rejected
        let empty_secret = br#"{"shared_secret": "  ", "account_name": "alice"}"#;
        assert!(parse_ma_file(empty_secret).is_err());
    }

    #[test]
    fn bad_json_and_non_mafile_documents_are_rejected() {
        assert!(parse_ma_file(b"not json at all").is_err());
        assert!(parse_ma_file(b"[1, 2, 3]").is_err());
        // Valid JSON but not a maFile (no shared_secret)
        let err = parse_ma_file(br#"{"foo": {"bar": 1}}"#).unwrap_err();
        assert!(err.to_string().contains("shared_secret"), "got: {err}");
        // Wrong field type (shared_secret is a number)
        let wrong_type = br#"{"shared_secret": 42, "account_name": "alice"}"#;
        let err = parse_ma_file(wrong_type).unwrap_err();
        assert!(err.to_string().contains("non-empty string"), "got: {err}");
    }

    #[test]
    fn undecodable_secrets_are_rejected_upfront() {
        let bad_secret = br#"{"shared_secret": "!!!not base64!!!", "account_name": "alice"}"#;
        let err = parse_ma_file(bad_secret).unwrap_err();
        assert!(err.to_string().contains("base64"), "got: {err}");

        // identity_secret present but bad base64: likewise rejected, no silently dropping the field
        let bad_identity = br#"{
            "shared_secret": "MDAxMjM0NTY3ODlhYmNkZWZnaGo=",
            "account_name": "alice",
            "identity_secret": "!!!"
        }"#;
        let err = parse_ma_file(bad_identity).unwrap_err();
        assert!(err.to_string().contains("identity_secret"), "got: {err}");
    }

    #[test]
    fn session_field_names_match_case_insensitively() {
        // Newer export tools use camelCase / lowercase variants (accessToken, sessionid)
        let payload = br#"{
            "account_name": "alice",
            "shared_secret": "MDAxMjM0NTY3ODlhYmNkZWZnaGo=",
            "accessToken": "tok",
            "SESSIONID": "sid",
            "RefreshToken": "r"
        }"#;
        let parsed = parse_ma_file(payload).unwrap();
        assert_eq!(
            parsed.ignored_session_fields,
            vec![
                "RefreshToken".to_string(),
                "SESSIONID".to_string(),
                "accessToken".to_string()
            ]
        );
    }

    #[test]
    fn minimal_mafile_without_optional_fields_parses() {
        let payload = br#"{
            "account_name": "bob",
            "shared_secret": "cGVyc29uYS12ZWN0b3ItYg=="
        }"#;
        let parsed = parse_ma_file(payload).unwrap();
        assert_eq!(parsed.account_name, "bob");
        assert_eq!(parsed.identity_secret, None);
        assert_eq!(parsed.device_id, None);
        assert!(parsed.ignored_session_fields.is_empty());
        assert!(parsed.ignored_other_fields.is_empty());
    }
}
