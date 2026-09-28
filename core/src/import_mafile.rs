//! Steam Desktop Authenticator（SDA）`.maFile` 导入解析。
//!
//! maFile 是 SDA 导出的明文 JSON：出码密钥（`shared_secret`）、交易确认
//! 密钥（`identity_secret`）、设备标识（`device_id`）、账号名与一堆**高危
//! 会话凭据**（`Session` 对象里的 OAuthToken / SteamLoginSecure / WebCookie、
//! 新版导出的 `access_token` 等）混在一个文件里。本模块只挑选验证器所需
//! 字段；会话字段一律拒绝入库并在结果里显式列出，防止随导入静默落库。
//! 出码算法与库兼容性见 [`crate::crypto::steam`]。

use crate::crypto::steam::decode_steam_secret;
use anyhow::{bail, Context, Result};
use serde_json::Value;

/// 一次 maFile 解析的结果：入库字段 + 显式忽略清单。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaFileImport {
    /// maFile 的 `account_name`（Steam 账号登录名，作标签）
    pub account_name: String,
    /// 出码密钥（标准 base64，已验证可解码）
    pub shared_secret: String,
    /// 交易确认 HMAC 密钥（标准 base64）；旧 maFile 可能缺省
    pub identity_secret: Option<String>,
    /// SDA 设备标识（形如 "mobile1234567"）；旧 maFile 可能缺省
    pub device_id: Option<String>,
    /// 已忽略的会话/高危字段名——永不入库，导入时必须向用户展示
    pub ignored_session_fields: Vec<String>,
    /// 既不入库也非会话凭据的其余字段（revocation_code、steamid 等）
    pub ignored_other_fields: Vec<String>,
}

/// 识别为会话凭据的 maFile 字段名（大小写不敏感）。
///
/// `session` 覆盖 SDA 整个 Session 对象（内含 OAuthToken、
/// SteamLoginSecure、WebCookie——拿到即等于接管会话）；其余是各版本
/// SDA / steamguard-cli 导出里出现过的会话令牌字段。
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

/// 解析 SDA `.maFile` 字节。
///
/// 拒绝路径：坏 JSON、顶层非对象、缺 `shared_secret`/`account_name`
/// （"缺字段"即不认账——不猜默认值）、密钥 base64 不可解码。
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
    // 出码密钥必须可解码：坏 base64 不该等到第一次取码时才炸
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
    // 显式排序：不依赖 JSON 反序列化的键序，导入确认清单的展示顺序确定
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

    /// SDA 实际导出的形状：验证器字段 + Session 会话对象 + 杂项字段。
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
        // 其余字段按字典序列出（解析器显式排序），供导入确认时展示
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

    /// 会话字段绝不入库：解析结果里任何入库字段都不得包含 Session 对象
    /// 的内容（OAuthToken / SteamLoginSecure / WebCookie 片段）。
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
        // 缺 shared_secret：不能"猜"成普通 JSON 然后静默导入
        let missing_secret = br#"{"account_name": "alice"}"#;
        let err = parse_ma_file(missing_secret).unwrap_err();
        assert!(err.to_string().contains("shared_secret"), "got: {err}");

        // 缺 account_name：没有标签无法入库
        let missing_account = br#"{"shared_secret": "MDAxMjM0NTY3ODlhYmNkZWZnaGo="}"#;
        let err = parse_ma_file(missing_account).unwrap_err();
        assert!(err.to_string().contains("account_name"), "got: {err}");

        // 字段存在但为空串同样拒绝
        let empty_secret = br#"{"shared_secret": "  ", "account_name": "alice"}"#;
        assert!(parse_ma_file(empty_secret).is_err());
    }

    #[test]
    fn bad_json_and_non_mafile_documents_are_rejected() {
        assert!(parse_ma_file(b"not json at all").is_err());
        assert!(parse_ma_file(b"[1, 2, 3]").is_err());
        // 合法 JSON 但不是 maFile（没有 shared_secret）
        let err = parse_ma_file(br#"{"foo": {"bar": 1}}"#).unwrap_err();
        assert!(err.to_string().contains("shared_secret"), "got: {err}");
        // 字段类型不对（shared_secret 是数字）
        let wrong_type = br#"{"shared_secret": 42, "account_name": "alice"}"#;
        let err = parse_ma_file(wrong_type).unwrap_err();
        assert!(err.to_string().contains("non-empty string"), "got: {err}");
    }

    #[test]
    fn undecodable_secrets_are_rejected_upfront() {
        let bad_secret = br#"{"shared_secret": "!!!not base64!!!", "account_name": "alice"}"#;
        let err = parse_ma_file(bad_secret).unwrap_err();
        assert!(err.to_string().contains("base64"), "got: {err}");

        // identity_secret 存在但坏 base64：同样拒绝，不静默丢字段
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
        // 新版导出工具用 camelCase / 小写变体（accessToken、sessionid）
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
