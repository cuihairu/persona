// ---------------------------------------------------------------------------
// Import planning
// ---------------------------------------------------------------------------

use std::collections::HashMap;

use crate::import_1pux::{
    parse_totp_value, ImportPlan, PlannedCredential, PlannedIdentity, SkippedItem,
};
use crate::models::credential::{
    CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
};

use super::GENERIC_VAULT_KEY;

pub(super) fn generic_identity(identity_name: &str, source_label: &str) -> PlannedIdentity {
    PlannedIdentity {
        vault_uuid: GENERIC_VAULT_KEY.to_string(),
        name: identity_name.to_string(),
        description: format!("Imported from {source_label}"),
    }
}

/// folder 列（Bitwarden folder / 通用 group）映射为标签：CSV 导出的分组
/// 是库内轻量分组，不该膨胀成身份。
pub(super) fn folder_tags(folder: &Option<String>) -> Vec<String> {
    folder.iter().cloned().collect()
}

/// 无标题列时的兜底名：URL 主机（站点登录的直觉名）→ 用户名 → 行号。
pub(super) fn row_title_fallback(
    username: &Option<String>,
    url: &Option<String>,
    index: usize,
) -> String {
    if let Some(url) = url {
        if let Some(host) = host_of(url) {
            return host;
        }
        return url.clone();
    }
    if let Some(user) = username {
        return user.clone();
    }
    format!("Row {}", index + 1)
}

fn host_of(url: &str) -> Option<String> {
    let candidate = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };
    url::Url::parse(&candidate)
        .ok()?
        .host_str()
        .map(str::to_string)
}

/// 登录形条目（CSV 普通行 / Bitwarden login）：密码凭据 + TOTP 拆分。
/// 口径与 1PUX 一致：SecurityLevel::High、TOTP 命名 `{title} (TOTP)`、
/// TOTP 解析失败进 skipped（reason 不带密值）。
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_login_like(
    plan: &mut ImportPlan,
    name: String,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    is_favorite: bool,
    extra_metadata: HashMap<String, String>,
) {
    // 与 1PUX 相同：@ 形用户名同时落 email。
    let email = username.as_ref().filter(|u| u.contains('@')).cloned();
    plan.credentials.push(PlannedCredential {
        vault_uuid: GENERIC_VAULT_KEY.to_string(),
        name: name.clone(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::High,
        credential_data: CredentialData::Password(PasswordCredentialData {
            password: password.unwrap_or_default(),
            email,
            security_questions: Vec::new(),
        }),
        url: url.clone(),
        username: username.clone(),
        notes,
        tags,
        metadata: extra_metadata,
        is_favorite,
    });

    if let Some(value) = totp {
        let totp_name = format!("{name} (TOTP)");
        match parse_totp_value(&value, &name, username.as_deref()) {
            Ok(data) => plan.credentials.push(PlannedCredential {
                vault_uuid: GENERIC_VAULT_KEY.to_string(),
                name: totp_name,
                credential_type: CredentialType::TwoFactor,
                security_level: SecurityLevel::High,
                credential_data: CredentialData::TwoFactor(data),
                url,
                username,
                notes: None,
                tags: Vec::new(),
                metadata: HashMap::new(),
                is_favorite: false,
            }),
            Err(err) => plan.skipped.push(SkippedItem {
                vault_name: GENERIC_VAULT_KEY.to_string(),
                title: totp_name,
                category: "TOTP".to_string(),
                reason: format!("TOTP 字段跳过：{err:#}"),
            }),
        }
    }
}
