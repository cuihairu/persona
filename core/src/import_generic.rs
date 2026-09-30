//! 通用格式导入（FEATURE_GAP_ANALYSIS #20）：CSV + Bitwarden JSON 导出解析
//! 与导入规划。
//!
//! 覆盖主流明文导出形：
//! - **CSV**（按表头嗅探列角色）：Bitwarden CSV（含 `type` 列分流）、Chrome、
//!   Firefox、1Password CSV、KeePass 1.x/2.x CSV；
//! - **Bitwarden JSON**（`encrypted: false` 的明文导出；密码保护导出明确
//!   拒绝并指路）。
//!
//! 与 [`crate::import_1pux`] 同一条设计线：解析 → 纯函数规划出
//! [`ImportPlan`]，CLI/桌面先预览再确认后落库。CSV 导出没有容器概念，
//! 整个文件落进一个身份（`identity_name` 由调用方给定，通常是文件名 stem）；
//! Bitwarden 的 folder 映射为 persona 标签而非身份（folder 是库内轻量分组，
//! 不是 1Password vault 那种容器）。KeePass 走其 CSV 导出（KeePass →
//! Export → CSV），不直读 KDBX 加密容器——与 1PUX/maFile 一致的明文容器
//! 策略，避免引入 keepass-rs 重依赖。

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::import_1pux::{
    parse_totp_value, ImportPlan, PlannedCredential, PlannedIdentity, SkippedItem,
};
use crate::models::credential::{
    BankCardData, CredentialData, CredentialType, PasswordCredentialData, SecureNoteData,
    SecurityLevel, SshKeyData,
};

/// 通用导入的唯一容器键：整个文件一个身份，凭据经它回链。
pub const GENERIC_VAULT_KEY: &str = "generic-import";

/// 通用导入支持的格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericExportFormat {
    /// 密码管理器 CSV 导出（表头嗅探，见 [`map_roles`]）
    Csv,
    /// Bitwarden 明文 JSON 导出（`encrypted: false`）
    BitwardenJson,
}

/// 解析产物：CSV 记录集或 Bitwarden JSON 导出。
#[derive(Debug, Clone)]
pub enum GenericExport {
    Csv(CsvExport),
    BitwardenJson(BitwardenExport),
}

/// CSV 导出：表头 + 数据行（列与表头按位对齐，缺列由 `flexible` 容忍）。
#[derive(Debug, Clone)]
pub struct CsvExport {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// Bitwarden 明文 JSON 导出。
#[derive(Debug, Clone)]
pub struct BitwardenExport {
    pub folders: Vec<BitwardenFolder>,
    pub items: Vec<BitwardenItem>,
}

/// 自动嗅探格式：剥掉 UTF-8 BOM 后，`{`/`[` 开头当 JSON，否则当 CSV。
/// 扩展名不可靠（用户常改名），按内容判断。
pub fn detect_format(bytes: &[u8]) -> GenericExportFormat {
    let head = String::from_utf8_lossy(strip_utf8_bom(bytes));
    match head.trim_start().starts_with('{') || head.trim_start().starts_with('[') {
        true => GenericExportFormat::BitwardenJson,
        false => GenericExportFormat::Csv,
    }
}

/// 解析通用导出文件。`format` 传 `None` 时自动嗅探。
pub fn parse_generic(bytes: &[u8], format: Option<GenericExportFormat>) -> Result<GenericExport> {
    match format.unwrap_or_else(|| detect_format(bytes)) {
        GenericExportFormat::Csv => parse_csv(bytes).map(GenericExport::Csv),
        GenericExportFormat::BitwardenJson => {
            parse_bitwarden_json(bytes).map(GenericExport::BitwardenJson)
        }
    }
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_prefix([0xEF, 0xBB, 0xBF].as_slice())
        .unwrap_or(bytes)
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

fn parse_csv(bytes: &[u8]) -> Result<CsvExport> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(strip_utf8_bom(bytes));

    let mut records = reader.records();
    let headers: Vec<String> = loop {
        match records.next() {
            Some(record) => {
                let record = record.context("CSV 解析失败（表头行）")?;
                if record.iter().any(|cell| !cell.trim().is_empty()) {
                    break record.iter().map(|c| c.trim().to_string()).collect();
                }
                // 跳过文件开头的空行
            }
            None => bail!("CSV 文件为空或只有空行"),
        }
    };
    let rows: Vec<Vec<String>> = records
        .map(|record| {
            record
                .map(|r| r.iter().map(|c| c.to_string()).collect::<Vec<_>>())
                .context("CSV 解析失败（数据行）")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let roles = map_roles(&headers);
    if roles.username.is_none() && roles.password.is_none() && roles.totp.is_none() {
        bail!(
            "无法识别的 CSV 列（找不到 username/password/totp 任何一列）：{}",
            headers.join(", ")
        );
    }

    Ok(CsvExport { headers, rows })
}

/// 归一表头：小写 + 只留 ASCII 字母数字，`login_name` / `Login Name` /
/// `loginUsername` 归一后等形。
fn normalize_header(header: &str) -> String {
    header
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// 每个文件里各列扮演的字段角色（None = 该角色没有对应列）。
#[derive(Debug, Clone, Copy, Default)]
struct CsvRoles {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    folder: Option<usize>,
    favorite: Option<usize>,
    item_type: Option<usize>,
}

/// 表头 → 列角色。别名表覆盖：
/// - Bitwarden CSV：`name` / `login_uri` / `login_username` / `login_password` / `totp` / `folder` / `favorite` / `type`
/// - Chrome：`name` / `url` / `username` / `password`
/// - Firefox：`url` / `username` / `password`（无标题列）
/// - 1Password CSV：`Title` / `Url` / `Username` / `Password` / `Notes`
/// - KeePass 1.x：`Account` / `Login Name` / `Password` / `Web Site` / `Comments`
/// - KeePass 2.x：`Title` / `Username` / `Password` / `URL` / `Notes`
fn map_roles(headers: &[String]) -> CsvRoles {
    let mut roles = CsvRoles::default();
    for (index, header) in headers.iter().enumerate() {
        // 只在角色空缺时认领：先到先得，重复列（如双 url）取第一列。
        let slot = |current: Option<usize>| current.or(Some(index));
        match normalize_header(header).as_str() {
            "title" | "name" | "account" => roles.title = slot(roles.title),
            "url" | "uri" | "website" | "webpage" | "loginuri" | "loginurl" => {
                roles.url = slot(roles.url)
            }
            "username" | "user" | "login" | "loginname" | "loginusername" | "email" => {
                roles.username = slot(roles.username)
            }
            "password" | "pass" | "pwd" | "loginpassword" => roles.password = slot(roles.password),
            "notes" | "note" | "comments" | "comment" => roles.notes = slot(roles.notes),
            "totp" | "otp" | "otpauth" | "onetimepassword" => roles.totp = slot(roles.totp),
            "folder" | "group" | "collection" => roles.folder = slot(roles.folder),
            "favorite" | "fav" => roles.favorite = slot(roles.favorite),
            "type" => roles.item_type = slot(roles.item_type),
            _ => {} // 未知列静默忽略（各导出器都带各自的附加列）
        }
    }
    roles
}

/// 取一行中某角色列的值（去首尾空白，空串视同缺列）。
fn cell(row: &[String], slot: Option<usize>) -> Option<String> {
    slot.and_then(|i| row.get(i))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn favorite_truthy(value: Option<&str>) -> bool {
    value.is_some_and(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "y"))
}

// ---------------------------------------------------------------------------
// Bitwarden JSON schema（明文导出；宽容：缺字段按 None 处理）
// ---------------------------------------------------------------------------

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

/// Bitwarden 的 exp_month/exp_year/code 在明文 JSON 里通常是字符串，
/// 但有些导出器会写成数字——两者都容忍。
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

fn parse_bitwarden_json(bytes: &[u8]) -> Result<BitwardenExport> {
    let value: serde_json::Value =
        serde_json::from_slice(strip_utf8_bom(bytes)).context("Bitwarden JSON 解析失败")?;

    // 密码保护导出在 items 之前就要拦下：其字段全是密文，解析无意义。
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

// ---------------------------------------------------------------------------
// Import planning
// ---------------------------------------------------------------------------

/// 把通用导出映射成 [`ImportPlan`]：整个文件落进一个身份（`identity_name`，
/// 描述里记录 `source_label` 便于溯源）。纯函数、无 IO。
pub fn plan_generic_import(
    export: &GenericExport,
    identity_name: &str,
    source_label: &str,
) -> ImportPlan {
    match export {
        GenericExport::Csv(csv) => plan_csv(csv, identity_name, source_label),
        GenericExport::BitwardenJson(bw) => plan_bitwarden(bw, identity_name, source_label),
    }
}

fn generic_identity(identity_name: &str, source_label: &str) -> PlannedIdentity {
    PlannedIdentity {
        vault_uuid: GENERIC_VAULT_KEY.to_string(),
        name: identity_name.to_string(),
        description: format!("Imported from {source_label}"),
    }
}

fn plan_csv(csv: &CsvExport, identity_name: &str, source_label: &str) -> ImportPlan {
    let roles = map_roles(&csv.headers);
    let mut plan = ImportPlan {
        identities: vec![generic_identity(identity_name, source_label)],
        ..ImportPlan::default()
    };

    for (index, row) in csv.rows.iter().enumerate() {
        let title = cell(row, roles.title);
        let username = cell(row, roles.username);
        let password = cell(row, roles.password);
        let totp = cell(row, roles.totp);
        let url = cell(row, roles.url);
        let notes = cell(row, roles.notes);
        let folder = cell(row, roles.folder);
        let favorite = favorite_truthy(cell(row, roles.favorite).as_deref());
        let item_type = cell(row, roles.item_type).map(|t| t.to_lowercase());

        // 完全空行（含全空白单元格）：跳过且不进报告，避免噪声。
        if title.is_none()
            && username.is_none()
            && password.is_none()
            && totp.is_none()
            && url.is_none()
        {
            continue;
        }
        let name = title.unwrap_or_else(|| row_title_fallback(&username, &url, index));

        // Bitwarden CSV 的 type 列分流：note 落 SecureNote；card/identity
        // 的字段不在 CSV 列里，硬塞必然丢数据——报告跳过并指路 JSON 导出。
        match item_type.as_deref() {
            Some("note") => {
                plan.credentials.push(PlannedCredential {
                    vault_uuid: GENERIC_VAULT_KEY.to_string(),
                    name: name.clone(),
                    credential_type: CredentialType::SecureNote,
                    security_level: SecurityLevel::High,
                    credential_data: CredentialData::SecureNote(SecureNoteData {
                        note: notes.unwrap_or_default(),
                    }),
                    url: None,
                    username: None,
                    notes: None,
                    tags: folder_tags(&folder),
                    metadata: HashMap::new(),
                    is_favorite: favorite,
                });
            }
            Some(other @ ("card" | "identity")) => {
                plan.skipped.push(SkippedItem {
                    vault_name: identity_name.to_string(),
                    title: name,
                    category: format!("Bitwarden CSV ({other})"),
                    reason: "CSV 导出不含该类型的字段；改用 Bitwarden JSON 导出可完整迁移"
                        .to_string(),
                });
            }
            _ => plan_login_like(
                &mut plan,
                name,
                username,
                password,
                totp,
                url,
                notes,
                folder_tags(&folder),
                favorite,
                HashMap::new(),
            ),
        }
    }

    plan
}

/// folder 列（Bitwarden folder / 通用 group）映射为标签：CSV 导出的分组
/// 是库内轻量分组，不该膨胀成身份。
fn folder_tags(folder: &Option<String>) -> Vec<String> {
    folder.iter().cloned().collect()
}

/// 无标题列时的兜底名：URL 主机（站点登录的直觉名）→ 用户名 → 行号。
fn row_title_fallback(username: &Option<String>, url: &Option<String>, index: usize) -> String {
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
fn plan_login_like(
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

fn plan_bitwarden(export: &BitwardenExport, identity_name: &str, source_label: &str) -> ImportPlan {
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
                        // Bitwarden 导出没有银行名；品牌落 card_type。
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
                // 公钥首 token 即算法名（"ssh-ed25519 AAAA..."）
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::credential::CredentialType;

    fn plan_csv_str(csv: &str, name: &str) -> ImportPlan {
        let export = parse_generic(csv.as_bytes(), Some(GenericExportFormat::Csv)).unwrap();
        plan_generic_import(&export, name, "test.csv")
    }

    fn plan_bw_json(value: serde_json::Value, name: &str) -> ImportPlan {
        let bytes = value.to_string().into_bytes();
        let export = parse_generic(&bytes, Some(GenericExportFormat::BitwardenJson)).unwrap();
        plan_generic_import(&export, name, "test.json")
    }

    fn password_of<'a>(plan: &'a ImportPlan, name: &'a str) -> &'a PlannedCredential {
        plan.credentials
            .iter()
            .find(|c| c.name == name && c.credential_type == CredentialType::Password)
            .unwrap_or_else(|| panic!("no password credential named {name}"))
    }

    // -- 格式嗅探 ------------------------------------------------------------

    #[test]
    fn detect_format_distinguishes_json_from_csv() {
        assert_eq!(
            detect_format(b"{\"items\":[]}"),
            GenericExportFormat::BitwardenJson
        );
        assert_eq!(
            detect_format(b"\xEF\xBB\xBF[{\"id\":1}]"),
            GenericExportFormat::BitwardenJson
        );
        assert_eq!(detect_format(b"name,url\nx,y"), GenericExportFormat::Csv);
        assert_eq!(
            detect_format(b"\xEF\xBB\xBFname,url\r\nx,y"),
            GenericExportFormat::Csv
        );
    }

    // -- CSV 列形 ------------------------------------------------------------

    #[test]
    fn bitwarden_csv_full_shape_with_totp_folder_and_type_splits() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,\
                   login_password,totp\n\
                   Work,1,login,GitHub,some note,,0,https://github.com,alice,hunter2,\
                   otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n\
                   ,0,note,Recovery codes,codes...,,,\n\
                   ,0,card,Bank card,,,0,,,\n";
        let plan = plan_csv_str(csv, "bitwarden");

        assert_eq!(plan.identities.len(), 1);
        assert_eq!(plan.identities[0].name, "bitwarden");
        assert_eq!(plan.identities[0].vault_uuid, GENERIC_VAULT_KEY);

        let login = password_of(&plan, "GitHub");
        assert_eq!(login.url.as_deref(), Some("https://github.com"));
        assert_eq!(login.username.as_deref(), Some("alice"));
        assert!(login.is_favorite, "favorite=1 → is_favorite");
        assert_eq!(login.tags, vec!["Work"]);
        match &login.credential_data {
            CredentialData::Password(p) => assert_eq!(p.password, "hunter2"),
            other => panic!("unexpected: {other:?}"),
        }

        let totp = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::TwoFactor)
            .expect("totp split out");
        assert_eq!(totp.name, "GitHub (TOTP)");
        match &totp.credential_data {
            CredentialData::TwoFactor(t) => {
                assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
                assert_eq!(t.issuer, "GitHub");
                assert_eq!(t.account_name, "alice");
            }
            other => panic!("unexpected: {other:?}"),
        }

        let note = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::SecureNote)
            .expect("note row → SecureNote");
        assert_eq!(note.name, "Recovery codes");
        match &note.credential_data {
            CredentialData::SecureNote(n) => assert_eq!(n.note, "codes..."),
            other => panic!("unexpected: {other:?}"),
        }

        assert_eq!(plan.skipped.len(), 1, "card row skipped");
        assert!(plan.skipped[0].reason.contains("JSON"));
    }

    #[test]
    fn chrome_csv_minimal_shape() {
        let plan = plan_csv_str(
            "name,url,username,password\nExample,https://example.com,bob,pw1\n",
            "chrome",
        );
        let login = password_of(&plan, "Example");
        assert_eq!(login.url.as_deref(), Some("https://example.com"));
        assert_eq!(login.username.as_deref(), Some("bob"));
        match &login.credential_data {
            CredentialData::Password(p) => assert_eq!(p.password, "pw1"),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(login.metadata.is_empty());
    }

    #[test]
    fn firefox_csv_without_title_falls_back_to_host() {
        let plan = plan_csv_str(
            "url,username,password,httpRealm,formActionOrigin,guid,timeCreated\n\
             https://example.org/login,carol,pw2,,,abc,1\n",
            "firefox",
        );
        let login = password_of(&plan, "example.org");
        assert_eq!(login.username.as_deref(), Some("carol"));
        assert_eq!(login.url.as_deref(), Some("https://example.org/login"));
    }

    #[test]
    fn keepass_one_csv_aliases() {
        let plan = plan_csv_str(
            "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\
             \"Server\",\"root\",\"s3cret\",\"https://srv.example.com\",\"prod box\"\n",
            "keepass1",
        );
        let login = password_of(&plan, "Server");
        assert_eq!(login.username.as_deref(), Some("root"));
        assert_eq!(login.url.as_deref(), Some("https://srv.example.com"));
        assert_eq!(login.notes.as_deref(), Some("prod box"));
    }

    #[test]
    fn keepass_two_csv_aliases() {
        let plan = plan_csv_str(
            "Title,Username,Password,URL,Notes\nSite,admin,pw3,https://site.example.com,note\n",
            "keepass2",
        );
        let login = password_of(&plan, "Site");
        assert_eq!(login.username.as_deref(), Some("admin"));
        assert_eq!(login.url.as_deref(), Some("https://site.example.com"));
    }

    #[test]
    fn quoted_multiline_notes_and_empty_rows() {
        let plan = plan_csv_str(
            "name,url,username,password,notes\n\
             \"Multi\",\"https://a.com\",u,p,\"line1\nline2\"\n\
             ,,,,\n\
             \"Bare\",,,,,\n",
            "multi",
        );
        let multi = password_of(&plan, "Multi");
        match &multi.credential_data {
            CredentialData::Password(p) if p.password == "p" => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(multi.notes.as_deref(), Some("line1\nline2"));
        // "Bare" 行只有标题，也导入（密码为空）；空行忽略不进报告。
        assert!(password_of(&plan, "Bare").username.is_none());
        assert_eq!(plan.credentials.len(), 2);
        assert!(plan.skipped.is_empty());
    }

    #[test]
    fn unrecognized_headers_report_columns() {
        let err = parse_generic(b"foo,bar\n1,2\n", Some(GenericExportFormat::Csv))
            .expect_err("unknown columns must fail");
        assert!(err.to_string().contains("foo, bar"));
    }

    #[test]
    fn broken_otpauth_totp_goes_to_skipped_without_the_secret() {
        // 与 1PUX 相同的宽容口径：非 otpauth 的裸值按 base32 密钥原样保留；
        // otpauth 形但 host 不是 totp 才解析失败 → skipped，且原因不带密值。
        let plan = plan_csv_str(
            "name,username,password,totp\nX,u,p,otpauth://hotp/x?secret=TOPSECRET\n",
            "badtotp",
        );
        assert_eq!(
            password_of(&plan, "X").username.as_deref(),
            Some("u"),
            "登录本体照常导入"
        );
        assert_eq!(plan.skipped.len(), 1);
        assert!(
            !plan.skipped[0].reason.contains("TOPSECRET"),
            "跳过原因不得携带密值: {}",
            plan.skipped[0].reason
        );
    }

    #[test]
    fn bare_totp_value_is_imported_verbatim_like_1pux() {
        let plan = plan_csv_str(
            "name,username,password,totp\nX,u,p,NOTBASE32!!!\n",
            "lenient",
        );
        let totp = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::TwoFactor)
            .expect("裸值宽容导入");
        match &totp.credential_data {
            CredentialData::TwoFactor(t) => assert_eq!(t.secret_key, "NOTBASE32!!!"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -- Bitwarden JSON -------------------------------------------------------

    #[test]
    fn bitwarden_json_login_with_uris_folder_and_favorite() {
        let plan = plan_bw_json(
            serde_json::json!({
                "encrypted": false,
                "folders": [{"id": "f1", "name": "Infra"}],
                "items": [{
                    "id": "i1", "type": 1, "name": "GitHub", "notes": "n",
                    "favorite": true, "folderId": "f1",
                    "login": {
                        "username": "alice", "password": "hunter2",
                        "totp": "JBSWY3DPEHPK3PXP",
                        "uris": [{"uri": "https://github.com"}, {"uri": "https://gist.github.com"}]
                    }
                }]
            }),
            "bw",
        );

        let login = password_of(&plan, "GitHub");
        assert_eq!(login.url.as_deref(), Some("https://github.com"));
        assert_eq!(
            login.metadata.get("alt_urls").map(String::as_str),
            Some("https://gist.github.com")
        );
        assert_eq!(login.tags, vec!["Infra"]);
        assert!(login.is_favorite);

        let totp = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::TwoFactor)
            .expect("bare secret totp split");
        match &totp.credential_data {
            CredentialData::TwoFactor(t) => {
                assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
                assert_eq!(t.issuer, "GitHub", "issuer 兜底用条目名");
                assert_eq!(t.account_name, "alice");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn bitwarden_json_note_card_ssh_and_identity() {
        let plan = plan_bw_json(
            serde_json::json!({
                "items": [
                    {"id": "i2", "type": 2, "name": "Note", "notes": "body"},
                    {"id": "i3", "type": 3, "name": "Card",
                     "card": {"cardholderName": "A B", "brand": "visa", "number": "4111",
                              "expMonth": "12", "expYear": "2030", "code": "123"}},
                    {"id": "i4", "type": 4, "name": "Identity"},
                    {"id": "i5", "type": 5, "name": "Key",
                     "sshKey": {"privateKey": "-----BEGIN", "publicKey": "ssh-ed25519 AAAA"}},
                    {"id": "i6", "type": 99, "name": "Mystery"}
                ]
            }),
            "bw",
        );

        let note = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::SecureNote)
            .unwrap();
        match &note.credential_data {
            CredentialData::SecureNote(n) => assert_eq!(n.note, "body"),
            other => panic!("unexpected: {other:?}"),
        }

        let card = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::BankCard)
            .unwrap();
        match &card.credential_data {
            CredentialData::BankCard(c) => {
                assert_eq!(c.card_number, "4111");
                assert_eq!(c.cardholder_name, "A B");
                assert_eq!(c.expiry_date, "12/2030");
                assert_eq!(c.cvv, "123");
                assert_eq!(c.card_type, "visa");
            }
            other => panic!("unexpected: {other:?}"),
        }

        let ssh = plan
            .credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::SshKey)
            .unwrap();
        match &ssh.credential_data {
            CredentialData::SshKey(k) => {
                assert_eq!(k.key_type, "ssh-ed25519");
                assert!(k.private_key.starts_with("-----BEGIN"));
            }
            other => panic!("unexpected: {other:?}"),
        }

        let skipped_categories: Vec<&str> =
            plan.skipped.iter().map(|s| s.category.as_str()).collect();
        assert!(skipped_categories.contains(&"Bitwarden Identity"));
        assert!(skipped_categories.contains(&"Bitwarden type 99"));
    }

    #[test]
    fn bitwarden_encrypted_export_is_rejected_with_guidance() {
        let bytes = serde_json::json!({
            "encrypted": true,
            "items": [{"type": 1, "name": "x"}]
        })
        .to_string()
        .into_bytes();
        let err = parse_generic(&bytes, Some(GenericExportFormat::BitwardenJson))
            .expect_err("encrypted export must be refused");
        assert!(err.to_string().contains("encrypted: true"));
    }

    #[test]
    fn bitwarden_bare_item_array_is_accepted() {
        let bytes = serde_json::json!([
            {"id": "i1", "type": 1, "name": "Solo", "login": {"username": "u", "password": "p"}}
        ])
        .to_string()
        .into_bytes();
        let export = parse_generic(&bytes, None).unwrap();
        assert!(matches!(export, GenericExport::BitwardenJson(_)));
        let plan = plan_generic_import(&export, "bw", "test.json");
        assert_eq!(password_of(&plan, "Solo").username.as_deref(), Some("u"));
    }

    #[test]
    fn bitwarden_item_without_name_gets_untitled_fallback() {
        let plan = plan_bw_json(
            serde_json::json!({"items": [{"id": "abc", "type": 2}]}),
            "bw",
        );
        assert_eq!(plan.credentials[0].name, "Untitled (abc)");
    }
}
