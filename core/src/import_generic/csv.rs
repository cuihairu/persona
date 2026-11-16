// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use crate::import_1pux::{ImportPlan, PlannedCredential, SkippedItem};
use crate::models::credential::{CredentialData, CredentialType, SecureNoteData, SecurityLevel};

use super::plan::{folder_tags, generic_identity, plan_login_like, row_title_fallback};
use super::strip_utf8_bom;
use super::CsvExport;
use super::GENERIC_VAULT_KEY;

pub(super) fn parse_csv(bytes: &[u8]) -> Result<CsvExport> {
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

pub(super) fn plan_csv(csv: &CsvExport, identity_name: &str, source_label: &str) -> ImportPlan {
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
