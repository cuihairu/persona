//! Travel Mode（旅行模式）：把被标记身份的数据整包移出本设备，退出时
//! 原样恢复（1Password「remove vaults from devices」语义）。
//!
//! # 数据流
//!
//! enter：读被标记身份的全部行（12 张表）+ 附件 blob 文件字节（磁盘密封
//! 态，不解密）→ `TravelPack` 序列化 → gzip → PERSENC1 加密（独立 travel
//! 口令，与主密码无关）→ 写 sidecar `<db dir>/travel.persenc` → 单事务
//! 从主库删除（先剥离 audit_logs 的 FK 引用）。主库零痕迹（连名字都没有）；
//! 主密码打不开 sidecar。
//!
//! exit：读 sidecar → 解密解包（校验 format）→ 单事务 `INSERT OR REPLACE`
//! 恢复（父表在前）+ settings 复位 → 重写 blob 文件 → 删 sidecar。
//! 行 id、加密形态（`wrapped_item_key`/`encrypted_data` 字节）不变——
//! per-item key 由主密钥包裹，主密码未变则恢复后可解；也因此旅行模式
//! 期间拒绝改主密码（见 `PersonaService::change_master_password` 拦截）。
//!
//! # 崩溃窗口语义
//!
//! | 崩溃点 | 状态 | 恢复方式 |
//! |---|---|---|
//! | sidecar 已写、事务未提交 | sidecar 存在、`travel_mode=false`、行未删 | enter 拒绝（sidecar 已存在），提示删残留 sidecar 或直接 exit 恢复 |
//! | 事务已提交、blob 文件未删 | 行已删、文件残留 | exit 时按 storage_path 原路径覆写文件，自愈 |
//! | 用户手删 sidecar | `travel_mode=true` 且 sidecar 缺失 | `travel_status().inconsistent = true`——数据仅存于 sidecar，已丢失（诚实呈现，不假装可恢复） |
//!
//! # 已知限制
//!
//! - travel 口令忘了 = sidecar 不可解 = 数据只能靠 enter 之前的整库备份
//!   （备份是时间点快照，含当时仍在库内的被标记身份）。
//! - 本机攻击者可删除/替换 sidecar（拒绝服务）；替换者没有 travel 口令
//!   就构造不出能通过 GCM 认证的密文，注入不可行。
//! - audit_logs 不随行（只记 id 无明文，留作存证）；change_history 快照
//!   含明文元数据，随行。

use crate::backup::file_crypto::{decrypt_bytes, encrypt_bytes, is_persona_encrypted, KdfParams};
use crate::backup::snapshot::{gzip_bytes, maybe_gunzip};
use crate::{PersonaError, PersonaResult};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::{Column, Row, SqlitePool};
use std::path::{Component, Path, PathBuf};

/// sidecar 文件名（放在库文件同目录）。
pub const SIDECAR_FILENAME: &str = "travel.persenc";

/// 格式名（open_pack 校验）。
pub const FORMAT_NAME: &str = "persona-travel-1";

/// 格式版本。
pub const FORMAT_VERSION: u32 = 1;

/// enter 时打包的表（恢复时按此顺序插回，父表在前——FK 依赖序）。
const PACKED_TABLES_IN_INSERT_ORDER: &[&str] = &[
    "identities",
    "credentials",
    "attachments",
    "attachment_chunks",
    "passkeys",
    "crypto_wallets",
    "wallet_addresses",
    "wallet_metadata",
    "transaction_requests",
    "signed_transactions",
    "workspace_members",
    "change_history",
];

/// `<db dir>/travel.persenc`。
pub fn sidecar_path(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(SIDECAR_FILENAME)
}

/// 附件 blob 文件（磁盘原始字节，保持密封态——恢复时行原样插回，
/// 文件也必须原样归位，任何解密/再加密都会破坏与行的对应关系）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TravelBlobFile {
    pub storage_path: String,
    /// 内容 hex sha256（来自 attachments/attachment_chunks 行的
    /// content_hash 列，读入时复核）。
    pub sha256: String,
    pub data_b64: String,
}

/// 打包数据（gzip 前的明文 JSON）。
#[derive(Debug, Serialize, Deserialize)]
pub struct TravelPack {
    pub format_name: String,
    pub format_version: u32,
    pub created_at: String,
    pub app_version: String,
    /// enter 前 workspace 指向被移除身份时的原指针（exit 时还原；否则为 None）。
    pub active_identity_id: Option<String>,
    /// 冗余索引：被移除身份 id 集。
    pub identity_ids: Vec<String>,
    /// 表名 → 原始行（BLOB 单元格为 `{"b64": "..."}`）。
    pub tables: std::collections::BTreeMap<String, Vec<Map<String, Value>>>,
    pub attachment_files: Vec<TravelBlobFile>,
}

/// enter/exit 的数量报告（审计 metadata 与 UI 反馈）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TravelCounts {
    pub identities: u32,
    pub credentials: u32,
    pub attachments: u32,
    pub passkeys: u32,
    pub wallets: u32,
    pub history_rows: u32,
    pub files: u32,
}

impl TravelCounts {
    pub(crate) fn from_pack(pack: &TravelPack) -> Self {
        let table = |name: &str| pack.tables.get(name).map(Vec::len).unwrap_or(0);
        Self {
            identities: table("identities") as u32,
            credentials: table("credentials") as u32,
            attachments: table("attachments") as u32,
            passkeys: table("passkeys") as u32,
            wallets: table("crypto_wallets") as u32,
            history_rows: table("change_history") as u32,
            files: pack.attachment_files.len() as u32,
        }
    }
}

/// 旅行模式状态（读取不需要 travel 口令；给 UI/CLI 展示用）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TravelStatus {
    /// settings 里的 travel_mode 旗标。
    pub active: bool,
    /// 进入时刻（RFC3339；enter 写入、exit 清空）。
    pub entered_at: Option<String>,
    /// sidecar 文件是否存在于 `<db dir>/travel.persenc`。
    pub sidecar_exists: bool,
    /// `active && !sidecar_exists`：旗标说在旅行模式，但数据容器没了
    /// （被手删或损毁）——数据已丢失，诚实呈现而非假装可恢复。
    pub inconsistent: bool,
}

// ---------------------------------------------------------------------------
// 通用行编解码：SQLite 行 ↔ JSON（值级探测，SQLite 动态类型保真）
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// 一行 → JSON map。按**值**逐级探测实际存储类型（SQLite 同一列可存
/// 不同类型值，列声明类型不可信）：NULL/TEXT → i64 → f64 → BLOB。
/// INTEGER 与 BOOLEAN 声明列的值统一落 i64（存储等价，bind 回 int）。
fn row_to_json(row: &sqlx::sqlite::SqliteRow) -> PersonaResult<Map<String, Value>> {
    let mut map = Map::new();
    for col in row.columns() {
        let name = col.name();
        let value = if let Ok(v) = row.try_get::<Option<String>, _>(name) {
            match v {
                Some(s) => Value::String(s),
                None => Value::Null,
            }
        } else if let Ok(v) = row.try_get::<i64, _>(name) {
            Value::Number(v.into())
        } else if let Ok(v) = row.try_get::<f64, _>(name) {
            Value::Number(
                serde_json::Number::from_f64(v)
                    .ok_or_else(|| PersonaError::Database(format!("non-finite float in {name}")))?,
            )
        } else if let Ok(v) = row.try_get::<Vec<u8>, _>(name) {
            json!({ "b64": BASE64.encode(v) })
        } else {
            return Err(PersonaError::Database(format!(
                "column {name}: unsupported value type"
            )));
        };
        map.insert(name.to_string(), value);
    }
    Ok(map)
}

/// JSON 值 → 可 bind 的单元格。
enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

fn value_to_cell(key: &str, value: &Value) -> PersonaResult<Cell> {
    Ok(match value {
        Value::Null => Cell::Null,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Cell::Int(i)
            } else if let Some(f) = n.as_f64() {
                Cell::Real(f)
            } else {
                return Err(PersonaError::Validation(format!(
                    "column {key}: number out of range"
                )));
            }
        }
        Value::String(s) => Cell::Text(s.clone()),
        Value::Object(o) => {
            let Some(b64) = o.get("b64").and_then(Value::as_str) else {
                return Err(PersonaError::Validation(format!(
                    "column {key}: unexpected object cell"
                )));
            };
            Cell::Blob(
                BASE64.decode(b64).map_err(|e| {
                    PersonaError::Validation(format!("column {key}: bad base64: {e}"))
                })?,
            )
        }
        Value::Bool(b) => Cell::Int(*b as i64),
        other => {
            return Err(PersonaError::Validation(format!(
                "column {key}: unsupported JSON value {other}"
            )))
        }
    })
}

/// 列名白名单校验（列名来自我们自己的 SELECT *，此处防御脏 pack）。
fn check_column_name(key: &str) -> PersonaResult<()> {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(PersonaError::Validation(format!(
            "illegal column name in pack: {key}"
        )));
    }
    Ok(())
}

/// 表名白名单校验。
fn check_table_name(name: &str) -> PersonaResult<()> {
    if PACKED_TABLES_IN_INSERT_ORDER.contains(&name) {
        Ok(())
    } else {
        Err(PersonaError::Validation(format!(
            "illegal table name in pack: {name}"
        )))
    }
}

async fn insert_rows(
    executor: &mut sqlx::SqliteConnection,
    table: &str,
    rows: &[Map<String, Value>],
) -> PersonaResult<()> {
    for row in rows {
        if row.is_empty() {
            return Err(PersonaError::Validation(format!(
                "table {table}: empty row"
            )));
        }
        let mut columns = String::new();
        let mut placeholders = String::new();
        for key in row.keys() {
            check_column_name(key)?;
            if !columns.is_empty() {
                columns.push_str(", ");
                placeholders.push_str(", ");
            }
            // 白名单已限 [A-Za-z0-9_]，双引号仅用于越过 SQL 关键字
            //（如 wallet_addresses 的 "index" 列）。
            columns.push('"');
            columns.push_str(key);
            columns.push('"');
            placeholders.push('?');
        }
        let sql = format!("INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})");
        let mut query = sqlx::query(&sql);
        for (key, value) in row {
            query = match value_to_cell(key, value)? {
                Cell::Null => query.bind(None::<String>),
                Cell::Int(i) => query.bind(i),
                Cell::Real(f) => query.bind(f),
                Cell::Text(s) => query.bind(s),
                Cell::Blob(b) => query.bind(b),
            };
        }
        query
            .execute(&mut *executor)
            .await
            .map_err(|e| PersonaError::Database(format!("restoring {table}: {e}")))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 打包 / 封装
// ---------------------------------------------------------------------------

/// 逗号分隔的 `?` 占位符串（IN 子句用）。
fn placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
}

/// 读一行集：`SELECT * FROM {table} WHERE {key} IN (...)`。
async fn select_rows_by_ids(
    pool: &SqlitePool,
    table: &str,
    key_column: &str,
    ids: &[String],
) -> PersonaResult<Vec<Map<String, Value>>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT * FROM {table} WHERE {key_column} IN ({})",
        placeholders(ids.len())
    );
    let mut query = sqlx::query(&sql);
    for id in ids {
        query = query.bind(id);
    }
    let rows = query
        .fetch_all(pool)
        .await
        .map_err(|e| PersonaError::Database(format!("packing {table}: {e}")))?;
    rows.iter().map(row_to_json).collect()
}

/// 读被标记身份的全部数据行 + 附件文件字节。
///
/// `attachments_root`：附件根目录（`AttachmentManager::storage_root()`）；
/// 被标记身份有附件行但为 None 时报错（调用方 service 保证传入）。
pub(crate) async fn build_pack(
    pool: &SqlitePool,
    attachments_root: Option<&Path>,
    marked: &[String],
) -> PersonaResult<TravelPack> {
    if marked.is_empty() {
        return Err(PersonaError::Validation(
            "no marked identities for travel pack".to_string(),
        ));
    }
    let in_identities = placeholders(marked.len());

    // 展开凭据/附件/钱包 id（attachment_chunks、钱包子表按父 id 收集）
    let credential_ids: Vec<String> = {
        let sql = format!("SELECT id FROM credentials WHERE identity_id IN ({in_identities})");
        let mut query = sqlx::query(&sql);
        for id in marked {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(pool)
            .await
            .map_err(|e| PersonaError::Database(format!("collecting credentials: {e}")))?;
        rows.iter()
            .map(|r| r.try_get::<String, _>(0))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| PersonaError::Database(e.to_string()))?
    };
    let attachment_ids: Vec<String> = {
        let sql = format!(
            "SELECT id FROM attachments WHERE credential_id IN ({})",
            placeholders(credential_ids.len())
        );
        let mut query = sqlx::query(&sql);
        for id in &credential_ids {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(pool)
            .await
            .map_err(|e| PersonaError::Database(format!("collecting attachments: {e}")))?;
        rows.iter()
            .map(|r| r.try_get::<String, _>(0))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| PersonaError::Database(e.to_string()))?
    };
    let wallet_ids: Vec<String> = {
        let sql = format!("SELECT id FROM crypto_wallets WHERE identity_id IN ({in_identities})");
        let mut query = sqlx::query(&sql);
        for id in marked {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(pool)
            .await
            .map_err(|e| PersonaError::Database(format!("collecting wallets: {e}")))?;
        rows.iter()
            .map(|r| r.try_get::<String, _>(0))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| PersonaError::Database(e.to_string()))?
    };

    // change_history 的 entity_id 全集：身份 ∪ 凭据 ∪ 附件（UUID 互斥）
    let mut history_ids = marked.to_vec();
    history_ids.extend(credential_ids.iter().cloned());
    history_ids.extend(attachment_ids.iter().cloned());

    let mut tables = std::collections::BTreeMap::new();
    tables.insert(
        "identities".to_string(),
        select_rows_by_ids(pool, "identities", "id", marked).await?,
    );
    tables.insert(
        "credentials".to_string(),
        select_rows_by_ids(pool, "credentials", "id", &credential_ids).await?,
    );
    tables.insert(
        "attachments".to_string(),
        select_rows_by_ids(pool, "attachments", "id", &attachment_ids).await?,
    );
    tables.insert(
        "attachment_chunks".to_string(),
        select_rows_by_ids(pool, "attachment_chunks", "attachment_id", &attachment_ids).await?,
    );
    tables.insert(
        "passkeys".to_string(),
        select_rows_by_ids(pool, "passkeys", "identity_id", marked).await?,
    );
    tables.insert(
        "crypto_wallets".to_string(),
        select_rows_by_ids(pool, "crypto_wallets", "id", &wallet_ids).await?,
    );
    tables.insert(
        "wallet_addresses".to_string(),
        select_rows_by_ids(pool, "wallet_addresses", "wallet_id", &wallet_ids).await?,
    );
    tables.insert(
        "wallet_metadata".to_string(),
        select_rows_by_ids(pool, "wallet_metadata", "wallet_id", &wallet_ids).await?,
    );
    tables.insert(
        "transaction_requests".to_string(),
        select_rows_by_ids(pool, "transaction_requests", "wallet_id", &wallet_ids).await?,
    );
    tables.insert(
        "signed_transactions".to_string(),
        select_rows_by_ids(pool, "signed_transactions", "wallet_id", &wallet_ids).await?,
    );
    tables.insert(
        "workspace_members".to_string(),
        select_rows_by_ids(pool, "workspace_members", "identity_id", marked).await?,
    );
    tables.insert(
        "change_history".to_string(),
        select_rows_by_ids(pool, "change_history", "entity_id", &history_ids).await?,
    );

    // 附件 blob 文件（行数 = 文件数：单文件型一行一文件；分块型
    // chunk 行各一个文件）。storage_path 为相对 attachments 根的路径。
    let mut attachment_files = Vec::new();
    let file_rows: Vec<(String, String)> = tables
        .get("attachments")
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let (Some(path), Some(hash)) = (
                row.get("storage_path").and_then(Value::as_str),
                row.get("content_hash").and_then(Value::as_str),
            ) else {
                return None;
            };
            Some((path.to_string(), hash.to_string()))
        })
        .collect();
    let file_rows = {
        let mut all = file_rows;
        for row in tables.get("attachment_chunks").into_iter().flatten() {
            if let (Some(path), Some(hash)) = (
                row.get("storage_path").and_then(Value::as_str),
                row.get("content_hash").and_then(Value::as_str),
            ) {
                all.push((path.to_string(), hash.to_string()));
            }
        }
        all
    };
    if !file_rows.is_empty() {
        let root = attachments_root.ok_or_else(|| {
            PersonaError::ConfigurationError(
                "marked identities have attachments but attachment storage is not initialized"
                    .to_string(),
            )
        })?;
        for (storage_path, expected_hash) in file_rows {
            let bytes = read_blob_file(root, &storage_path)?;
            let actual = sha256_hex(&bytes);
            if actual != expected_hash {
                return Err(PersonaError::Database(format!(
                    "attachment file {storage_path}: content hash mismatch (expected {expected_hash}, got {actual})"
                )));
            }
            attachment_files.push(TravelBlobFile {
                storage_path,
                sha256: expected_hash,
                data_b64: BASE64.encode(bytes),
            });
        }
    }

    // workspace 的 active 指针若指向被移除身份则记入 pack（exit 还原）
    let active_identity_id: Option<String> = {
        let row: Option<(Option<String>, String)> = sqlx::query_as(
            "SELECT active_identity_id, settings FROM workspaces ORDER BY rowid LIMIT 1",
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        match row {
            Some((Some(active), _)) if marked.contains(&active) => Some(active),
            _ => None,
        }
    };

    Ok(TravelPack {
        format_name: FORMAT_NAME.to_string(),
        format_version: FORMAT_VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        active_identity_id,
        identity_ids: marked.to_vec(),
        tables,
        attachment_files,
    })
}

/// 读附件文件（密封态原字节）。storage_path 防逃逸（历史脏数据防御）。
fn read_blob_file(root: &Path, storage_path: &str) -> PersonaResult<Vec<u8>> {
    let relative = Path::new(storage_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(PersonaError::Validation(format!(
            "attachment storage_path escapes storage root: {storage_path}"
        )));
    }
    std::fs::read(root.join(relative))
        .map_err(|e| PersonaError::Io(format!("failed to read attachment {storage_path}: {e}")))
}

/// 写附件文件（密封态原字节；exit 时父目录按需创建）。
fn write_blob_file(root: &Path, storage_path: &str, bytes: &[u8]) -> PersonaResult<()> {
    let relative = Path::new(storage_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(PersonaError::Validation(format!(
            "attachment storage_path escapes storage root: {storage_path}"
        )));
    }
    let target = root.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            PersonaError::Io(format!(
                "failed to create attachment dir {}: {e}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(&target, bytes).map_err(|e| {
        PersonaError::Io(format!(
            "failed to write attachment {}: {e}",
            target.display()
        ))
    })
}

/// 序列化 → gzip → PERSENC1（默认 64 MiB Argon2id；与备份链同款参数，
/// 但口令独立——travel 口令忘了不影响主库，反之亦然）。明文 JSON 在
/// 内存短暂存在（与备份链的快照明文同等暴露面，见模块注释限制节）。
pub(crate) fn seal_pack(
    pack: &TravelPack,
    passphrase: &str,
    kdf: Option<KdfParams>,
) -> PersonaResult<Vec<u8>> {
    let plaintext = serde_json::to_vec(pack)
        .map_err(|e| PersonaError::Validation(format!("pack serialization failed: {e}")))?;
    let gz = gzip_bytes(plaintext);
    encrypt_bytes(&gz, passphrase, kdf)
        .map_err(|e| PersonaError::CryptographicError(format!("travel pack encryption: {e}")))
}

/// 解密解包并校验 format。口令错（GCM 认证失败）与格式不符分路报错。
pub(crate) fn open_pack(bytes: &[u8], passphrase: &str) -> PersonaResult<TravelPack> {
    if !is_persona_encrypted(bytes) {
        return Err(PersonaError::Validation(
            "travel sidecar is not a Persona encrypted file".to_string(),
        ));
    }
    let gz = decrypt_bytes(bytes, passphrase).map_err(|e| {
        PersonaError::AuthenticationFailed(format!(
            "travel passphrase is wrong or the sidecar is corrupted: {e}"
        ))
    })?;
    let plaintext = maybe_gunzip(&gz).map_err(|e| {
        PersonaError::Validation(format!("travel sidecar decompression failed: {e}"))
    })?;
    let pack: TravelPack = serde_json::from_slice(&plaintext).map_err(|e| {
        PersonaError::Validation(format!("travel sidecar is not a valid pack: {e}"))
    })?;
    if pack.format_name != FORMAT_NAME || pack.format_version != FORMAT_VERSION {
        return Err(PersonaError::Validation(format!(
            "unsupported travel sidecar format {} v{} (expected {FORMAT_NAME} v{FORMAT_VERSION})",
            pack.format_name, pack.format_version
        )));
    }
    Ok(pack)
}

/// 原子写 sidecar：同目录 `.tmp` 写完 fsync 后 rename（crash-safe），
/// Unix 下 0600（主库同级的最高敏度文件）。
pub(crate) fn write_sidecar_atomic(path: &Path, bytes: &[u8]) -> PersonaResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| PersonaError::ConfigurationError("sidecar path has no parent".into()))?;
    let tmp = parent.join(format!(".{}.tmp.{}", SIDECAR_FILENAME, std::process::id()));
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| PersonaError::Io(format!("failed to create sidecar tmp: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| PersonaError::Io(format!("failed to chmod sidecar: {e}")))?;
        }
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| PersonaError::Io(format!("failed to write sidecar: {e}")))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| PersonaError::Io(format!("failed to place sidecar: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// enter / exit 事务
// ---------------------------------------------------------------------------

/// enter 的库内删除（单事务）：剥离 audit FK → 清 favicon 缓存 →
/// 删 change_history → settings 置位 + 清 active 指针 → 删 identities
/// （级联清其余表）。
pub(crate) async fn apply_enter_tx(pool: &SqlitePool, pack: &TravelPack) -> PersonaResult<()> {
    let marked = &pack.identity_ids;
    let in_identities = placeholders(marked.len());

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| PersonaError::Database(format!("begin enter tx: {e}")))?;
    let conn = &mut *tx;

    // audit_logs.identity_id / credential_id 有 FK（sqlx 默认 foreign_keys=ON），
    // 必须先剥离引用才能删 identities（与 delete_identity 的
    // clear_identity_reference 同理）；审计行本身留下（只记 id 无明文）。
    {
        let sql = format!(
            "UPDATE audit_logs SET identity_id = NULL WHERE identity_id IN ({in_identities})"
        );
        let mut query = sqlx::query(&sql);
        for id in marked {
            query = query.bind(id);
        }
        query
            .execute(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("clearing audit identity refs: {e}")))?;
    }

    let credential_ids = pack.tables.get("credentials").map(|v| {
        v.iter()
            .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
            .collect::<Vec<_>>()
    });
    if let Some(credential_ids) = credential_ids.as_deref().filter(|v| !v.is_empty()) {
        let sql = format!(
            "UPDATE audit_logs SET credential_id = NULL WHERE credential_id IN ({})",
            placeholders(credential_ids.len())
        );
        let mut query = sqlx::query(&sql);
        for id in credential_ids {
            query = query.bind(id);
        }
        query
            .execute(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("clearing audit credential refs: {e}")))?;
    }

    // favicon_cache 无 FK；必须在 DELETE 之前清（URL 是 credentials 明文
    // 列，行删后就无法区分哪些 host 只被被移除凭据引用了）
    #[cfg(feature = "favicon")]
    prune_favicon_cache_tx(conn, marked).await?;

    // change_history 无 FK，须显式删（快照含明文元数据，随 pack 走）
    {
        let sql = format!("DELETE FROM change_history WHERE entity_id IN ({in_identities})");
        let mut query = sqlx::query(&sql);
        for id in marked {
            query = query.bind(id);
        }
        query
            .execute(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("removing change history: {e}")))?;
    }

    // settings 置位 + active 指针处理（workspaces 首行，单 workspace 惯例）
    set_travel_mode_in_settings(conn, true, pack.active_identity_id.is_some()).await?;

    {
        let sql = format!("DELETE FROM identities WHERE id IN ({in_identities})");
        let mut query = sqlx::query(&sql);
        for id in marked {
            query = query.bind(id);
        }
        query
            .execute(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("removing marked identities: {e}")))?;
    }

    tx.commit()
        .await
        .map_err(|e| PersonaError::Database(format!("commit enter tx: {e}")))?;
    Ok(())
}

/// 事务内清理 favicon_cache 中仅被被移除凭据引用的 host（明文 host 是
/// 被移除身份的浏览痕迹；仍被保留凭据引用的 host 保留）。非 favicon
/// 构建下抓取入口不存在、缓存恒空，无需清理。
#[cfg(feature = "favicon")]
async fn prune_favicon_cache_tx(
    conn: &mut sqlx::SqliteConnection,
    marked: &[String],
) -> PersonaResult<()> {
    use crate::favicon::extract_favicon_host;

    // 被移除凭据与保留凭据各自的 host 集（URL 是明文列，无需解密）。
    // 不可抓取的 URL（IP/内网/非 https）本就进不了缓存，提取失败即跳过。
    let hosts_of = |urls: Vec<Option<String>>| -> Vec<String> {
        let mut hosts = Vec::new();
        for url in urls.into_iter().flatten() {
            if let Ok(host) = extract_favicon_host(&url) {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        hosts
    };

    let removed_urls = {
        let sql = format!(
            "SELECT url FROM credentials WHERE identity_id IN ({})",
            placeholders(marked.len())
        );
        let mut query = sqlx::query_scalar::<_, Option<String>>(&sql);
        for id in marked {
            query = query.bind(id);
        }
        query
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("collecting removed urls: {e}")))?
    };

    let kept_urls = {
        let sql = format!(
            "SELECT url FROM credentials WHERE identity_id IS NULL OR identity_id NOT IN ({})",
            placeholders(marked.len())
        );
        let mut query = sqlx::query_scalar::<_, Option<String>>(&sql);
        for id in marked {
            query = query.bind(id);
        }
        query
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("collecting kept urls: {e}")))?
    };

    let kept_hosts = hosts_of(kept_urls);
    let doomed: Vec<String> = hosts_of(removed_urls)
        .into_iter()
        .filter(|host| !kept_hosts.contains(host))
        .collect();
    if doomed.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "DELETE FROM favicon_cache WHERE host IN ({})",
        placeholders(doomed.len())
    );
    let mut query = sqlx::query(&sql);
    for host in &doomed {
        query = query.bind(host);
    }
    query
        .execute(&mut *conn)
        .await
        .map_err(|e| PersonaError::Database(format!("pruning favicon cache: {e}")))?;
    Ok(())
}

/// exit 的库内恢复（单事务，失败回滚、sidecar 保留）：INSERT OR REPLACE
/// 父表在前 + settings 复位 + active 指针还原。
pub(crate) async fn apply_exit_tx(pool: &SqlitePool, pack: &TravelPack) -> PersonaResult<()> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| PersonaError::Database(format!("begin exit tx: {e}")))?;
    let conn = &mut *tx;

    for table in PACKED_TABLES_IN_INSERT_ORDER {
        check_table_name(table)?;
        if let Some(rows) = pack.tables.get(*table) {
            insert_rows(conn, table, rows).await?;
        }
    }

    set_travel_mode_in_settings(conn, false, false).await?;
    if let Some(active) = &pack.active_identity_id {
        sqlx::query("UPDATE workspaces SET active_identity_id = ? WHERE rowid = (SELECT rowid FROM workspaces ORDER BY rowid LIMIT 1)")
            .bind(active)
            .execute(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("restoring active identity: {e}")))?;
    }

    tx.commit()
        .await
        .map_err(|e| PersonaError::Database(format!("commit exit tx: {e}")))?;
    Ok(())
}

/// settings JSON 里 travel_mode/travel_entered_at 的读写（直连 SQL，
/// 不绕 WorkspaceRepository——travel.rs 不依赖类型化 repo）。
async fn set_travel_mode_in_settings(
    conn: &mut sqlx::SqliteConnection,
    active: bool,
    clear_active_identity: bool,
) -> PersonaResult<()> {
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT rowid, settings FROM workspaces ORDER BY rowid LIMIT 1")
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
    let Some((rowid, settings_json)) = row else {
        return Err(PersonaError::NotFound(
            "no workspace row; run `persona migrate` first".to_string(),
        ));
    };
    let mut settings: Value = serde_json::from_str(&settings_json)
        .map_err(|e| PersonaError::Database(format!("workspace settings JSON: {e}")))?;
    let Some(obj) = settings.as_object_mut() else {
        return Err(PersonaError::Database(
            "workspace settings is not an object".into(),
        ));
    };
    obj.insert("travel_mode".into(), Value::Bool(active));
    if active {
        obj.insert(
            "travel_entered_at".into(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
    } else {
        obj.insert("travel_entered_at".into(), Value::Null);
    }
    let updated =
        serde_json::to_string(&settings).map_err(|e| PersonaError::Database(e.to_string()))?;

    let sql = if clear_active_identity {
        "UPDATE workspaces SET settings = ?, active_identity_id = NULL WHERE rowid = ?"
    } else {
        "UPDATE workspaces SET settings = ? WHERE rowid = ?"
    };
    sqlx::query(sql)
        .bind(&updated)
        .bind(rowid)
        .execute(&mut *conn)
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
    Ok(())
}

/// 删除被移除身份的附件 blob 文件（enter 事务提交后 best-effort：
/// 失败项 warn 并计入返回清单——exit 会按 storage_path 覆写自愈）。
pub(crate) fn delete_blob_files(root: &Path, files: &[TravelBlobFile]) -> Vec<String> {
    let mut failures = Vec::new();
    for file in files {
        let relative = Path::new(&file.storage_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            failures.push(format!("{} (path escapes root)", file.storage_path));
            continue;
        }
        match std::fs::remove_file(root.join(relative)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    "travel enter: failed to remove attachment {}: {e}",
                    file.storage_path
                );
                failures.push(file.storage_path.clone());
            }
        }
    }
    failures
}

/// 重写附件 blob 文件（exit 事务提交后；行已恢复，此步失败可整条重试，
/// INSERT OR REPLACE 与文件覆写均幂等）。路径逃逸校验先于内容校验：
/// 坏路径直接拒绝，不浪费解码与哈希。
pub(crate) fn write_blob_files(root: &Path, files: &[TravelBlobFile]) -> PersonaResult<()> {
    for file in files {
        let relative = Path::new(&file.storage_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(PersonaError::Validation(format!(
                "attachment storage_path escapes storage root: {}",
                file.storage_path
            )));
        }
        let bytes = BASE64.decode(&file.data_b64).map_err(|e| {
            PersonaError::Validation(format!("attachment {}: bad base64: {e}", file.storage_path))
        })?;
        let actual = sha256_hex(&bytes);
        if actual != file.sha256 {
            return Err(PersonaError::Validation(format!(
                "attachment {}: integrity check failed (expected {}, got {})",
                file.storage_path, file.sha256, actual
            )));
        }
        write_blob_file(root, &file.storage_path, &bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Identity, IdentityType};
    use crate::storage::repository::{IdentityRepository, Repository};
    use crate::storage::Database;

    /// 测试 KDF：8 MiB（解密侧恒 3/1，iterations 不能动）。
    fn fast_kdf() -> KdfParams {
        KdfParams {
            mem_kib: 8 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    async fn seeded_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        // enter/exit 都要读写 workspaces 首行 settings；migrate 不建行，
        // 与生产 `persona init` 对齐由这里显式建。
        use crate::models::Workspace;
        use crate::storage::WorkspaceRepository;
        let ws_repo = WorkspaceRepository::new(db.clone());
        crate::storage::Repository::create(
            &ws_repo,
            &Workspace::new(dir.path(), "test".to_string()),
        )
        .await
        .unwrap();
        let repo = IdentityRepository::new(db.clone());
        repo.create(&Identity::new("A".to_owned(), IdentityType::Personal))
            .await
            .unwrap();
        repo.create(&Identity::new("B".to_owned(), IdentityType::Work))
            .await
            .unwrap();
        (dir, db)
    }

    #[test]
    fn sidecar_path_sits_next_to_db() {
        assert_eq!(
            sidecar_path(Path::new("/data/persona/identities.db")),
            PathBuf::from("/data/persona/travel.persenc")
        );
        assert_eq!(
            sidecar_path(Path::new("identities.db")),
            PathBuf::from("travel.persenc")
        );
    }

    /// 行恢复入口的防御面：坏 base64、无 b64 键的对象、不支持的 JSON
    /// 类型、非法列名、空行逐类拒绝；Bool 落表为 INTEGER 1/0。
    #[tokio::test]
    async fn insert_rows_rejects_malformed_cells_and_column_names() {
        let (_dir, db) = seeded_db().await;
        let mut conn = db.pool().acquire().await.unwrap();
        sqlx::query("CREATE TABLE probe (flag INTEGER, blob BLOB, num REAL)")
            .execute(&mut *conn)
            .await
            .unwrap();

        let row_with = |key: &str, value: Value| {
            let mut row = Map::new();
            row.insert(key.to_string(), value);
            vec![row]
        };

        // 标记对象但 base64 非法
        let err = insert_rows(&mut conn, "probe", &row_with("blob", json!({"b64": "!!"})))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad base64"), "{err}");

        // 对象缺 b64 键
        let err = insert_rows(&mut conn, "probe", &row_with("blob", json!({"other": 1})))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unexpected object cell"), "{err}");

        // 不支持的 JSON 值（数组）
        let err = insert_rows(&mut conn, "probe", &row_with("blob", json!([1, 2])))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unsupported JSON value"), "{err}");

        // 非法列名（连字符不在白名单）
        let err = insert_rows(&mut conn, "probe", &row_with("bad-name", json!(1)))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("illegal column name"), "{err}");

        // 空行
        let err = insert_rows(&mut conn, "probe", &[Map::new()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty row"), "{err}");

        // Bool 走 Int 通道落表
        insert_rows(&mut conn, "probe", &row_with("flag", Value::Bool(true)))
            .await
            .unwrap();
        let flag: i64 = sqlx::query_scalar("SELECT flag FROM probe")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(flag, 1);
    }

    #[tokio::test]
    async fn pack_rows_and_round_trips_through_seal_open() {
        let (_dir, db) = seeded_db().await;
        let marked: Vec<String> = IdentityRepository::new(db.clone())
            .find_all()
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.id.to_string())
            .collect();
        let pack = build_pack(db.pool(), None, &marked).await.unwrap();
        assert_eq!(pack.tables.get("identities").unwrap().len(), 2);
        assert_eq!(pack.format_name, FORMAT_NAME);
        assert!(pack.attachment_files.is_empty());

        let sealed = seal_pack(&pack, "travel-pw", Some(fast_kdf())).unwrap();
        assert!(is_persona_encrypted(&sealed));
        let opened = open_pack(&sealed, "travel-pw").unwrap();
        assert_eq!(opened.tables.len(), pack.tables.len());
        assert_eq!(opened.identity_ids, pack.identity_ids);

        let err = open_pack(&sealed, "wrong").unwrap_err();
        assert!(err.to_string().contains("passphrase is wrong"), "{err}");

        // 坏 magic：非 PERSENC1 字节直接拒绝
        let err = open_pack(b"not encrypted at all", "travel-pw").unwrap_err();
        assert!(
            err.to_string().contains("not a Persona encrypted file"),
            "{err}"
        );

        // format 校验（TravelPack 字段全 pub，直接构造坏格式）
        let mut bad = build_pack(db.pool(), None, &marked).await.unwrap();
        bad.format_name = "other".into();
        let sealed_bad = seal_pack(&bad, "travel-pw", Some(fast_kdf())).unwrap();
        let err = open_pack(&sealed_bad, "travel-pw").unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported travel sidecar format"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn enter_exit_round_trip_preserves_rows() {
        let (_dir, db) = seeded_db().await;
        let repo = IdentityRepository::new(db.clone());
        let all = repo.find_all().await.unwrap();
        let marked: Vec<String> = all.iter().map(|i| i.id.to_string()).collect();

        let pack = build_pack(db.pool(), None, &marked).await.unwrap();
        apply_enter_tx(db.pool(), &pack).await.unwrap();
        assert!(
            repo.find_all().await.unwrap().is_empty(),
            "marked identities must be gone after enter"
        );

        apply_exit_tx(db.pool(), &pack).await.unwrap();
        let restored = repo.find_all().await.unwrap();
        assert_eq!(restored.len(), 2);
        let mut restored_ids: Vec<String> = restored.iter().map(|i| i.id.to_string()).collect();
        let mut expected_ids = marked.clone();
        restored_ids.sort();
        expected_ids.sort();
        assert_eq!(restored_ids, expected_ids);
    }

    #[tokio::test]
    async fn enter_exit_clears_and_restores_travel_mode_settings() {
        let (_dir, db) = seeded_db().await;
        let marked: Vec<String> = IdentityRepository::new(db.clone())
            .find_all()
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.id.to_string())
            .collect();
        let pack = build_pack(db.pool(), None, &marked).await.unwrap();

        apply_enter_tx(db.pool(), &pack).await.unwrap();
        let (mode, entered_at): (i64, Option<String>) = sqlx::query_as(
            "SELECT json_extract(settings, '$.travel_mode'), json_extract(settings, '$.travel_entered_at') FROM workspaces LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(mode, 1);
        assert!(entered_at.is_some());

        apply_exit_tx(db.pool(), &pack).await.unwrap();
        let (mode, entered_at): (i64, Option<String>) = sqlx::query_as(
            "SELECT json_extract(settings, '$.travel_mode'), json_extract(settings, '$.travel_entered_at') FROM workspaces LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(mode, 0);
        assert!(entered_at.is_none());
    }

    #[tokio::test]
    async fn blob_files_round_trip_with_hash_check() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("attachments");
        std::fs::create_dir_all(&root).unwrap();
        let bytes = b"sealed attachment bytes \xf0\x9f\x94\x92".to_vec();
        let storage_path = format!("{}/att1/file.bin", uuid::Uuid::new_v4());
        let full = root.join(&storage_path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(&full, &bytes).unwrap();

        // read → pack → write 回新 root，逐字节相等
        let file = TravelBlobFile {
            storage_path: storage_path.clone(),
            sha256: sha256_hex(&bytes),
            data_b64: BASE64.encode(&bytes),
        };
        let new_root = dir.path().join("attachments2");
        std::fs::create_dir_all(&new_root).unwrap();
        write_blob_files(&new_root, &[file]).unwrap();
        assert_eq!(std::fs::read(new_root.join(&storage_path)).unwrap(), bytes);

        // 删除（含 NotFound 容忍）与逃逸防御
        assert!(delete_blob_files(
            &root,
            &[TravelBlobFile {
                storage_path: storage_path.clone(),
                sha256: String::new(),
                data_b64: String::new(),
            }]
        )
        .is_empty());
        assert!(!full.exists());
        assert!(
            delete_blob_files(
                &root,
                &[TravelBlobFile {
                    storage_path: storage_path.clone(),
                    sha256: String::new(),
                    data_b64: String::new(),
                }]
            )
            .is_empty(),
            "already-deleted file is not a failure"
        );

        let escaped = TravelBlobFile {
            storage_path: "../escape.bin".to_string(),
            sha256: String::new(),
            data_b64: String::new(),
        };
        assert!(!delete_blob_files(&root, std::slice::from_ref(&escaped)).is_empty());
        let err = write_blob_files(&new_root, std::slice::from_ref(&escaped)).unwrap_err();
        assert!(err.to_string().contains("escapes storage root"), "{err}");

        // hash 不符拒绝写回
        let tampered = TravelBlobFile {
            storage_path: "x/y.bin".to_string(),
            sha256: sha256_hex(b"different"),
            data_b64: BASE64.encode(&bytes),
        };
        let err = write_blob_files(&new_root, &[tampered]).unwrap_err();
        assert!(err.to_string().contains("integrity check failed"), "{err}");
    }

    #[tokio::test]
    async fn write_sidecar_atomic_places_file_with_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("travel.persenc");
        write_sidecar_atomic(&path, b"sealed").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"sealed");

        // 覆盖写也走 tmp+rename（无 .tmp 残留）
        write_sidecar_atomic(&path, b"sealed2").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"sealed2");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "tmp files must be renamed away");
    }
}
