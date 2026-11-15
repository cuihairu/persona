//! 跨库读取聚合：把被标记身份关联的全部行与附件字节打包成
//! `TravelPack`。

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{Map, Value};
use sqlx::{AssertSqlSafe, Row, SqlitePool};
use std::path::Path;

use super::blob::read_blob_file;
use super::codec::row_to_json;
use super::model::{TravelBlobFile, TravelPack};
use super::{sha256_hex, FORMAT_NAME, FORMAT_VERSION};
use crate::{PersonaError, PersonaResult};

/// 逗号分隔的 `?` 占位符串（IN 子句用）。
pub(super) fn placeholders(count: usize) -> String {
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
    let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
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
        let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
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
        let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
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
        let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
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
