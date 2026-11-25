//! Cross-database read aggregation: pack all rows tied to the marked
//! identities plus attachment bytes into a `TravelPack`.

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

/// Comma-separated string of `?` placeholders (for IN clauses).
pub(super) fn placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
}

/// Read one row set: `SELECT * FROM {table} WHERE {key} IN (...)`.
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

/// Read all data rows of the marked identities + attachment file bytes.
///
/// `attachments_root`: the attachment root directory
/// (`AttachmentManager::storage_root()`); error out when the marked
/// identities have attachment rows but this is None (the caller service
/// guarantees it is passed).
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

    // Expand credential/attachment/wallet ids (attachment_chunks and the
    // wallet child tables are collected by parent id)
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

    // Full entity_id set for change_history: identities ∪ credentials ∪
    // attachments (mutually exclusive UUIDs)
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

    // Attachment blob files (row count == file count: single-file rows are
    // one file each; chunked attachments have one file per chunk row).
    // storage_path is relative to the attachments root.
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

    // If the workspace active pointer targets a removed identity, record it
    // in the pack (restored on exit)
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
