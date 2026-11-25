//! The in-database single transaction for enter / exit: deletion (stripping
//! audit FK references first) and restore (`INSERT OR REPLACE` with parent
//! tables first), including favicon cache pruning and the settings travel
//! flag read/write.

use serde_json::Value;
use sqlx::{AssertSqlSafe, SqlitePool};

use super::codec::{check_table_name, insert_rows};
use super::model::TravelPack;
use super::pack::placeholders;
use super::PACKED_TABLES_IN_INSERT_ORDER;
use crate::{PersonaError, PersonaResult};

/// enter's in-database deletion (single transaction): strip audit FKs ->
/// prune the favicon cache -> delete change_history -> set the settings
/// flag + clear the active pointer -> delete identities (which cascades to
/// the remaining tables).
pub(crate) async fn apply_enter_tx(pool: &SqlitePool, pack: &TravelPack) -> PersonaResult<()> {
    let marked = &pack.identity_ids;
    let in_identities = placeholders(marked.len());

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| PersonaError::Database(format!("begin enter tx: {e}")))?;
    let conn = &mut *tx;

    // audit_logs.identity_id / credential_id are FKs (sqlx defaults to
    // foreign_keys=ON), so the references must be stripped before identities
    // can be deleted (same reasoning as delete_identity's
    // clear_identity_reference); the audit rows themselves stay (ids only,
    // no plaintext).
    {
        let sql = format!(
            "UPDATE audit_logs SET identity_id = NULL WHERE identity_id IN ({in_identities})"
        );
        let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
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
        let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
        for id in credential_ids {
            query = query.bind(id);
        }
        query
            .execute(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("clearing audit credential refs: {e}")))?;
    }

    // favicon_cache has no FK; it must be pruned before the DELETE (the URL
    // is a plaintext column of credentials, and once the rows are gone there
    // is no way to tell which hosts were referenced only by the removed
    // credentials)
    #[cfg(feature = "favicon")]
    prune_favicon_cache_tx(conn, marked).await?;

    // change_history has no FK and must be deleted explicitly (its snapshots
    // hold plaintext metadata and travel with the pack)
    {
        let sql = format!("DELETE FROM change_history WHERE entity_id IN ({in_identities})");
        let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
        for id in marked {
            query = query.bind(id);
        }
        query
            .execute(&mut *conn)
            .await
            .map_err(|e| PersonaError::Database(format!("removing change history: {e}")))?;
    }

    // Set the settings flag + handle the active pointer (first workspaces
    // row, single-workspace convention)
    set_travel_mode_in_settings(conn, true, pack.active_identity_id.is_some()).await?;

    {
        let sql = format!("DELETE FROM identities WHERE id IN ({in_identities})");
        let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
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

/// Prune hosts from favicon_cache that are referenced only by removed
/// credentials (a plaintext host is a browsing trace of a removed identity;
/// hosts still referenced by kept credentials are preserved). Without the
/// favicon feature there is no fetching entry point and the cache is always
/// empty, so nothing needs pruning.
#[cfg(feature = "favicon")]
async fn prune_favicon_cache_tx(
    conn: &mut sqlx::SqliteConnection,
    marked: &[String],
) -> PersonaResult<()> {
    use crate::favicon::extract_favicon_host;

    // The host sets of the removed and the kept credentials (URL is a
    // plaintext column, no decryption needed). Unfetchable URLs (IP /
    // internal / non-https) can never reach the cache, so a failed
    // extraction is skipped.
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
        let mut query = sqlx::query_scalar::<_, Option<String>>(AssertSqlSafe(sql.as_str()));
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
        let mut query = sqlx::query_scalar::<_, Option<String>>(AssertSqlSafe(sql.as_str()));
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
    let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
    for host in &doomed {
        query = query.bind(host);
    }
    query
        .execute(&mut *conn)
        .await
        .map_err(|e| PersonaError::Database(format!("pruning favicon cache: {e}")))?;
    Ok(())
}

/// exit's in-database restore (single transaction; failure rolls back and
/// leaves the sidecar in place): `INSERT OR REPLACE` with parent tables
/// first + reset settings + restore the active pointer.
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

/// Read/write travel_mode/travel_entered_at inside the settings JSON (plain
/// SQL, bypassing WorkspaceRepository -- travel does not depend on typed
/// repositories).
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
