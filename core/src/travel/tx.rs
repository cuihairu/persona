//! enter / exit 的库内单事务：删除（先剥离 audit FK 引用）与恢复
//! （父表在前 `INSERT OR REPLACE`），含 favicon 缓存清理与 settings
//! travel 旗标读写。

use serde_json::Value;
use sqlx::{AssertSqlSafe, SqlitePool};

use super::codec::{check_table_name, insert_rows};
use super::model::TravelPack;
use super::pack::placeholders;
use super::PACKED_TABLES_IN_INSERT_ORDER;
use crate::{PersonaError, PersonaResult};

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

    // favicon_cache 无 FK；必须在 DELETE 之前清（URL 是 credentials 明文
    // 列，行删后就无法区分哪些 host 只被被移除凭据引用了）
    #[cfg(feature = "favicon")]
    prune_favicon_cache_tx(conn, marked).await?;

    // change_history 无 FK，须显式删（快照含明文元数据，随 pack 走）
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

    // settings 置位 + active 指针处理（workspaces 首行，单 workspace 惯例）
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
