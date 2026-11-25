//! Local oplog and sync-state storage (E2EE_SYNC_DESIGN §5; migration 014).
//!
//! Division of labor: this repo only does append-only persistence and
//! state reads/writes; LWW arbitration lives in [`crate::sync::oplog`]
//! (pure functions), and sync orchestration (push/pull/travel gating) lives in
//! the phase 2, batch 4 engine. Rows with `origin='remote'` never enter the
//! push queue; the op_id primary key plus `INSERT OR IGNORE` provides
//! storage-level idempotency (replay-safe).

use chrono::{DateTime, Utc};
use sqlx::AssertSqlSafe;
use sqlx::Row;
use std::collections::HashSet;
use uuid::Uuid;

use crate::storage::Database;
use crate::sync::oplog::{OpType, SyncOp, SyncPayload};
use crate::{PersonaError, Result};

/// This device's sync state (the single sync_state row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    /// Local Lamport clock: a local write = this value + 1; after a pull =
    /// max(this value, the remote maximum).
    pub local_lamport: u64,
    /// This device's identity in the sync group (filled in after registration).
    pub device_id: Option<Uuid>,
    /// Pull cursor (server seq); None = from the beginning.
    pub last_pull_cursor: Option<String>,
    /// Time of the last successful sync cycle (migration 017;
    /// None = never synced).
    pub last_sync_at: Option<DateTime<Utc>>,
    /// Coverage point of this machine's most recent db-level snapshot
    /// (migration 018; 0 = no snapshot ever) — recorded when an upload or
    /// bootstrap package install succeeds; the comparison baseline for the
    /// snapshot trigger threshold (E2EE_SYNC_DESIGN §5 "when to trigger").
    pub last_snapshot_seq: i64,
}

pub struct SyncRepository {
    db: Database,
}

impl SyncRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ---- sync_state ----

    /// Read this device's sync state; returns all defaults when the row is
    /// missing (lamport 0 / not registered / no cursor).
    pub async fn get_state(&self) -> Result<SyncState> {
        let row = sqlx::query(
            "SELECT local_lamport, device_id, last_pull_cursor, last_sync_at, last_snapshot_seq
             FROM sync_state WHERE id = 1",
        )
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        let Some(row) = row else {
            return Ok(SyncState {
                local_lamport: 0,
                device_id: None,
                last_pull_cursor: None,
                last_sync_at: None,
                last_snapshot_seq: 0,
            });
        };
        let device_id: Option<String> = row.get("device_id");
        let last_sync_at: Option<String> = row.get("last_sync_at");
        Ok(SyncState {
            local_lamport: row.get::<i64, _>("local_lamport") as u64,
            device_id: device_id.and_then(|s| Uuid::parse_str(&s).ok()),
            last_pull_cursor: row.get("last_pull_cursor"),
            last_sync_at: last_sync_at
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|t| t.with_timezone(&Utc)),
            last_snapshot_seq: row.get::<i64, _>("last_snapshot_seq"),
        })
    }

    /// Advance the Lamport clock forward only (`MAX` semantics, guarding against
    /// regression).
    pub async fn bump_lamport(&self, to: u64) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_state (id, local_lamport) VALUES (1, ?)
             ON CONFLICT(id) DO UPDATE SET local_lamport = MAX(local_lamport, excluded.local_lamport)",
        )
        .bind(to as i64)
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn set_device_id(&self, device_id: Uuid) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_state (id, device_id) VALUES (1, ?)
             ON CONFLICT(id) DO UPDATE SET device_id = excluded.device_id",
        )
        .bind(device_id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn set_last_pull_cursor(&self, cursor: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_state (id, last_pull_cursor) VALUES (1, ?)
             ON CONFLICT(id) DO UPDATE SET last_pull_cursor = excluded.last_pull_cursor",
        )
        .bind(cursor)
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    /// Record the "last successful sync cycle" time (the status display in
    /// sync-group-mode §2.5.5).
    pub async fn mark_synced(&self, at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_state (id, last_sync_at) VALUES (1, ?)
             ON CONFLICT(id) DO UPDATE SET last_sync_at = excluded.last_sync_at",
        )
        .bind(at.to_rfc3339())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    /// Record the coverage point of this machine's most recent db-level snapshot
    /// (on successful upload and bootstrap package install).
    /// `MAX` semantics means forward only: a regressing watermark makes the
    /// trigger threshold fire prematurely (an extra package, the harmless
    /// direction), while the forward direction must be honest — overstating it
    /// would delay a repack.
    pub async fn set_last_snapshot_seq(&self, seq: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_state (id, last_snapshot_seq) VALUES (1, ?)
             ON CONFLICT(id) DO UPDATE SET last_snapshot_seq = MAX(last_snapshot_seq, excluded.last_snapshot_seq)",
        )
        .bind(seq)
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    /// This machine's synced watermark: the pull cursor decoded back to a server
    /// seq; no cursor (never pulled) = 0.
    pub async fn local_watermark(&self) -> Result<i64> {
        let state = self.get_state().await?;
        Ok(state
            .last_pull_cursor
            .as_deref()
            .and_then(|raw| crate::sync::cursor::decode_cursor(raw).ok())
            .map(|(seq, _)| seq)
            .unwrap_or(0))
    }

    /// Push queue length (ops produced locally but not yet pushed to the server).
    pub async fn pending_count(&self) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM sync_oplog WHERE origin = 'local' AND push_state = 'pending'",
        )
        .fetch_one(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(row.get::<i64, _>("n"))
    }

    // ---- oplog ----

    /// Append one locally produced op (the push queue). An existing op_id is
    /// silently ignored (idempotent).
    pub async fn append_local_op(&self, op: &SyncOp) -> Result<()> {
        self.insert_op(op, "local", "pending").await
    }

    /// Record a remote op pulled from the server (the durable basis for idempotent
    /// deduplication; never enters the push queue).
    pub async fn record_remote_op(&self, op: &SyncOp) -> Result<()> {
        self.insert_op(op, "remote", "acked").await
    }

    async fn insert_op(&self, op: &SyncOp, origin: &str, push_state: &str) -> Result<()> {
        let (ciphertext, wrapped_item_key) = match &op.payload {
            Some(p) => (Some(&p.ciphertext), Some(&p.wrapped_item_key)),
            None => (None, None),
        };
        sqlx::query(
            "INSERT OR IGNORE INTO sync_oplog
                (op_id, item_id, kind, op, lamport, device_id, timestamp,
                 ciphertext, wrapped_item_key, origin, push_state)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(op.op_id.to_string())
        .bind(op.item_id.to_string())
        .bind(
            serde_json::to_string(&op.kind)
                .map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
        )
        .bind(match op.op {
            OpType::Put => "put",
            OpType::Delete => "delete",
        })
        .bind(op.lamport as i64)
        .bind(op.device_id.to_string())
        .bind(op.timestamp.map(|t| t.to_rfc3339()))
        .bind(ciphertext)
        .bind(wrapped_item_key)
        .bind(origin)
        .bind(push_state)
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn has_op(&self, op_id: Uuid) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(1) AS cnt FROM sync_oplog WHERE op_id = ?")
            .bind(op_id.to_string())
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(row.get::<i64, _>("cnt") > 0)
    }

    /// The set of already-persisted op_ids (batch dedup: filters replays before
    /// applying a pull).
    pub async fn existing_op_ids(&self, ids: &[Uuid]) -> Result<HashSet<Uuid>> {
        let mut seen = HashSet::new();
        for id in ids {
            if self.has_op(*id).await? {
                seen.insert(*id);
            }
        }
        Ok(seen)
    }

    /// The push queue: local unacknowledged ops, flattened in ascending
    /// (lamport, device_id, op_id) order.
    pub async fn pending_ops(&self, limit: i64) -> Result<Vec<SyncOp>> {
        let rows = sqlx::query(
            "SELECT op_id, item_id, kind, op, lamport, device_id, timestamp,
                    ciphertext, wrapped_item_key
             FROM sync_oplog
             WHERE origin = 'local' AND push_state = 'pending'
             ORDER BY lamport, device_id, op_id
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        rows.iter().map(row_to_op).collect()
    }

    /// Batch-acknowledge after a successful push.
    pub async fn mark_acked(&self, op_ids: &[Uuid]) -> Result<()> {
        for id in op_ids {
            sqlx::query("UPDATE sync_oplog SET push_state = 'acked' WHERE op_id = ?")
                .bind(id.to_string())
                .execute(self.db.pool())
                .await
                .map_err(|e| PersonaError::Database(e.to_string()))?;
        }
        Ok(())
    }

    /// The set of ops in the push queue not yet acked — GC's protected set
    /// (changes not pushed out are never cleaned up). Rows from remote are
    /// always acked, so no extra origin filtering is needed.
    pub async fn pending_op_ids(&self) -> Result<HashSet<Uuid>> {
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT op_id FROM sync_oplog WHERE push_state = 'pending'")
                .fetch_all(self.db.pool())
                .await
                .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(rows
            .into_iter()
            .filter_map(|s| Uuid::parse_str(&s).ok())
            .collect())
    }

    /// Batch-delete oplog rows (GC only; deletes only op_ids the caller selected
    /// under a safety predicate).
    /// Chunks inside one transaction and returns the number of rows actually
    /// deleted.
    pub async fn delete_ops(&self, op_ids: &[Uuid]) -> Result<u64> {
        if op_ids.is_empty() {
            return Ok(0);
        }
        let mut tx = self
            .db
            .pool()
            .begin()
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        let mut removed = 0u64;
        for chunk in op_ids.chunks(64) {
            let placeholders = vec!["?"; chunk.len()].join(", ");
            let sql = format!("DELETE FROM sync_oplog WHERE op_id IN ({placeholders})");
            let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
            for id in chunk {
                query = query.bind(id.to_string());
            }
            let result = query
                .execute(&mut *tx)
                .await
                .map_err(|e| PersonaError::Database(e.to_string()))?;
            removed += result.rows_affected();
        }
        tx.commit()
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(removed)
    }

    /// All ops of one item (consumed by [`crate::sync::oplog::item_view`] to
    /// derive the primary / replicas).
    pub async fn item_ops(&self, item_id: Uuid) -> Result<Vec<SyncOp>> {
        let rows = sqlx::query(
            "SELECT op_id, item_id, kind, op, lamport, device_id, timestamp,
                    ciphertext, wrapped_item_key
             FROM sync_oplog WHERE item_id = ?
             ORDER BY lamport, device_id, op_id",
        )
        .bind(item_id.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        rows.iter().map(row_to_op).collect()
    }

    /// Every item that ever had a write in the oplog (deduplicated, for the
    /// materialization layer to derive views item by item).
    /// Order of magnitude = the total number of entries ever synced in this
    /// workspace, so a single query suffices.
    pub async fn item_ids(&self) -> Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT DISTINCT item_id FROM sync_oplog")
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        rows.iter()
            .map(|row| {
                Uuid::parse_str(&row.get::<String, _>("item_id"))
                    .map_err(|e| PersonaError::Database(e.to_string()).into())
            })
            .collect()
    }
}

fn row_to_op(row: &sqlx::sqlite::SqliteRow) -> Result<SyncOp> {
    let kind_str: String = row.get("kind");
    let op_str: String = row.get("op");
    let timestamp: Option<String> = row.get("timestamp");
    let ciphertext: Option<Vec<u8>> = row.get("ciphertext");
    let wrapped_item_key: Option<Vec<u8>> = row.get("wrapped_item_key");
    let payload = match (ciphertext, wrapped_item_key) {
        (Some(c), Some(w)) => Some(SyncPayload {
            ciphertext: c,
            wrapped_item_key: w,
        }),
        (None, None) => None,
        _ => {
            return Err(PersonaError::Database(
                "sync_oplog payload columns partially null".to_string(),
            )
            .into())
        }
    };
    Ok(SyncOp {
        op_id: Uuid::parse_str(&row.get::<String, _>("op_id"))
            .map_err(|e| PersonaError::Database(e.to_string()))?,
        item_id: Uuid::parse_str(&row.get::<String, _>("item_id"))
            .map_err(|e| PersonaError::Database(e.to_string()))?,
        kind: serde_json::from_str(&kind_str)
            .map_err(|e| PersonaError::Database(format!("unknown sync kind: {e}")))?,
        op: match op_str.as_str() {
            "put" => OpType::Put,
            "delete" => OpType::Delete,
            other => {
                return Err(PersonaError::Database(format!("unknown sync op type: {other}")).into())
            }
        },
        lamport: row.get::<i64, _>("lamport") as u64,
        device_id: Uuid::parse_str(&row.get::<String, _>("device_id"))
            .map_err(|e| PersonaError::Database(e.to_string()))?,
        timestamp: timestamp
            .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
            .map(|t| t.with_timezone(&Utc)),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::oplog::{ItemKind, SyncPayload};

    async fn db() -> Database {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    fn put_op(lamport: u64, tag: u8) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            kind: ItemKind::Credential,
            op: OpType::Put,
            lamport,
            device_id: Uuid::new_v4(),
            timestamp: Some(Utc::now()),
            payload: Some(SyncPayload {
                ciphertext: vec![tag; 16],
                wrapped_item_key: vec![tag; 32],
            }),
        }
    }

    #[tokio::test]
    async fn state_defaults_then_bumps_monotonically() {
        let repo = SyncRepository::new(db().await);
        let initial = repo.get_state().await.unwrap();
        assert_eq!(initial.local_lamport, 0);
        assert_eq!(initial.device_id, None);
        assert_eq!(initial.last_pull_cursor, None);

        repo.bump_lamport(5).await.unwrap();
        repo.bump_lamport(3).await.unwrap(); // regression attempt: MAX semantics blocks it
        assert_eq!(repo.get_state().await.unwrap().local_lamport, 5);

        let device = Uuid::new_v4();
        repo.set_device_id(device).await.unwrap();
        repo.set_last_pull_cursor(Some("cursor-7")).await.unwrap();
        let state = repo.get_state().await.unwrap();
        assert_eq!(state.device_id, Some(device));
        assert_eq!(state.last_pull_cursor.as_deref(), Some("cursor-7"));
    }

    #[tokio::test]
    async fn append_is_idempotent_and_fills_push_queue_in_order() {
        let repo = SyncRepository::new(db().await);
        let mut ops: Vec<SyncOp> = (0..3u8).map(|i| put_op(u64::from(i) + 1, i)).collect();
        // The append order is deliberately shuffled
        ops.swap(0, 2);

        for op in &ops {
            repo.append_local_op(op).await.unwrap();
            repo.append_local_op(op).await.unwrap(); // duplicate append with the same op_id: ignored
        }

        let pending = repo.pending_ops(100).await.unwrap();
        assert_eq!(pending.len(), 3);
        // The queue is ascending by (lamport, ...)
        let lamports: Vec<u64> = pending.iter().map(|o| o.lamport).collect();
        let mut sorted = lamports.clone();
        sorted.sort();
        assert_eq!(lamports, sorted);

        // Ciphertext payload round-trips (tag = lamport-1, see put_op)
        assert_eq!(
            pending[0].payload.as_ref().unwrap().ciphertext,
            vec![0u8; 16]
        );

        repo.mark_acked(&[pending[0].op_id, pending[1].op_id])
            .await
            .unwrap();
        let remaining = repo.pending_ops(100).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].lamport, 3);
    }

    #[tokio::test]
    async fn remote_ops_never_enter_push_queue() {
        let repo = SyncRepository::new(db().await);
        let op = put_op(1, 9);
        repo.record_remote_op(&op).await.unwrap();

        assert!(repo.has_op(op.op_id).await.unwrap());
        assert!(repo.pending_ops(100).await.unwrap().is_empty());

        // Appending the same op_id again as local: the primary key is idempotent, so
        // it does not become a pending push
        repo.append_local_op(&op).await.unwrap();
        assert!(repo.pending_ops(100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn existing_op_ids_and_item_ops_round_trip() {
        let repo = SyncRepository::new(db().await);
        let mut tombstone = put_op(2, 0);
        tombstone.op = OpType::Delete;
        tombstone.payload = None;
        let keep = put_op(1, 1);
        let ghost = Uuid::new_v4();
        repo.append_local_op(&keep).await.unwrap();
        repo.append_local_op(&tombstone).await.unwrap();

        let found = repo
            .existing_op_ids(&[keep.op_id, tombstone.op_id, ghost])
            .await
            .unwrap();
        assert_eq!(found.len(), 2);
        assert!(!found.contains(&ghost));

        let ops = repo.item_ops(tombstone.item_id).await.unwrap();
        assert_eq!(ops.len(), 1);
        assert!(ops[0].is_tombstone());
        assert_eq!(ops[0].payload, None);
    }

    #[tokio::test]
    async fn pending_op_ids_and_delete_ops_support_gc() {
        let repo = SyncRepository::new(db().await);
        let local = put_op(1, 1);
        let remote = put_op(2, 2);
        repo.append_local_op(&local).await.unwrap(); // pending
        repo.record_remote_op(&remote).await.unwrap(); // always acked

        // The protected set contains only un-acked rows of the push queue (remote
        // rows need no origin filtering)
        let pending = repo.pending_op_ids().await.unwrap();
        assert_eq!(pending, HashSet::from([local.op_id]));

        repo.mark_acked(&[local.op_id]).await.unwrap();
        assert!(repo.pending_op_ids().await.unwrap().is_empty());

        // Batch delete: an empty set does zero queries and returns 0 directly; the
        // count is accurate across chunks; the rows are truly gone
        assert_eq!(repo.delete_ops(&[]).await.unwrap(), 0);
        let mut many: Vec<Uuid> = Vec::new();
        for _ in 0..70 {
            let op = put_op(3, 3);
            repo.append_local_op(&op).await.unwrap();
            repo.mark_acked(&[op.op_id]).await.unwrap();
            many.push(op.op_id);
        }
        many.push(local.op_id);
        many.push(remote.op_id);
        let removed = repo.delete_ops(&many).await.unwrap();
        assert_eq!(removed as usize, many.len());
        for id in &many {
            assert!(!repo.has_op(*id).await.unwrap());
        }
    }
}
