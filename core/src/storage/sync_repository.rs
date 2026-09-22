//! 本地 oplog 与同步状态存储（E2EE_SYNC_DESIGN §5；迁移 014）。
//!
//! 职责边界：本 repo 只做 append-only 落库与状态读写；LWW 裁决在
//! [`crate::sync::oplog`]（纯函数），同步编排（push/pull/travel 闸）在
//! 阶段 2 批 4 的 engine。`origin='remote'` 的行永不进入 push 队列；
//! op_id 主键 + `INSERT OR IGNORE` 提供存储层幂等（重放安全）。

use chrono::{DateTime, Utc};
use sqlx::Row;
use std::collections::HashSet;
use uuid::Uuid;

use crate::storage::Database;
use crate::sync::oplog::{OpType, SyncOp, SyncPayload};
use crate::{PersonaError, Result};

/// 本设备同步状态（sync_state 单行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    /// 本机 Lamport 时钟：本地写 = 此值 + 1；pull 后 = max(此值, 远端最大值)。
    pub local_lamport: u64,
    /// 本设备在同步组中的身份（注册后填）。
    pub device_id: Option<Uuid>,
    /// pull 游标（服务器 seq），None = 从头。
    pub last_pull_cursor: Option<String>,
}

pub struct SyncRepository {
    db: Database,
}

impl SyncRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ---- sync_state ----

    /// 读本设备同步状态；行不存在时返回全默认（lamport 0 / 未注册 / 无游标）。
    pub async fn get_state(&self) -> Result<SyncState> {
        let row = sqlx::query(
            "SELECT local_lamport, device_id, last_pull_cursor FROM sync_state WHERE id = 1",
        )
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        let Some(row) = row else {
            return Ok(SyncState {
                local_lamport: 0,
                device_id: None,
                last_pull_cursor: None,
            });
        };
        let device_id: Option<String> = row.get("device_id");
        Ok(SyncState {
            local_lamport: row.get::<i64, _>("local_lamport") as u64,
            device_id: device_id.and_then(|s| Uuid::parse_str(&s).ok()),
            last_pull_cursor: row.get("last_pull_cursor"),
        })
    }

    /// 只进不退地推进 Lamport 时钟（`MAX` 语义，防回退）。
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

    // ---- oplog ----

    /// 追加一条本地产生的 op（push 队列）。op_id 已存在则静默忽略（幂等）。
    pub async fn append_local_op(&self, op: &SyncOp) -> Result<()> {
        self.insert_op(op, "local", "pending").await
    }

    /// 记录一条 pull 来的远端 op（幂等去重的持久依据，永不入 push 队列）。
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

    /// 已持久化的 op_id 集合（批量去重：pull 应用前过滤重放）。
    pub async fn existing_op_ids(&self, ids: &[Uuid]) -> Result<HashSet<Uuid>> {
        let mut seen = HashSet::new();
        for id in ids {
            if self.has_op(*id).await? {
                seen.insert(*id);
            }
        }
        Ok(seen)
    }

    /// push 队列：本地未确认的 op，按 (lamport, device_id, op_id) 升序推平。
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

    /// push 成功后批量确认。
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

    /// 某 item 的全部 op（供 [`crate::sync::oplog::item_view`] 推导主位/副本）。
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

    /// oplog 中出现过写入的全部 item（去重，供物化层逐 item 推导视图）。
    /// 数量级 = 本工作区被同步过的条目总数，单查询足够。
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
        repo.bump_lamport(3).await.unwrap(); // 回退尝试：MAX 语义挡住
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
        // append 顺序故意乱
        ops.swap(0, 2);

        for op in &ops {
            repo.append_local_op(op).await.unwrap();
            repo.append_local_op(op).await.unwrap(); // 同 op_id 重复 append：忽略
        }

        let pending = repo.pending_ops(100).await.unwrap();
        assert_eq!(pending.len(), 3);
        // 队列按 (lamport, ...) 升序
        let lamports: Vec<u64> = pending.iter().map(|o| o.lamport).collect();
        let mut sorted = lamports.clone();
        sorted.sort();
        assert_eq!(lamports, sorted);

        // 密文载荷 round-trip（tag = lamport-1，见 put_op）
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

        // 同 op_id 再以 local 身份 append：主键幂等，不会变成待推送
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
}
