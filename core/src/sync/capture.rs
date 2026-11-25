//! The capture seam from the service write path to the sync oplog
//! (E2EE_SYNC_DESIGN §5 "capture point").
//!
//! `PersonaService` hands entry-level changes to [`SyncCapture`] at the same
//! call sites as change_history: **it delivers only the entry ciphertext and
//! the item key plaintext**, never holding the group key——the group wrapping
//! ([`super::keys::wrap_item_key_with_group`]) and
//! `SyncEngine::record_local_change` are both done in the assembly-layer
//! implementation, preserving the key layering (the group key belongs only to
//! the sync assembly layer; the service's unlocked session never has it).
//!
//! Fault tolerance matches `record_credential_history`: a capture failure or
//! missing assembly must not block the main operation. Trait methods return
//! `()` (the implementation logs on its own), and the service side does no
//! fallible preparation before calling——sync in this product is a best-effort
//! bypass; the main DB is the single source of truth (the STORAGE_AND_SYNC
//! principle).

use std::sync::Arc;

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::sync::engine::{SyncEngine, SyncRemote};
use crate::sync::keys::{wrap_item_key_with_group, GroupKey};
use crate::sync::oplog::{ItemKind, OpType, SyncPayload};

/// Entry-level change capture (implemented in the assembly layer; zero-cost
/// skip on the service side when unassembled).
#[async_trait::async_trait]
pub trait SyncCapture: Send + Sync {
    /// `put`: carries the sync snapshot ciphertext (sealed by
    /// [`super::snapshot::SyncItemSnapshot`], a metadata + CredentialData
    /// composite) and the item key plaintext (the implementation drops it
    /// right after wrapping the group envelope——`Zeroizing` guarantees this);
    /// `delete`: both are `None` (tombstone, the payload is always empty).
    async fn capture(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        ciphertext: Option<Vec<u8>>,
        item_key: Option<Zeroizing<[u8; 32]>>,
    );
}

/// Default assembly implementation: group wrapping + oplog bookkeeping.
///
/// The item key handed over by the service is wrapped here with the group
/// key into `SyncPayload.wrapped_item_key` and passed together with the
/// snapshot ciphertext to [`SyncEngine::record_local_change`]; after that
/// `item_key` (`Zeroizing`) is zeroed as soon as it leaves scope. Failures
/// are only logged, never propagated (trait contract: capture is a best-effort
/// bypass).
pub struct OplogCapture<R: SyncRemote> {
    engine: Arc<SyncEngine<R>>,
    group_key: GroupKey,
}

impl<R: SyncRemote> OplogCapture<R> {
    pub fn new(engine: Arc<SyncEngine<R>>, group_key: GroupKey) -> Self {
        Self { engine, group_key }
    }
}

#[async_trait::async_trait]
impl<R: SyncRemote> SyncCapture for OplogCapture<R> {
    async fn capture(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        ciphertext: Option<Vec<u8>>,
        item_key: Option<Zeroizing<[u8; 32]>>,
    ) {
        let payload = match (op, ciphertext, item_key) {
            (OpType::Put, Some(ciphertext), Some(item_key)) => Some(SyncPayload {
                ciphertext,
                wrapped_item_key: wrap_item_key_with_group(&item_key, &self.group_key),
            }),
            (OpType::Delete, None, None) => None,
            _ => {
                tracing::warn!(item_id = %item_id, op = ?op, "sync capture payload mismatch; dropped");
                return;
            }
        };
        if let Err(e) = self
            .engine
            .record_local_change(item_id, kind, op, payload)
            .await
        {
            tracing::warn!(item_id = %item_id, error = %e, "sync capture failed (best-effort bypass)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encryption::EncryptionService;
    use crate::models::{CredentialData, PasswordCredentialData};
    use crate::storage::sync_repository::SyncRepository;
    use crate::sync::engine::SyncRemote;
    use crate::sync::keys::unwrap_item_key_with_group;
    use crate::sync::oplog::SyncOp;
    use crate::sync::snapshot::SyncItemSnapshot;
    use crate::{Database, PersonaError, Result};

    struct DeadRemote;
    #[async_trait::async_trait]
    impl SyncRemote for DeadRemote {
        async fn push_ops(&self, _ops: &[SyncOp]) -> Result<(u64, u64)> {
            Err(PersonaError::InvalidInput("dead remote".into()).into())
        }
        async fn pull_ops(
            &self,
            _since: Option<&str>,
            _limit: u32,
        ) -> Result<(Vec<SyncOp>, Option<String>)> {
            Ok((vec![], None))
        }
        async fn head_seq(&self) -> Result<i64> {
            Ok(0)
        }
        async fn put_library_snapshot(
            &self,
            _seq: i64,
            _device_id: &str,
            _ciphertext: &[u8],
        ) -> Result<u64> {
            Err(PersonaError::InvalidInput("dead remote".into()).into())
        }
        async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
            Ok(None)
        }
    }

    fn sample_snapshot() -> SyncItemSnapshot {
        SyncItemSnapshot {
            identity_id: Uuid::new_v4(),
            name: "端到端".to_string(),
            credential_type: crate::models::CredentialType::Password,
            security_level: crate::models::SecurityLevel::High,
            url: None,
            username: Some("e2e@example.com".to_string()),
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: CredentialData::Password(PasswordCredentialData {
                password: "pw".to_string(),
                email: None,
                security_questions: vec![],
            }),
        }
    }

    #[tokio::test]
    async fn oplog_capture_wraps_group_and_records_into_oplog() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let engine = Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            DeadRemote,
            Uuid::new_v4(),
            Box::new(|| false),
        ));
        let group = GroupKey::generate().unwrap();
        let capture = OplogCapture::new(engine.clone(), group.clone());

        let item_id = Uuid::new_v4();
        let snapshot = sample_snapshot();
        let item_key = EncryptionService::generate_key();
        capture
            .capture(
                item_id,
                ItemKind::Credential,
                OpType::Put,
                Some(snapshot.seal(&item_key).unwrap()),
                Some(Zeroizing::new(item_key)),
            )
            .await;

        // Exactly one local op in the oplog, with both ciphertext layers present in the payload
        let ops = SyncRepository::new(db).item_ops(item_id).await.unwrap();
        assert_eq!(ops.len(), 1);
        let payload = ops[0].payload.as_ref().unwrap();

        // The group key recovers the item key, which in turn opens the snapshot——the full assembly chain
        let recovered_key = unwrap_item_key_with_group(&payload.wrapped_item_key, &group).unwrap();
        let opened = SyncItemSnapshot::open(&payload.ciphertext, &recovered_key).unwrap();
        assert_eq!(opened.name, "端到端");
        assert_eq!(opened.username.as_deref(), Some("e2e@example.com"));

        // lamport starts at 1; device_id is taken from the engine
        assert_eq!(ops[0].lamport, 1);
    }

    #[tokio::test]
    async fn oplog_capture_records_tombstone_without_payload() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let engine = Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            DeadRemote,
            Uuid::new_v4(),
            Box::new(|| false),
        ));
        let capture = OplogCapture::new(engine.clone(), GroupKey::generate().unwrap());

        let item_id = Uuid::new_v4();
        capture
            .capture(item_id, ItemKind::Credential, OpType::Delete, None, None)
            .await;
        capture
            .capture(item_id, ItemKind::Credential, OpType::Put, None, None) // put missing payload: not booked
            .await;

        let ops = SyncRepository::new(db).item_ops(item_id).await.unwrap();
        assert_eq!(ops.len(), 1, "put 缺 payload 的畸形的调用被丢弃");
        assert_eq!(ops[0].op, OpType::Delete);
        assert!(ops[0].payload.is_none());
    }

    /// S2 zero-knowledge check: after the capture is stored, the oplog raw
    /// bytes contain no plaintext of entry name / domain / username / password,
    /// and no raw bytes of the item key / group key either. Local stored bytes
    /// = what the server holds (the server is only a forwarding store), so
    /// this assertion pins "relay zero-knowledge" into a test instead of
    /// leaving it only in the docs.
    #[tokio::test]
    async fn oplog_bytes_never_contain_entry_plaintext_or_keys() {
        use sqlx::Row;

        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let engine = Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            DeadRemote,
            Uuid::new_v4(),
            Box::new(|| false),
        ));
        let group = GroupKey::generate().unwrap();
        let capture = OplogCapture::new(engine.clone(), group.clone());

        let item_key = EncryptionService::generate_key();
        let snapshot = SyncItemSnapshot {
            name: "机密条目Alpha".to_string(),
            url: Some("https://secret-site.example/login".to_string()),
            username: Some("alice@example.com".to_string()),
            notes: Some("备注里有域名 wordle.example.org".to_string()),
            data: CredentialData::Password(PasswordCredentialData {
                password: "特征口令-s3cret-π".to_string(),
                email: None,
                security_questions: vec![],
            }),
            ..sample_snapshot()
        };
        capture
            .capture(
                Uuid::new_v4(),
                ItemKind::Credential,
                OpType::Put,
                Some(snapshot.seal(&item_key).unwrap()),
                Some(Zeroizing::new(item_key)),
            )
            .await;

        // Aggregate all stored bytes of sync_oplog (two ciphertext layers +
        // wrapped key + text columns)
        let rows =
            sqlx::query("SELECT ciphertext, wrapped_item_key, item_id, device_id FROM sync_oplog")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert_eq!(rows.len(), 1);
        let mut stored: Vec<u8> = Vec::new();
        for row in &rows {
            stored.extend(
                row.get::<Option<Vec<u8>>, _>("ciphertext")
                    .unwrap_or_default(),
            );
            stored.extend(
                row.get::<Option<Vec<u8>>, _>("wrapped_item_key")
                    .unwrap_or_default(),
            );
            stored.extend(row.get::<String, _>("item_id").as_bytes());
            stored.extend(row.get::<String, _>("device_id").as_bytes());
        }

        // Plaintext markers: entry name / domain / username / notes domain /
        // password must all be unfindable
        for plaintext in [
            "机密条目Alpha".as_bytes(),
            b"secret-site.example",
            b"alice@example.com",
            b"wordle.example.org",
            "特征口令-s3cret-π".as_bytes(),
        ] {
            assert!(
                !stored.windows(plaintext.len()).any(|w| w == plaintext),
                "oplog 落库字节泄露明文: {}",
                String::from_utf8_lossy(plaintext)
            );
        }
        // Raw key bytes must not appear either (the wrapping must be real)
        assert!(
            !stored.windows(32).any(|w| w == item_key.as_slice()),
            "item key 原始字节泄露"
        );
        assert!(
            !stored.windows(32).any(|w| w == group.as_bytes().as_slice()),
            "group key 原始字节泄露"
        );

        // Reverse control: the group key recovers the item key and the item
        // key recovers the snapshot plaintext——the stored bytes really are
        // encrypted at both layers (rather than the marker fields having been
        // dropped)
        let payload_row = sqlx::query("SELECT ciphertext, wrapped_item_key FROM sync_oplog")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let recovered =
            unwrap_item_key_with_group(&payload_row.get::<Vec<u8>, _>("wrapped_item_key"), &group)
                .unwrap();
        let opened =
            SyncItemSnapshot::open(&payload_row.get::<Vec<u8>, _>("ciphertext"), &recovered)
                .unwrap();
        assert_eq!(opened.name, "机密条目Alpha");
        assert_eq!(opened.username.as_deref(), Some("alice@example.com"));
    }
}
