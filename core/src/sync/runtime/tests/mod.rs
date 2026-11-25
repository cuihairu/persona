//! runtime split (LAY-021) test hub: fixtures/helpers shared across domains,
//! plus per-domain grouping.
//! Each group cascades through `use super::*` (hub imports and helpers are
//! visible to descendants); domain-private helpers live with their group
//! (the SharedRemote family in session, retention_days and
//! pending_after_resolve in gc, assert_variant in conflicts).

use super::*;
use crate::models::credential::{
    Credential, CredentialType, PasswordCredentialData, SecurityLevel,
};
use crate::models::identity::{Identity, IdentityType};
use crate::storage::repository::IdentityRepository;
use crate::storage::Repository;
use crate::sync::capture::SyncCapture as _;
use crate::sync::oplog::SyncOp;
use std::sync::Mutex;
use zeroize::Zeroizing;

mod conflicts;
mod gc;
mod rotate;
mod session;

/// In-memory remote: push collects ops (the Arc is shared with test
/// assertions), pull returns an empty page.
struct MemRemote {
    pushed: Arc<Mutex<Vec<SyncOp>>>,
}

#[async_trait::async_trait]
impl SyncRemote for MemRemote {
    async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
        let n = ops.len() as u64;
        self.pushed.lock().unwrap().extend(ops.iter().cloned());
        Ok((n, 0))
    }

    async fn pull_ops(
        &self,
        _since: Option<&str>,
        _limit: u32,
    ) -> Result<(Vec<SyncOp>, Option<String>)> {
        Ok((Vec::new(), None))
    }

    async fn head_seq(&self) -> Result<i64> {
        Ok(self.pushed.lock().unwrap().len() as i64)
    }

    async fn put_library_snapshot(
        &self,
        _seq: i64,
        _device_id: &str,
        _ciphertext: &[u8],
    ) -> Result<u64> {
        Ok(0)
    }

    async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
        Ok(None)
    }
}

fn no_travel() -> Box<dyn Fn() -> bool + Send + Sync> {
    Box::new(|| false)
}

async fn seeded_db() -> (Database, Identity, EncryptionService) {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_repo = IdentityRepository::new(db.clone());
    let identity = Identity::new("seed".to_string(), IdentityType::Personal);
    identity_repo.create(&identity).await.unwrap();
    let master = EncryptionService::new(&EncryptionService::generate_key());
    (db, identity, master)
}

fn data(secret: &str) -> CredentialData {
    CredentialData::Password(PasswordCredentialData {
        password: secret.to_string(),
        email: None,
        security_questions: vec![],
    })
}

async fn store_credential(
    cred_repo: &CredentialRepository,
    identity_id: Uuid,
    name: &str,
    master: &EncryptionService,
    secret: &str,
) {
    let item_key = EncryptionService::generate_key();
    let wrapped = master.encrypt(&item_key).unwrap();
    let ciphertext = KeyHierarchy::new(master)
        .encrypt_with_item_key(&item_key, &data(secret).to_bytes().unwrap())
        .unwrap();
    let cred = Credential::new(
        identity_id,
        name.to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        ciphertext,
        Some(wrapped),
    );
    cred_repo.create(&cred).await.unwrap();
}

fn session_for(
    db: &Database,
    device_id: Uuid,
    group_key: GroupKey,
) -> (SyncSession<MemRemote>, Arc<Mutex<Vec<SyncOp>>>) {
    let remote = MemRemote {
        pushed: Arc::new(Mutex::new(Vec::new())),
    };
    let pushed_log = remote.pushed.clone();
    let engine = Arc::new(SyncEngine::new(
        SyncRepository::new(db.clone()),
        remote,
        device_id,
        no_travel(),
    ));
    let session = SyncSession {
        engine,
        sync_repo: SyncRepository::new(db.clone()),
        db: db.clone(),
        group_key,
        device_id,
    };
    (session, pushed_log)
}

// ---- Conflict resolution (phase 3c) ----

use chrono::Utc as TestUtc;

fn snapshot(name: &str, identity_id: Uuid) -> SyncItemSnapshot {
    SyncItemSnapshot {
        identity_id,
        name: name.to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::Medium,
        url: None,
        username: None,
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: data(name),
    }
}

fn conflict_put_op(
    item_id: Uuid,
    device_id: Uuid,
    lamport: u64,
    snap: &SyncItemSnapshot,
    group: &GroupKey,
) -> SyncOp {
    let item_key = EncryptionService::generate_key();
    SyncOp {
        op_id: Uuid::new_v4(),
        item_id,
        kind: ItemKind::Credential,
        op: OpType::Put,
        lamport,
        device_id,
        timestamp: Some(TestUtc::now()),
        payload: Some(SyncPayload {
            ciphertext: snap.seal(&item_key).unwrap(),
            wrapped_item_key: wrap_item_key_with_group(&item_key, group),
        }),
    }
}

fn conflict_delete_op(item_id: Uuid, device_id: Uuid, lamport: u64) -> SyncOp {
    SyncOp {
        op_id: Uuid::new_v4(),
        item_id,
        kind: ItemKind::Credential,
        op: OpType::Delete,
        lamport,
        device_id,
        timestamp: Some(TestUtc::now()),
        payload: None,
    }
}

/// Build a genuine conflict pair (same item, same lamport, different
/// devices) and return them in total order as (primary op, copy op).
fn seeded_conflict(item_id: Uuid, group: &GroupKey, identity_id: Uuid) -> (SyncOp, SyncOp) {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let (winner, loser) = if a > b { (a, b) } else { (b, a) };
    let primary = conflict_put_op(
        item_id,
        winner,
        5,
        &snapshot("primary-name", identity_id),
        group,
    );
    let copy = conflict_put_op(
        item_id,
        loser,
        5,
        &snapshot("copy-name", identity_id),
        group,
    );
    (primary, copy)
}
