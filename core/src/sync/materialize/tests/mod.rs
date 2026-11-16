use super::Materializer;
use crate::crypto::encryption::EncryptionService;
use crate::models::{CredentialData, Identity, IdentityType, PasswordCredentialData};
use crate::storage::{IdentityRepository, Repository};
use crate::sync::keys::{wrap_item_key_with_group, GroupKey};
use crate::sync::oplog::{ItemKind, OpType, SyncOp, SyncPayload};
use crate::sync::snapshot::{SyncItemSnapshot, SyncPasskeySnapshot};
use crate::Database;
use chrono::Utc;
use uuid::Uuid;

fn password_data(secret: &str) -> CredentialData {
    CredentialData::Password(PasswordCredentialData {
        password: secret.to_string(),
        email: Some("alice@example.com".to_string()),
        security_questions: vec![],
    })
}

fn put_op(
    item_id: Uuid,
    device_id: Uuid,
    lamport: u64,
    snapshot: &SyncItemSnapshot,
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
        timestamp: Some(Utc::now()),
        payload: Some(SyncPayload {
            ciphertext: snapshot.seal(&item_key).unwrap(),
            wrapped_item_key: wrap_item_key_with_group(&item_key, group),
        }),
    }
}

fn delete_op(item_id: Uuid, device_id: Uuid, lamport: u64) -> SyncOp {
    SyncOp {
        op_id: Uuid::new_v4(),
        item_id,
        kind: ItemKind::Credential,
        op: OpType::Delete,
        lamport,
        device_id,
        timestamp: Some(Utc::now()),
        payload: None,
    }
}

async fn setup() -> (Database, Materializer, IdentityRepository, GroupKey, Uuid) {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_repo = IdentityRepository::new(db.clone());
    let identity = Identity::new("Alice".to_string(), IdentityType::Personal);
    identity_repo.create(&identity).await.unwrap();
    (
        db.clone(),
        Materializer::new(db),
        identity_repo,
        GroupKey::generate().unwrap(),
        identity.id,
    )
}

fn passkey_put_op(
    item_id: Uuid,
    device_id: Uuid,
    lamport: u64,
    item_key: &[u8; 32],
    snapshot: &SyncPasskeySnapshot,
    group: &GroupKey,
) -> SyncOp {
    SyncOp {
        op_id: Uuid::new_v4(),
        item_id,
        kind: ItemKind::Passkey,
        op: OpType::Put,
        lamport,
        device_id,
        timestamp: Some(Utc::now()),
        payload: Some(SyncPayload {
            ciphertext: snapshot.seal(item_key).unwrap(),
            wrapped_item_key: wrap_item_key_with_group(item_key, group),
        }),
    }
}

fn passkey_snapshot(identity_id: Uuid, rp_id: &str, private_key: &[u8]) -> SyncPasskeySnapshot {
    SyncPasskeySnapshot {
        identity_id,
        rp_id: rp_id.to_string(),
        rp_name: Some("Example".to_string()),
        user_handle: b"remote-handle".to_vec(),
        user_name: Some("bob@example.com".to_string()),
        user_display_name: None,
        credential_id: b"credential-id-32-bytes-remote-xxxx".to_vec(),
        encrypted_private_key: private_key.to_vec(),
        public_key_cose: b"cose".to_vec(),
        alg: -7,
        uv_initialized: true,
        export_allowed: false,
        tags: vec!["remote".to_string()],
    }
}

mod materializer;
mod passkey;
