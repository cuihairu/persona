//! Integration tests for the service write path → [`SyncCapture`] capture seam
//! (E2EE_SYNC_DESIGN §5).
//!
//! Core invariant: the captured ciphertext is **byte-for-byte identical** to the
//! main vault's `encrypted_data`, and the captured item key can open that
//! ciphertext — the local vault and the sync oplog share the same
//! (ciphertext, item key), with the assembly layer wrapping it again under the
//! group key (unreadable at both server levels).
//!
//! Failure-tolerance semantics: without the seam installed, the write path works
//! as usual (a zero-cost skip); the capture seam can be detached at any time.
//! The service knows nothing about the assembly beyond the db path, and the
//! group key never reaches the service — those assertions live in keys.rs /
//! the assembly-layer tests; this file only verifies the capture contract itself.

use std::sync::{Arc, Mutex};

use persona_core::crypto::EncryptionService;
use persona_core::sync::capture::SyncCapture;
use persona_core::sync::keys::{wrap_item_key_with_group, GroupKey};
use persona_core::sync::oplog::{ItemKind, OpType};
use persona_core::sync::snapshot::{SyncItemSnapshot, SyncPasskeySnapshot};
use persona_core::*;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Record of one capture (the item key is zeroed with `Zeroizing` before hitting disk).
#[derive(Debug, Clone)]
struct Captured {
    item_id: Uuid,
    kind: ItemKind,
    op: OpType,
    ciphertext: Option<Vec<u8>>,
    item_key: Option<[u8; 32]>,
}

#[derive(Default, Clone)]
struct RecordingCapture {
    events: Arc<Mutex<Vec<Captured>>>,
}

impl RecordingCapture {
    fn snapshot(&self) -> Vec<Captured> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl SyncCapture for RecordingCapture {
    async fn capture(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        ciphertext: Option<Vec<u8>>,
        item_key: Option<Zeroizing<[u8; 32]>>,
    ) {
        self.events.lock().unwrap().push(Captured {
            item_id,
            kind,
            op,
            ciphertext,
            item_key: item_key.map(|k| *k),
        });
    }
}

async fn unlocked_service() -> PersonaService {
    let db = Database::in_memory().await.expect("db");
    db.migrate().await.expect("migrate");
    let mut service = PersonaService::new(db).await.expect("service");
    let salt = service.generate_salt();
    service
        .unlock("correct horse battery", &salt)
        .expect("unlock");
    service
}

fn password_data(secret: &str) -> CredentialData {
    CredentialData::Password(PasswordCredentialData {
        password: secret.to_string(),
        email: Some("user@example.com".to_string()),
        security_questions: vec![],
    })
}

#[tokio::test]
async fn create_credential_captures_put_snapshot_with_shared_item_key() {
    let service = unlocked_service().await;
    let capture = RecordingCapture::default();
    service
        .attach_sync_capture(Some(Arc::new(capture.clone())))
        .await;

    let identity = service
        .create_identity("Alice".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let data = password_data("s3cret-π");
    let created = service
        .create_credential(
            identity.id,
            "Email".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            &data,
        )
        .await
        .unwrap();

    let events = capture.snapshot();
    assert_eq!(events.len(), 1, "create 恰好产生一次捕获");
    let ev = &events[0];
    assert_eq!(ev.item_id, created.id);
    assert_eq!(ev.kind, ItemKind::Credential);
    assert_eq!(ev.op, OpType::Put);

    // Invariant 1: the sync payload = a sealing of the full item snapshot
    // (metadata + CredentialData), openable by the captured item key.
    let row = service.get_credential(&created.id).await.unwrap().unwrap();
    let ciphertext = ev.ciphertext.as_ref().expect("put 必带密文");
    assert!(row.wrapped_item_key.is_some());
    let item_key = ev.item_key.expect("put 必带 item key");
    let snapshot = SyncItemSnapshot::open(ciphertext, &item_key).unwrap();
    assert_eq!(snapshot.name, "Email");
    assert_eq!(snapshot.identity_id, identity.id);
    assert_eq!(snapshot.data.to_bytes().unwrap(), data.to_bytes().unwrap());

    // Invariant 2: the same item key also seals the main vault's ciphertext — two ciphertexts, one key.
    assert_ne!(
        ciphertext, &row.encrypted_data,
        "主库密文与同步密文是两次密封"
    );
    let plaintext = EncryptionService::new(&item_key)
        .decrypt(&row.encrypted_data)
        .expect("捕获的 item key 必须能解主库密文");
    assert_eq!(
        CredentialData::from_bytes(&plaintext)
            .unwrap()
            .to_bytes()
            .unwrap(),
        data.to_bytes().unwrap()
    );

    // Assembly-layer flow rehearsal: after group-key wrapping the same item key can be recovered (unreadable at both server levels).
    let group = GroupKey::generate().unwrap();
    let wrapped = wrap_item_key_with_group(&item_key, &group);
    assert_eq!(
        persona_core::sync::keys::unwrap_item_key_with_group(&wrapped, &group).unwrap(),
        item_key
    );
}

#[tokio::test]
async fn update_credential_data_captures_put_reusing_the_item_key() {
    let service = unlocked_service().await;
    let capture = RecordingCapture::default();
    service
        .attach_sync_capture(Some(Arc::new(capture.clone())))
        .await;

    let identity = service
        .create_identity("Bob".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let created = service
        .create_credential(
            identity.id,
            "Bank".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            &password_data("old-pass"),
        )
        .await
        .unwrap();

    let updated = service
        .update_credential_data(&created.id, &password_data("new-pass"))
        .await
        .unwrap();

    let events = capture.snapshot();
    assert_eq!(events.len(), 2, "create + update 各一次捕获");
    let (first, second) = (&events[0], &events[1]);
    assert_eq!(second.item_id, created.id);
    assert_eq!(second.op, OpType::Put);

    // Item key reuse invariant: editing does not rotate the key (attachments are sealed under the same key).
    assert_eq!(second.item_key, first.item_key);
    // The ciphertext changed; the snapshot decrypts to the edited data.
    assert_ne!(second.ciphertext, first.ciphertext);
    let snapshot = SyncItemSnapshot::open(
        second.ciphertext.as_ref().unwrap(),
        &second.item_key.unwrap(),
    )
    .unwrap();
    assert_eq!(
        snapshot.data.to_bytes().unwrap(),
        password_data("new-pass").to_bytes().unwrap()
    );
    // The same key also opens the main vault's new ciphertext.
    let plaintext = EncryptionService::new(&second.item_key.unwrap())
        .decrypt(&updated.encrypted_data)
        .unwrap();
    assert_eq!(
        CredentialData::from_bytes(&plaintext)
            .unwrap()
            .to_bytes()
            .unwrap(),
        password_data("new-pass").to_bytes().unwrap()
    );
}

#[tokio::test]
async fn delete_credential_captures_tombstone_without_payload() {
    let service = unlocked_service().await;
    let capture = RecordingCapture::default();
    service
        .attach_sync_capture(Some(Arc::new(capture.clone())))
        .await;

    let identity = service
        .create_identity("Carol".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let created = service
        .create_credential(
            identity.id,
            "VPN".to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            &password_data("vpn-pass"),
        )
        .await
        .unwrap();

    let deleted = service.delete_credential(&created.id).await.unwrap();
    assert!(deleted);

    let events = capture.snapshot();
    assert_eq!(events.len(), 2);
    let ev = &events[1];
    assert_eq!(ev.item_id, created.id);
    assert_eq!(ev.op, OpType::Delete);
    assert!(ev.ciphertext.is_none(), "tombstone 不携带密文");
    assert!(ev.item_key.is_none(), "tombstone 不携带 item key");

    // Deleting a nonexistent credential returns false and produces no capture.
    let missing = service.delete_credential(&Uuid::new_v4()).await.unwrap();
    assert!(!missing);
    assert_eq!(capture.snapshot().len(), 2, "no-op delete 不捕获");
}

#[tokio::test]
async fn without_capture_attached_writes_succeed_normally() {
    let service = unlocked_service().await;

    let identity = service
        .create_identity("Dave".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let created = service
        .create_credential(
            identity.id,
            "SSH".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            &password_data("host-key"),
        )
        .await
        .unwrap();
    let updated = service
        .update_credential_data(&created.id, &password_data("host-key-2"))
        .await
        .unwrap();
    assert_eq!(
        updated.encrypted_data.len(),
        created.encrypted_data.len() + 2
    );
    assert!(service.delete_credential(&created.id).await.unwrap());

    let row = service.get_credential(&created.id).await.unwrap();
    assert!(row.is_none(), "未装配捕获缝时写路径行为不变");
}

#[tokio::test]
async fn metadata_edit_captures_put_with_updated_snapshot() {
    let service = unlocked_service().await;
    let capture = RecordingCapture::default();
    service
        .attach_sync_capture(Some(Arc::new(capture.clone())))
        .await;

    let identity = service
        .create_identity("Frank".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let created = service
        .create_credential(
            identity.id,
            "Git".to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            &password_data("token-1"),
        )
        .await
        .unwrap();

    // Metadata edit (not via update_credential_data): rename + favorite.
    let mut row = service.get_credential(&created.id).await.unwrap().unwrap();
    row.name = "Git 重命名".to_string();
    row.is_favorite = true;
    service.update_credential(&row).await.unwrap();

    let events = capture.snapshot();
    assert_eq!(events.len(), 2, "create + 元数据编辑各一次捕获");
    let ev = &events[1];
    assert_eq!(ev.item_id, created.id);
    let snapshot =
        SyncItemSnapshot::open(ev.ciphertext.as_ref().unwrap(), &ev.item_key.unwrap()).unwrap();
    assert_eq!(snapshot.name, "Git 重命名");
    assert!(snapshot.is_favorite);
    // The secret data is unchanged by the metadata edit.
    assert_eq!(
        snapshot.data.to_bytes().unwrap(),
        password_data("token-1").to_bytes().unwrap()
    );
}

#[tokio::test]
async fn detaching_capture_stops_recording() {
    let service = unlocked_service().await;
    let capture = RecordingCapture::default();
    service
        .attach_sync_capture(Some(Arc::new(capture.clone())))
        .await;

    let identity = service
        .create_identity("Eve".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let created = service
        .create_credential(
            identity.id,
            "Git".to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            &password_data("token-1"),
        )
        .await
        .unwrap();
    assert_eq!(capture.snapshot().len(), 1);

    service.attach_sync_capture(None).await;
    service
        .update_credential_data(&created.id, &password_data("token-2"))
        .await
        .unwrap();
    assert_eq!(capture.snapshot().len(), 1, "拆卸后不再捕获");
}

#[tokio::test]
async fn create_passkey_captures_put_snapshot_and_delete_captures_tombstone() {
    let service = unlocked_service().await;
    let capture = RecordingCapture::default();
    service
        .attach_sync_capture(Some(Arc::new(capture.clone())))
        .await;

    let identity = service
        .create_identity("Alice".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let client_data =
        br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#;
    let created = service
        .create_passkey(
            identity.id,
            "example.com".to_string(),
            "https://example.com",
            client_data,
            None,
            Some("alice@example.com".to_string()),
            None,
            false,
        )
        .await
        .unwrap();

    let events = capture.snapshot();
    assert_eq!(events.len(), 1, "passkey create 恰好产生一次捕获");
    let ev = &events[0];
    assert_eq!(ev.item_id, created.id);
    assert_eq!(ev.kind, ItemKind::Passkey);
    assert_eq!(ev.op, OpType::Put);

    // The snapshot can be opened by the captured item key, with semantic fields matching the main vault row (usage state excluded)
    let snapshot = SyncPasskeySnapshot::open(
        ev.ciphertext.as_ref().unwrap(),
        ev.item_key.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(snapshot.identity_id, identity.id);
    assert_eq!(snapshot.rp_id, "example.com");
    assert_eq!(snapshot.user_name.as_deref(), Some("alice@example.com"));

    // The private-key envelope is carried verbatim (snapshot and main vault row share the same ciphertext), and the captured item key can open it
    let row = service
        .list_passkeys(&identity.id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(snapshot.encrypted_private_key, row.encrypted_private_key);
    let scalar = EncryptionService::new(ev.item_key.as_ref().unwrap())
        .decrypt(&row.encrypted_private_key)
        .unwrap();
    assert_eq!(scalar.len(), 32, "解出的是 P-256 私钥标量");

    // Delete → tombstone (no payload)
    assert!(service.delete_passkey(&created.id).await.unwrap());
    let events = capture.snapshot();
    assert_eq!(events.len(), 2, "delete 恰好追加一次捕获");
    let ev = &events[1];
    assert_eq!(ev.item_id, created.id);
    assert_eq!(ev.kind, ItemKind::Passkey);
    assert_eq!(ev.op, OpType::Delete);
    assert!(ev.ciphertext.is_none());
    assert!(ev.item_key.is_none());
}
