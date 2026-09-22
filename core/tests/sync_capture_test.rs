//! service 写路径 → [`SyncCapture`] 捕获缝的集成测试（E2EE_SYNC_DESIGN §5）。
//!
//! 核心不变量：捕获到的密文与主库 `encrypted_data` **逐字节相同**，捕获到的
//! item key 能解开这份密文——本地库与同步 oplog 共享同一份
//! (ciphertext, item key)，装配层再用 group key 包裹（服务端两级都不可读）。
//!
//! 容错语义：未装配时写路径照常工作（零开销跳过）；捕获缝可随时拆卸。
//! service 不知道 db 路径之外的一切装配细节，group key 不进 service——
//! 这些断言在 keys.rs / 装配层测试里，此处只验证捕获契约本身。

use std::sync::{Arc, Mutex};

use persona_core::crypto::EncryptionService;
use persona_core::sync::capture::SyncCapture;
use persona_core::sync::keys::{wrap_item_key_with_group, GroupKey};
use persona_core::sync::oplog::{ItemKind, OpType};
use persona_core::sync::snapshot::SyncItemSnapshot;
use persona_core::*;
use uuid::Uuid;
use zeroize::Zeroizing;

/// 一次捕获的记录（item key 落盘前 `Zeroizing` 清零）。
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

    // 不变量 1：同步载荷 = 完整条目快照的密封（元数据 + CredentialData），
    // 捕获的 item key 能拆开它。
    let row = service.get_credential(&created.id).await.unwrap().unwrap();
    let ciphertext = ev.ciphertext.as_ref().expect("put 必带密文");
    assert!(row.wrapped_item_key.is_some());
    let item_key = ev.item_key.expect("put 必带 item key");
    let snapshot = SyncItemSnapshot::open(ciphertext, &item_key).unwrap();
    assert_eq!(snapshot.name, "Email");
    assert_eq!(snapshot.identity_id, identity.id);
    assert_eq!(snapshot.data.to_bytes().unwrap(), data.to_bytes().unwrap());

    // 不变量 2：同一把 item key 也封着主库密文——两份密文、一把钥匙。
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

    // 装配层流程演练：group key 包裹后可还原同一 item key（服务器两级不可读）。
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

    // item key 复用不变量：编辑不换 key（附件以同一 key 封存）。
    assert_eq!(second.item_key, first.item_key);
    // 密文变了；快照解出的是编辑后的数据。
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
    // 同一把 key 也解得开主库新密文。
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

    // 删除不存在的凭据返回 false，不产生捕获。
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

    // 元数据编辑（不走 update_credential_data）：改名 + 打收藏。
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
    // 秘密数据不因元数据编辑而变。
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
