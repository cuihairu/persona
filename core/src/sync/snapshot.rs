//! Sync item snapshots (E2EE_SYNC_DESIGN §5) — the plaintext format of oplog
//! payload ciphertext.
//!
//! A credential row in the primary database = plaintext metadata columns +
//! `encrypted_data` (holding only [`CredentialData`]). A remote device needs
//! more than `CredentialData` to materialize the same row — so the sync
//! payload ciphertext carries a **full item snapshot**: metadata and
//! `CredentialData` serialized together and encrypted once with the item key.
//! The primary-database ciphertext and the sync ciphertext are therefore two
//! different byte strings (under the same item key); "the oplog holds only
//! ciphertext" stays unchanged, and the server cannot read either level.
//!
//! Format: `bincode(SyncItemSnapshot)` → `EncryptionService` (random nonce
//! prefixed, 12B ‖ AES-256-GCM). Same encoding pipeline as
//! [`CredentialData`]; field evolution relies on bincode's default strictness
//! — unrecognized byte streams error out (fail-closed), and future fields
//! bump the version first before being made compatible.

use std::collections::HashMap;

use uuid::Uuid;

use crate::crypto::encryption::EncryptionService;
use crate::models::{Credential, CredentialData, CredentialType, SecurityLevel};
use crate::sync::oplog::SyncOp;
use crate::{PersonaError, Result};

/// Sync snapshot of a credential entry: every semantic field a remote needs to
/// materialize one credential row.
///
/// **Excludes** device-local timestamps (`created_at`/`updated_at`/
/// `last_accessed`) — those are local device facts; copying them across
/// devices only creates noise. On materialization the receiver keeps the local
/// timestamps of its existing row (a new row uses the materialization time).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncItemSnapshot {
    pub identity_id: Uuid,
    pub name: String,
    pub credential_type: CredentialType,
    pub security_level: SecurityLevel,
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub is_favorite: bool,
    pub is_active: bool,
    pub data: CredentialData,
}

impl SyncItemSnapshot {
    /// Assemble a snapshot from a local credential row plus decrypted
    /// `CredentialData`.
    pub fn from_credential(credential: &Credential, data: &CredentialData) -> Self {
        Self {
            identity_id: credential.identity_id,
            name: credential.name.clone(),
            credential_type: credential.credential_type.clone(),
            security_level: credential.security_level.clone(),
            url: credential.url.clone(),
            username: credential.username.clone(),
            notes: credential.notes.clone(),
            tags: credential.tags.clone(),
            metadata: credential.metadata.clone(),
            is_favorite: credential.is_favorite,
            is_active: credential.is_active,
            data: data.clone(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Seal with the item key (the sync payload's `ciphertext` field).
    pub fn seal(&self, item_key: &[u8; 32]) -> Result<Vec<u8>> {
        EncryptionService::new(item_key)
            .encrypt(&self.to_bytes()?)
            .map_err(|e| {
                PersonaError::CryptographicError(format!("failed to seal snapshot: {e}")).into()
            })
    }

    /// Open (materialization path; a wrong key or tampered ciphertext is
    /// always fail-closed).
    pub fn open(sealed: &[u8], item_key: &[u8; 32]) -> Result<Self> {
        let plaintext = EncryptionService::new(item_key)
            .decrypt(sealed)
            .map_err(|_| {
                PersonaError::CryptographicError(
                    "failed to open snapshot with item key".to_string(),
                )
            })?;
        Self::from_bytes(&plaintext)
    }
}

/// Sync snapshot of a passkey entry: every semantic field a remote needs to
/// materialize one passkey row.
///
/// **Excludes** device-local facts — `created_at` (a new row uses the
/// materialization time), `sign_count` and `last_used_at` (advanced
/// independently on each device per assertion; copying counts across devices
/// only fakes the WebAuthn clone-detection baseline). On materialization the
/// receiver keeps the local usage state of its existing row.
///
/// `encrypted_private_key` is the private-key envelope sealed by the source
/// item key, moved **verbatim**: the item key travels inside the group
/// envelope (the materializing device rewraps it to its local primary key
/// without changing the key bytes), so the same item key can still open this
/// envelope — same invariant as the primary database's attachment one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncPasskeySnapshot {
    pub identity_id: Uuid,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub credential_id: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub alg: i64,
    pub uv_initialized: bool,
    pub export_allowed: bool,
    pub tags: Vec<String>,
}

impl SyncPasskeySnapshot {
    /// Assemble a snapshot from a local passkey row (capture path; no
    /// device-local usage state).
    pub fn from_item(item: &crate::models::PasskeyItem) -> Self {
        Self {
            identity_id: item.identity_id,
            rp_id: item.rp_id.clone(),
            rp_name: item.rp_name.clone(),
            user_handle: item.user_handle.clone(),
            user_name: item.user_name.clone(),
            user_display_name: item.user_display_name.clone(),
            credential_id: item.credential_id.clone(),
            encrypted_private_key: item.encrypted_private_key.clone(),
            public_key_cose: item.public_key_cose.clone(),
            alg: item.alg,
            uv_initialized: item.uv_initialized,
            export_allowed: item.export_allowed,
            tags: item.tags.clone(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Seal with the item key (the sync payload's `ciphertext` field).
    pub fn seal(&self, item_key: &[u8; 32]) -> Result<Vec<u8>> {
        EncryptionService::new(item_key)
            .encrypt(&self.to_bytes()?)
            .map_err(|e| {
                PersonaError::CryptographicError(format!("failed to seal passkey snapshot: {e}"))
                    .into()
            })
    }

    /// Open (materialization path; a wrong key or tampered ciphertext is
    /// always fail-closed).
    pub fn open(sealed: &[u8], item_key: &[u8; 32]) -> Result<Self> {
        let plaintext = EncryptionService::new(item_key)
            .decrypt(sealed)
            .map_err(|_| {
                PersonaError::CryptographicError(
                    "failed to open passkey snapshot with item key".to_string(),
                )
            })?;
        Self::from_bytes(&plaintext)
    }
}

/// Library-level snapshot package (S2 wrap-up, E2EE_SYNC_DESIGN §5
/// "library-level snapshots and op compaction"): the whole library state at
/// some server seq — the **view-sufficient set** of the local oplog (the
/// primary op of every item plus undecided conflict copies, tombstones
/// included as primary; older versions dropped by GC have a neutral view and
/// are absent). The whole package is then encrypted with the group key and
/// uploaded — the server sees a single BLOB (single-snapshot upsert plus
/// compaction of ops with `seq ≤ S`).
///
/// **Packs original ops rather than credential table rows** (install = upsert
/// into the local oplog by op_id + the existing materialization path, reused
/// end to end):
///
/// - **pending identities are not lost**: when a new device lacks the identity
///   row, `materialize_put` returns `SkippedPendingIdentity` — a credential
///   table snapshot would simply drop the item while its op has already been
///   compacted (a real data hole); the op goes into the oplog instead and
///   retries pending like a full replay.
/// - **conflict copies are not lost**: undecided dual versions are part of the
///   "no data loss" baseline, and conflict ops before the snapshot point are
///   compacted too.
/// - **tombstones present to prevent resurrection**: after `seq ≤ S` is
///   compacted, "increments after the point" do not carry deletions from
///   before the snapshot point; a snapshot missing deletions would resurrect
///   deleted items on devices installing into a non-empty library.
/// - **LWW total order preserved**: op_id/lamport/device_id are moved
///   verbatim, so the `item_view` of a snapshot-installing device matches
///   that of old devices not using snapshots, item by item — "snapshot start
///   + increments after the point == full replay" by view equality (the
///   criterion of the convergence-equivalence test anchor).
///
/// The zero-knowledge invariant matches single-item snapshots: item
/// names/domains/usernames/passwords exist only inside item key ciphertext,
/// and the item key only inside group key ciphertext; any packaging format
/// error is fail-closed (the covered range may already be compacted away, so
/// silently degrading to a full replay is not viable).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LibrarySnapshotPayload {
    /// Packaging time (rfc3339, display only).
    pub created_at: String,
    /// View-sufficient set: primaries (put or tombstone) plus conflict copies,
    /// grouped by item.
    pub ops: Vec<SyncOp>,
}

/// Snapshot upload trigger threshold (E2EE_SYNC_DESIGN §5 "trigger timing"):
/// after a push ack, repack only when `head_seq − last_snapshot_seq > this
/// value` (to avoid frequent repacking). Configuration-level only: not
/// exposed by the CLI/desktop.
pub const UPLOAD_THRESHOLD_OPS: i64 = 1000;

impl LibrarySnapshotPayload {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Encrypt the whole package with the group key (server-stored bytes).
    pub fn seal(&self, group_key: &super::keys::GroupKey) -> Result<Vec<u8>> {
        EncryptionService::new(group_key.as_bytes())
            .encrypt(&self.to_bytes()?)
            .map_err(|e| {
                PersonaError::CryptographicError(format!("failed to seal library snapshot: {e}"))
                    .into()
            })
    }

    /// Open (bootstrap path; a wrong group key or tampered ciphertext is
    /// fail-closed).
    pub fn open(sealed: &[u8], group_key: &super::keys::GroupKey) -> Result<Self> {
        let plaintext = EncryptionService::new(group_key.as_bytes())
            .decrypt(sealed)
            .map_err(|_| {
                PersonaError::CryptographicError(
                    "failed to open library snapshot with group key".to_string(),
                )
            })?;
        Self::from_bytes(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PasswordCredentialData;
    use crate::sync::oplog::{ItemKind, OpType, SyncPayload};

    fn sample() -> SyncItemSnapshot {
        SyncItemSnapshot {
            identity_id: Uuid::new_v4(),
            name: "Email 邮箱".to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::High,
            url: Some("https://example.com".to_string()),
            username: Some("alice@example.com".to_string()),
            notes: Some("备注\n第二行".to_string()),
            tags: vec!["work".to_string(), "重要".to_string()],
            metadata: HashMap::from([("region".to_string(), "cn-north".to_string())]),
            is_favorite: true,
            is_active: true,
            data: CredentialData::Password(PasswordCredentialData {
                password: "s3cret-π".to_string(),
                email: Some("alice@example.com".to_string()),
                security_questions: vec![],
            }),
        }
    }

    #[test]
    fn snapshot_bytes_round_trip_preserves_every_field() {
        let snap = sample();
        let opened = SyncItemSnapshot::from_bytes(&snap.to_bytes().unwrap()).unwrap();
        assert_eq!(opened.to_bytes().unwrap(), snap.to_bytes().unwrap());
    }

    #[test]
    fn seal_open_round_trips_with_item_key() {
        let snap = sample();
        let item_key = EncryptionService::generate_key();
        let sealed = snap.seal(&item_key).unwrap();
        assert_ne!(sealed, snap.to_bytes().unwrap(), "密封后必须是密文");
        assert_eq!(
            SyncItemSnapshot::open(&sealed, &item_key)
                .unwrap()
                .to_bytes()
                .unwrap(),
            snap.to_bytes().unwrap()
        );
    }

    #[test]
    fn wrong_item_key_cannot_open_snapshot() {
        let snap = sample();
        let sealed = snap.seal(&EncryptionService::generate_key()).unwrap();
        assert!(SyncItemSnapshot::open(&sealed, &EncryptionService::generate_key()).is_err());
        // Tampering and truncation also error out rather than panicking
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(SyncItemSnapshot::open(&tampered, &EncryptionService::generate_key()).is_err());
        assert!(SyncItemSnapshot::open(&sealed[..12], &EncryptionService::generate_key()).is_err());
    }

    #[test]
    fn garbage_bytes_are_rejected_not_panicking() {
        assert!(SyncItemSnapshot::from_bytes(b"not bincode").is_err());
        assert!(SyncItemSnapshot::from_bytes(&[0u8; 4]).is_err());
    }

    #[test]
    fn from_credential_maps_every_semantic_field() {
        let credential = Credential::new(
            Uuid::new_v4(),
            "Bank".to_string(),
            CredentialType::BankCard,
            SecurityLevel::High,
            vec![1, 2, 3],
            None,
        );
        let data = CredentialData::Password(PasswordCredentialData {
            password: "x".to_string(),
            email: None,
            security_questions: vec![],
        });
        let snap = SyncItemSnapshot::from_credential(&credential, &data);
        assert_eq!(snap.identity_id, credential.identity_id);
        assert_eq!(snap.name, "Bank");
        assert_eq!(snap.credential_type, CredentialType::BankCard);
        assert_eq!(snap.data.to_bytes().unwrap(), data.to_bytes().unwrap());
    }

    // ---- passkey snapshots ----

    fn passkey_item() -> crate::models::PasskeyItem {
        let mut item = crate::models::PasskeyItem::new(
            Uuid::new_v4(),
            "example.com".to_string(),
            b"user-handle".to_vec(),
            b"credential-id-32-bytes-xxxxxxxxxxxx".to_vec(),
            vec![9; 48],
            vec![7; 48],
            b"cose-key".to_vec(),
        );
        item.rp_name = Some("Example".to_string());
        item.user_name = Some("alice@example.com".to_string());
        item.user_display_name = Some("Alice".to_string());
        item.uv_initialized = true;
        item.export_allowed = false;
        item.tags = vec!["synced".to_string()];
        item
    }

    #[test]
    fn passkey_snapshot_round_trip_preserves_every_field() {
        let item = passkey_item();
        let snap = SyncPasskeySnapshot::from_item(&item);
        let opened = SyncPasskeySnapshot::from_bytes(&snap.to_bytes().unwrap()).unwrap();
        assert_eq!(opened.identity_id, item.identity_id);
        assert_eq!(opened.rp_id, "example.com");
        assert_eq!(opened.rp_name.as_deref(), Some("Example"));
        assert_eq!(opened.user_handle, item.user_handle);
        assert_eq!(opened.user_name.as_deref(), Some("alice@example.com"));
        assert_eq!(opened.user_display_name.as_deref(), Some("Alice"));
        assert_eq!(opened.credential_id, item.credential_id);
        assert_eq!(opened.encrypted_private_key, item.encrypted_private_key);
        assert_eq!(opened.public_key_cose, item.public_key_cose);
        assert_eq!(opened.alg, item.alg);
        assert!(opened.uv_initialized);
        assert!(!opened.export_allowed);
        assert_eq!(opened.tags, vec!["synced".to_string()]);
    }

    #[test]
    fn passkey_snapshot_seal_open_and_fail_closed() {
        let snap = SyncPasskeySnapshot::from_item(&passkey_item());
        let item_key = EncryptionService::generate_key();
        let sealed = snap.seal(&item_key).unwrap();
        assert_ne!(sealed, snap.to_bytes().unwrap(), "密封后必须是密文");
        assert_eq!(
            SyncPasskeySnapshot::open(&sealed, &item_key)
                .unwrap()
                .credential_id,
            snap.credential_id
        );
        // Wrong key / tampering / truncation all fail-closed
        assert!(SyncPasskeySnapshot::open(&sealed, &EncryptionService::generate_key()).is_err());
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(SyncPasskeySnapshot::open(&tampered, &item_key).is_err());
        assert!(SyncPasskeySnapshot::open(&sealed[..12], &item_key).is_err());
        assert!(SyncPasskeySnapshot::from_bytes(b"not bincode").is_err());
    }

    // ---- library-level snapshot package (S2, E2EE_SYNC_DESIGN §5) ----

    /// An op isomorphic with the packaging path (a put carrying one item
    /// snapshot ciphertext; a tombstone always has an empty payload).
    fn library_op(
        item_key: &[u8; 32],
        group: &crate::sync::keys::GroupKey,
        lamport: u64,
        op: OpType,
    ) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            kind: ItemKind::Credential,
            op,
            lamport,
            device_id: Uuid::new_v4(),
            timestamp: None,
            payload: (op == OpType::Put).then(|| SyncPayload {
                ciphertext: sample().seal(item_key).unwrap(),
                wrapped_item_key: crate::sync::keys::wrap_item_key_with_group(item_key, group),
            }),
        }
    }

    fn library_sample(group: &crate::sync::keys::GroupKey) -> LibrarySnapshotPayload {
        let item_key = EncryptionService::generate_key();
        LibrarySnapshotPayload {
            created_at: "2026-10-07T00:00:00Z".to_string(),
            // View-sufficient set: put primary + tombstone primary (prevents deletion
            // resurrection)
            ops: vec![
                library_op(&item_key, group, 1, OpType::Put),
                library_op(&item_key, group, 2, OpType::Delete),
            ],
        }
    }

    #[test]
    fn library_snapshot_seal_open_round_trips_with_group_key() {
        let group = crate::sync::keys::GroupKey::generate().unwrap();
        let payload = library_sample(&group);
        let sealed = payload.seal(&group).unwrap();
        assert_ne!(sealed, payload.to_bytes().unwrap(), "整包必须是密文");

        let opened = LibrarySnapshotPayload::open(&sealed, &group).unwrap();
        assert_eq!(opened.ops.len(), 2);
        assert_eq!(opened.created_at, payload.created_at);
        // Every op field verbatim (the LWW total order and op_id idempotency both
        // rely on op_id/lamport/device_id staying intact — so the installing
        // device's item_view is item-for-item the same order as old devices')
        assert_eq!(opened.ops, payload.ops);
        // Tombstone primary is present and its payload is always empty
        assert!(opened.ops[1].is_tombstone());
        assert!(opened.ops[1].payload.is_none());

        // Unwrap the chain one level at a time: group key → item key →
        // single-item snapshot plaintext (exactly the materialization path)
        let put = opened.ops[0].payload.as_ref().expect("put 必带 payload");
        let item_key =
            crate::sync::keys::unwrap_item_key_with_group(&put.wrapped_item_key, &group).unwrap();
        let snap = SyncItemSnapshot::open(&put.ciphertext, &item_key).unwrap();
        assert_eq!(snap.name, "Email 邮箱");
        assert_eq!(snap.username.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn library_snapshot_wrong_group_key_and_tamper_fail_closed() {
        let group = crate::sync::keys::GroupKey::generate().unwrap();
        let sealed = library_sample(&group).seal(&group).unwrap();
        let other = crate::sync::keys::GroupKey::generate().unwrap();
        assert!(
            LibrarySnapshotPayload::open(&sealed, &other).is_err(),
            "错 key 必须 fail-closed（静默降级为全量重放不可行——区间可能已被压缩）"
        );
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(LibrarySnapshotPayload::open(&tampered, &group).is_err());
        assert!(LibrarySnapshotPayload::open(&sealed[..12], &group).is_err());
    }

    #[test]
    fn library_snapshot_bytes_never_leak_entry_plaintext() {
        // Zero-knowledge: item name/domain/username/password and raw key bytes cannot
        // be found anywhere in the stored package bytes
        let group = crate::sync::keys::GroupKey::generate().unwrap();
        let item_key = EncryptionService::generate_key();
        let snap = SyncItemSnapshot {
            name: "机密条目Bravo".to_string(),
            url: Some("https://secret-site-b.example/login".to_string()),
            username: Some("bob@example.com".to_string()),
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            identity_id: Uuid::new_v4(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::High,
            data: CredentialData::Password(PasswordCredentialData {
                password: "特征口令-Δ9".to_string(),
                email: None,
                security_questions: vec![],
            }),
        };
        let payload = LibrarySnapshotPayload {
            created_at: "2026-10-07T00:00:00Z".to_string(),
            ops: vec![SyncOp {
                op_id: Uuid::new_v4(),
                item_id: Uuid::new_v4(),
                kind: ItemKind::Credential,
                op: OpType::Put,
                lamport: 1,
                device_id: Uuid::new_v4(),
                timestamp: None,
                payload: Some(SyncPayload {
                    ciphertext: snap.seal(&item_key).unwrap(),
                    wrapped_item_key: crate::sync::keys::wrap_item_key_with_group(
                        &item_key, &group,
                    ),
                }),
            }],
        };
        let stored = payload.seal(&group).unwrap();
        for plaintext in [
            "机密条目Bravo".as_bytes(),
            b"secret-site-b.example",
            b"bob@example.com",
            "特征口令-Δ9".as_bytes(),
        ] {
            assert!(
                !stored.windows(plaintext.len()).any(|w| w == plaintext),
                "整包字节泄露明文: {}",
                String::from_utf8_lossy(plaintext)
            );
        }
        assert!(
            !stored.windows(32).any(|w| w == item_key.as_slice()),
            "item key 原始字节泄露"
        );
        assert!(
            !stored.windows(32).any(|w| w == group.as_bytes().as_slice()),
            "group key 原始字节泄露"
        );
    }
}
