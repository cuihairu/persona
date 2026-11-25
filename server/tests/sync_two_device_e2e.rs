//! M6 multi-device real-chain walkthrough (the part completable offline): a real
//! persona-server router + two real core clients (`SyncAdminApi` /
//! `SyncSession<HttpSyncRemote>`, each with its own temporary database), walking the whole
//! chain of join -> authorize -> one-way sync -> concurrent-edit genuine conflict ->
//! adjudication convergence -> revocation.
//!
//! Complementary to the MemRemote unit tests in core/src/sync/runtime.rs: those anchor the
//! engine logic, while this one anchors the HTTP wire format and the server's real
//! implementation (authentication, registration, envelopes, oplog relaying, epoch). The
//! desktop/plugin UI walkthrough (screenshots) still needs real hardware; see TODO M6.

use persona_core::crypto::key_hierarchy::KeyHierarchy;
use persona_core::crypto::EncryptionService;
use persona_core::models::credential::{
    CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
};
use persona_core::models::identity::{Identity, IdentityType};
use persona_core::storage::database::Database;
use persona_core::storage::passkey_repository::PasskeyRepository;
use persona_core::storage::repository::{CredentialRepository, IdentityRepository};
use persona_core::sync::capture::SyncCapture;
use persona_core::sync::device::DeviceIdentity;
use persona_core::sync::envelope;
use persona_core::sync::oplog::{ItemKind, OpType};
use persona_core::sync::remote::SyncAdminApi;
use persona_core::sync::runtime::SyncSession;
use persona_core::sync::snapshot::{SyncItemSnapshot, SyncPasskeySnapshot};
use persona_core::Repository;
use persona_server::auth::AuthTokens;
use persona_server::build_router;
use persona_server::metrics::Metrics;
use persona_server::state::{self, AppState};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const TOKEN_A: &str = "e2e-token-device-a";
const TOKEN_B: &str = "e2e-token-device-b";

/// Returns (base_url, TempDir): the TempDir must be held by the caller — the sqlite file
/// is deleted with it on drop, and dropping early would make later requests 500.
async fn spawn_server() -> (String, sqlx::SqlitePool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("server.db");
    let pool = state::init_pool(db_path.to_str().unwrap()).await.unwrap();
    state::run_migrations(&pool).await.unwrap();
    let auth = AuthTokens::parse(&format!("device-a:{TOKEN_A},device-b:{TOKEN_B}")).unwrap();
    let start_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let app = AppState::new(pool.clone(), Some(auth), Arc::new(Metrics::new(start_unix)));
    let router = build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}"), pool.clone(), dir)
}

/// One "device": its own temporary database + its own master key. Both databases are
/// seeded with the same identity row id — a snapshot carries the initiator's identity_id,
/// and materialize skips as pending_identity when it cannot find that identity, so both
/// ends must share the same identity id.
struct Device {
    db: Database,
    master: EncryptionService,
    identity_id: Uuid,
    cred_repo: CredentialRepository,
}

async fn make_device(shared_identity_id: Uuid) -> Device {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut identity = Identity::new("e2e-seed".to_string(), IdentityType::Personal);
    identity.id = shared_identity_id;
    IdentityRepository::new(db.clone())
        .create(&identity)
        .await
        .unwrap();
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let cred_repo = CredentialRepository::new(db.clone());
    Device {
        db,
        master,
        identity_id: shared_identity_id,
        cred_repo,
    }
}

fn no_travel() -> Box<dyn Fn() -> bool + Send + Sync> {
    Box::new(|| false)
}

fn password_data(password: &str) -> CredentialData {
    CredentialData::Password(PasswordCredentialData {
        password: password.to_string(),
        email: None,
        security_questions: vec![],
    })
}

fn snapshot(identity_id: Uuid, name: &str, password: &str) -> SyncItemSnapshot {
    SyncItemSnapshot {
        identity_id,
        name: name.to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::High,
        url: None,
        username: Some("e2e@example.com".to_string()),
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data(password),
    }
}

/// Local edit -> capture into the oplog (the same entry point as the desktop service's
/// assembly chain).
async fn local_put(
    session: &SyncSession<persona_core::sync::remote::HttpSyncRemote>,
    identity_id: Uuid,
    item_id: Uuid,
    name: &str,
    password: &str,
) {
    let item_key = EncryptionService::generate_key();
    let snap = snapshot(identity_id, name, password);
    session
        .capture()
        .capture(
            item_id,
            ItemKind::Credential,
            OpType::Put,
            Some(snap.seal(&item_key).unwrap()),
            Some(Zeroizing::new(item_key)),
        )
        .await;
}

/// Register a device and return (identity, token). The first device bootstraps the group
/// key; later devices stop at "awaiting authorization" after registering.
async fn register_device(
    admin: &SyncAdminApi,
    name: &str,
    token: &str,
    bootstrap: bool,
) -> (DeviceIdentity, Uuid) {
    let identity = DeviceIdentity::generate(name).unwrap();
    let device_id = admin
        .register_device(name, identity.key_pair.public_bytes())
        .await
        .unwrap();
    let identity = identity.with_device_id(device_id);
    if bootstrap {
        admin
            .bootstrap_group_if_empty(device_id, identity.key_pair.public_bytes())
            .await
            .unwrap();
    }
    let _ = token;
    (identity, device_id)
}

/// The first device authorizes a later one: open its own envelope to get the group key,
/// then seal and upload a new envelope for the other device (the same orchestration as the
/// desktop's sync_authorize).
async fn authorize(admin: &SyncAdminApi, me: &DeviceIdentity, target: Uuid) {
    let keys = admin.group_keys().await.unwrap();
    let own = keys
        .iter()
        .find(|k| k.device_id == me.device_id)
        .expect("own envelope must exist after bootstrap");
    let group = envelope::open_group_key(&own.envelope, me.key_pair.secret_bytes()).unwrap();
    let target_device = admin
        .list_devices()
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.id == target)
        .expect("target device registered");
    let sealed = envelope::seal_group_key(&group, &target_device.public_key).unwrap();
    admin.put_group_key(target, &sealed).await.unwrap();
}

/// A creates a credential (capture -> oplog -> push) and returns the item_id.
async fn device_a_creates_item(
    session_a: &SyncSession<persona_core::sync::remote::HttpSyncRemote>,
    device: &Device,
    name: &str,
    password: &str,
) -> Uuid {
    let item_id = Uuid::new_v4();
    local_put(session_a, device.identity_id, item_id, name, password).await;
    let report = session_a.run_cycle(&device.master).await.unwrap();
    assert_eq!(report.pushed, 1, "v1 should push to the server");
    item_id
}

#[tokio::test]
async fn join_authorize_and_single_direction_sync() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    // Both ends share the same identity row id (materialize's identity foreign key)
    let shared_identity = Identity::new("e2e".to_string(), IdentityType::Personal);
    let identity_id = shared_identity.id;
    let a = make_device(identity_id).await;
    let b = make_device(identity_id).await;

    // Join: A bootstraps, B awaits authorization
    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;

    // B is not authorized: it cannot open a session (fail-closed)
    let pending = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel()).await;
    assert!(
        pending.is_err(),
        "device B must not open a session before authorization"
    );

    // A authorizes B, and B can open a session
    authorize(&admin_a, &identity_a, device_id_b).await;
    let session_a = SyncSession::open(&a.db, &identity_a, &url, TOKEN_A, no_travel())
        .await
        .unwrap();
    let session_b = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
        .await
        .unwrap();

    // A creates a credential and pushes it
    let item_id = device_a_creates_item(&session_a, &a, "来自A的凭据", "secret-a").await;

    // B pulls and materializes: an entry with the same name appears in the main store
    let report_b = session_b.run_cycle(&b.master).await.unwrap();
    assert!(
        report_b.materialized >= 1,
        "B should materialize A's credential, got {report_b:?}"
    );
    let names: Vec<String> = b
        .cred_repo
        .find_by_identity(&identity_id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert!(
        names.contains(&"来自A的凭据".to_string()),
        "B's vault should contain A's credential, got {names:?}"
    );
    let _ = item_id;
}

#[tokio::test]
async fn concurrent_edits_conflict_then_resolution_converges() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    let shared_identity = Identity::new("e2e".to_string(), IdentityType::Personal);
    let identity_id = shared_identity.id;
    let a = make_device(identity_id).await;
    let b = make_device(identity_id).await;

    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;
    authorize(&admin_a, &identity_a, device_id_b).await;
    let session_a = SyncSession::open(&a.db, &identity_a, &url, TOKEN_A, no_travel())
        .await
        .unwrap();
    let session_b = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
        .await
        .unwrap();

    // Baseline: A creates v1, B syncs it down (both lamport clocks aligned on v1)
    let item_id = device_a_creates_item(&session_a, &a, "并发条目", "v1").await;
    let baseline = session_b.run_cycle(&b.master).await.unwrap();
    assert!(baseline.materialized >= 1);

    // Offline concurrent edits: both ends modify the same-named entry
    // (same lamport, different device = a true conflict)
    local_put(&session_a, identity_id, item_id, "并发条目", "edit-from-A").await;
    local_put(&session_b, identity_id, item_id, "并发条目", "edit-from-B").await;

    // Both sides come back online and push/pull in turn
    session_a.run_cycle(&a.master).await.unwrap();
    session_b.run_cycle(&b.master).await.unwrap();
    session_a.run_cycle(&a.master).await.unwrap();

    // Both ends see the true conflict awaiting adjudication
    assert_eq!(
        session_a.conflict_item_count().await.unwrap(),
        1,
        "A must see the concurrent conflict"
    );
    assert_eq!(
        session_b.conflict_item_count().await.unwrap(),
        1,
        "B must see the concurrent conflict"
    );

    // A adjudicates: adopt the losing copy (adopt_op_id = the op id from copies;
    // which side wins LWW is decided by device_id ordering, so the loser's content
    // determines the assertion expectation)
    let conflicts = session_a.list_conflicts().await.unwrap();
    assert_eq!(conflicts.len(), 1);
    let loser = &conflicts[0].copies[0];
    let expected_password = if loser.device_id == identity_b.device_id {
        "edit-from-B"
    } else {
        "edit-from-A"
    };
    session_a
        .resolve_conflict(&a.master, item_id, loser.op_id)
        .await
        .unwrap();

    // After adjudication, A's main-store content flips to the adopted copy
    let a_creds = a.cred_repo.find_by_identity(&identity_id).await.unwrap();
    assert!(
        a_creds.iter().any(|c| c.name == "并发条目"),
        "adopted item stays in A's vault, got {:?}",
        a_creds.iter().map(|c| &c.name).collect::<Vec<_>>()
    );
    let adopted = a_creds.iter().find(|c| c.id == item_id).unwrap();
    let plain = KeyHierarchy::new(&a.master)
        .decrypt_with_wrapped_key(
            adopted.wrapped_item_key.as_ref().unwrap(),
            &adopted.encrypted_data,
        )
        .unwrap();
    match CredentialData::from_bytes(&plain).unwrap() {
        CredentialData::Password(pw) => assert_eq!(
            pw.password, expected_password,
            "A's vault must adopt the losing copy's content"
        ),
        other => panic!("expected password credential, got {other:?}"),
    }
    // Convergence: B runs another cycle, and neither end has an unresolved conflict
    session_a.run_cycle(&a.master).await.unwrap();
    session_b.run_cycle(&b.master).await.unwrap();
    assert_eq!(
        session_a.conflict_item_count().await.unwrap(),
        0,
        "A's conflict should be cleared after resolution"
    );
    assert_eq!(
        session_b.conflict_item_count().await.unwrap(),
        0,
        "B's conflict should be cleared after the resolution cycle"
    );
}

#[tokio::test]
async fn revoke_device_drops_envelope_and_blocks_new_sessions() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    let shared_identity = Identity::new("e2e".to_string(), IdentityType::Personal);
    let _a = make_device(shared_identity.id).await;
    let b = make_device(shared_identity.id).await;

    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;
    authorize(&admin_a, &identity_a, device_id_b).await;

    // Before revocation, B can open a session normally
    assert!(
        SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
            .await
            .is_ok()
    );

    // A revokes B (same semantics as desktop sync_revoke: drop the
    // registration + envelope, idempotent)
    admin_a.delete_device(device_id_b).await.unwrap();

    // The envelope is gone with the revocation: no new session can open
    // (fail-closed)
    let fresh_b = make_device(shared_identity.id).await;
    let blocked = SyncSession::open(&fresh_b.db, &identity_b, &url, TOKEN_B, no_travel()).await;
    assert!(
        blocked.is_err(),
        "revoked device must not open a new sync session"
    );

    // B no longer appears in the device roster
    let devices = admin_a.list_devices().await.unwrap();
    assert!(
        devices.iter().all(|d| d.id != device_id_b),
        "revoked device must disappear from the roster, got {devices:?}"
    );
}

/// S4 self-service device remarks: each end writes the remark under its own
/// token (there is no cross-device path), readable by everyone; an empty
/// string / pure whitespace clears it; after revocation the original device
/// can no longer write it (404 fail-closed).
#[tokio::test]
async fn device_remark_self_service_and_isolation() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();
    let admin_b = SyncAdminApi::new(&url, TOKEN_B).unwrap();

    let (_identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (_identity_b, device_id_b) = register_device(&admin_b, "device-b", TOKEN_B, false).await;

    // Each writes its own (the server trims it and echoes it back)
    let stored_a = admin_a.set_device_remark("  书房的主力机  ").await.unwrap();
    assert_eq!(stored_a, "书房的主力机", "server must trim the remark");
    let stored_b = admin_b.set_device_remark("口袋里的备用机").await.unwrap();
    assert_eq!(stored_b, "口袋里的备用机");

    // The roster is visible in both directions, each value staying its own
    // (B's write cannot touch A's row)
    let names: Vec<(String, String)> = admin_a
        .list_devices()
        .await
        .unwrap()
        .into_iter()
        .map(|d| (d.device_name, d.remark))
        .collect();
    assert!(
        names.contains(&("device-a".to_string(), "书房的主力机".to_string()))
            && names.contains(&("device-b".to_string(), "口袋里的备用机".to_string())),
        "both remarks must be visible with their own values, got {names:?}"
    );

    // Pure whitespace = clear
    assert_eq!(admin_b.set_device_remark("   ").await.unwrap(), "");
    let b_row = admin_b
        .list_devices()
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.device_name == "device-b")
        .unwrap();
    assert_eq!(b_row.remark, "", "whitespace must clear the remark");

    // After B is revoked, its token cannot write a remark (the
    // registration row is gone → 404 absent)
    admin_a.delete_device(device_id_b).await.unwrap();
    let err = admin_b.set_device_remark("复活").await.unwrap_err();
    assert!(
        err.to_string().contains("HTTP 404"),
        "revoked device must fail closed, got: {err}"
    );
}

// Snapshot bootstrap + post-snapshot increments == full replay (E2EE_SYNC_DESIGN
// §5 test anchor): two real TCP devices, and B's first sync takes the snapshot
// path — A pushes past the threshold (>1000 ops) to trigger the packaged upload
// at the tail of run_cycle (the real production trigger path, with no
// test-only shortcut), and the server compresses the covered range inside the
// transaction; B's first round has pulled==0 yet materializes everything, which
// can only come from the snapshot package (the full-replay path would inevitably
// give pulled==1001), with the watermark landing on the coverage point;
// post-snapshot increments then continue as usual.
#[tokio::test]
async fn snapshot_bootstrap_plus_increment_converges_over_real_tcp() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    let shared_identity = Identity::new("e2e".to_string(), IdentityType::Personal);
    let identity_id = shared_identity.id;
    let a = make_device(identity_id).await;
    let b = make_device(identity_id).await;

    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;
    authorize(&admin_a, &identity_a, device_id_b).await;
    let session_a = SyncSession::open(&a.db, &identity_a, &url, TOKEN_A, no_travel())
        .await
        .unwrap();
    let session_b = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
        .await
        .unwrap();

    // A pushes all 1001 entries (> UPLOAD_THRESHOLD_OPS=1000): push sends one
    // batch per cycle (≤500) until nothing is pending — the final cycle crosses
    // the threshold and triggers the packaged upload (the server then compresses
    // all ops with seq ≤ 1001)
    for i in 1..=1001 {
        local_put(
            &session_a,
            identity_id,
            Uuid::new_v4(),
            &format!("item-{i}"),
            &format!("secret-{i}"),
        )
        .await;
    }
    let mut total_pushed = 0;
    for _ in 0..5 {
        let report_a = session_a.run_cycle(&a.master).await.unwrap();
        total_pushed += report_a.pushed;
        if report_a.pushed == 0 {
            break;
        }
    }
    assert_eq!(total_pushed, 1001, "all ops must reach the server");

    // B's first sync: bootstrap installs the snapshot, pull sees zero
    // increments and materializes everything
    let report_b = session_b.run_cycle(&b.master).await.unwrap();
    assert_eq!(
        report_b.pulled, 0,
        "server oplog was fully compressed; anything B got must come from the snapshot"
    );
    assert_eq!(
        report_b.materialized, 1001,
        "B must materialize the whole library from the snapshot"
    );
    let status_b = session_b.status().await.unwrap();
    assert_eq!(
        status_b.head_seq, 1001,
        "head is snapshot-aware: oplog emptied by compression must not regress the group version"
    );
    assert_eq!(
        status_b.local_watermark, 1001,
        "cursor must sit at the snapshot coverage point"
    );
    assert_eq!(status_b.behind, 0);

    // The snapshot package contents match A's main store entry by entry
    // (compare the full name set, plus decrypt one entry and compare)
    let mut b_names: Vec<String> = b
        .cred_repo
        .find_by_identity(&identity_id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    b_names.sort();
    assert_eq!(b_names.len(), 1001);
    assert_eq!(b_names[0], "item-1");
    assert_eq!(b_names[1000], "item-999");
    let b_row = b
        .cred_repo
        .find_by_identity(&identity_id)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.name == "item-42")
        .expect("item-42 must materialize from the snapshot");
    let plain = KeyHierarchy::new(&b.master)
        .decrypt_with_wrapped_key(
            b_row.wrapped_item_key.as_ref().unwrap(),
            &b_row.encrypted_data,
        )
        .unwrap();
    match CredentialData::from_bytes(&plain).unwrap() {
        CredentialData::Password(pw) => assert_eq!(pw.password, "secret-42"),
        other => panic!("expected password credential, got {other:?}"),
    }

    // Post-snapshot increment: A appends one entry and B keeps pulling as
    // usual (the cursor sits at the coverage point, so only the new range arrives)
    local_put(
        &session_a,
        identity_id,
        Uuid::new_v4(),
        "item-1002",
        "secret-1002",
    )
    .await;
    session_a.run_cycle(&a.master).await.unwrap();
    let report_b2 = session_b.run_cycle(&b.master).await.unwrap();
    assert_eq!(report_b2.pulled, 1, "only the post-snapshot op is new");
    assert!(report_b2.materialized >= 1);
    let b_names2: Vec<String> = b
        .cred_repo
        .find_by_identity(&identity_id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(
        b_names2.len(),
        1002,
        "increment must converge on the snapshot base"
    );
    assert!(b_names2.contains(&"item-1002".to_string()));
}

#[tokio::test]
async fn passkey_put_and_delete_sync_between_devices() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    let shared_identity = Identity::new("e2e-passkey".to_string(), IdentityType::Personal);
    let identity_id = shared_identity.id;
    let a = make_device(identity_id).await;
    let b = make_device(identity_id).await;

    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;
    authorize(&admin_a, &identity_a, device_id_b).await;
    let session_a = SyncSession::open(&a.db, &identity_a, &url, TOKEN_A, no_travel())
        .await
        .unwrap();
    let session_b = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
        .await
        .unwrap();

    // A registers the passkey (capture semantics mirror
    // service.create_passkey_full): the private-key envelope = the scalar sealed
    // with the item key, the snapshot carries the semantic fields, and the item
    // key is wrapped in a group envelope
    let item_id = Uuid::new_v4();
    let item_key = EncryptionService::generate_key();
    let scalar = EncryptionService::generate_key();
    let sealed_private = EncryptionService::new(&item_key)
        .encrypt(scalar.as_slice())
        .unwrap();
    let snap = SyncPasskeySnapshot {
        identity_id,
        rp_id: "example.com".to_string(),
        rp_name: Some("Example".to_string()),
        user_handle: b"e2e-handle".to_vec(),
        user_name: Some("e2e@example.com".to_string()),
        user_display_name: None,
        credential_id: b"e2e-credential-id-32-bytes-xxxxxxx".to_vec(),
        encrypted_private_key: sealed_private,
        public_key_cose: b"e2e-cose".to_vec(),
        alg: -7,
        uv_initialized: true,
        export_allowed: true,
        tags: vec![],
    };
    session_a
        .capture()
        .capture(
            item_id,
            ItemKind::Passkey,
            OpType::Put,
            Some(snap.seal(&item_key).unwrap()),
            Some(Zeroizing::new(item_key)),
        )
        .await;
    let report = session_a.run_cycle(&a.master).await.unwrap();
    assert_eq!(report.pushed, 1, "passkey put should push to the server");

    // B pulls and materializes: a row with the same id appears in the passkeys
    // table, the item key is re-wrapped to B's master key, and the private-key
    // envelope still decrypts normally
    let report_b = session_b.run_cycle(&b.master).await.unwrap();
    assert!(
        report_b.materialized >= 1,
        "B should materialize A's passkey, got {report_b:?}"
    );
    let b_repo = PasskeyRepository::new(std::sync::Arc::new(b.db.clone()));
    let row = b_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .expect("passkey row materialized on B");
    assert_eq!(row.rp_id, "example.com");
    assert_eq!(row.user_name.as_deref(), Some("e2e@example.com"));
    let scalar_out = KeyHierarchy::new(&b.master)
        .decrypt_with_wrapped_key(&row.wrapped_item_key, &row.encrypted_private_key)
        .unwrap();
    assert_eq!(scalar_out.as_slice(), scalar.as_slice());

    // A deletes → tombstone → B's main-store row disappears
    session_a
        .capture()
        .capture(item_id, ItemKind::Passkey, OpType::Delete, None, None)
        .await;
    let report = session_a.run_cycle(&a.master).await.unwrap();
    assert_eq!(report.pushed, 1, "tombstone should push to the server");
    session_b.run_cycle(&b.master).await.unwrap();
    assert!(
        b_repo.find_by_id(&item_id).await.unwrap().is_none(),
        "B should tombstone the passkey"
    );
}
