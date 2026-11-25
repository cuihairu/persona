use super::*;

// E2EE_SYNC_DESIGN phase 2 batch 4 acceptance "two-end convergence test": real HTTP
// stack + client wire layer (core HttpSyncRemote) + two independent oplogs (each with
// a SyncEngine attached). Covers: one-way push->pull, a genuine conflict from both
// ends editing offline at the same lamport (both converge on the same primary slot +
// both versions kept), and rebuilding an engine instance (all state lives in the
// library: local_lamport/cursor/pending do not travel with the instance — a
// constructive proof that changing the master password has zero effect on sync:
// SyncEngine takes no master-password parameter anywhere, so an instance can be
// freely discarded and replaced).
#[tokio::test(flavor = "multi_thread")]
async fn two_devices_converge_over_real_tcp_conflict_keeps_both_versions() {
    use persona_core::storage::sync_repository::SyncRepository;
    use persona_core::storage::Database;
    use persona_core::sync::engine::SyncEngine;
    use persona_core::sync::oplog::{item_view, ItemKind, OpType, SyncPayload};
    use persona_core::sync::remote::HttpSyncRemote;

    const TOKEN: &str = "sync-e2e-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");

    async fn fresh_repo() -> (SyncRepository, Database) {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let repo = SyncRepository::new(db.clone());
        (repo, db)
    }

    fn engine_for(
        db: Database,
        base: &str,
        token: &str,
        device_id: Uuid,
    ) -> SyncEngine<HttpSyncRemote> {
        SyncEngine::new(
            SyncRepository::new(db),
            HttpSyncRemote::new(base, token).unwrap(),
            device_id,
            Box::new(|| false),
        )
    }

    fn payload(tag: u8) -> Option<SyncPayload> {
        Some(SyncPayload {
            ciphertext: vec![tag; 8],
            wrapped_item_key: vec![tag; 32],
        })
    }

    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let (repo_a, db_a) = fresh_repo().await;
    let (repo_b, db_b) = fresh_repo().await;
    let engine_a = engine_for(db_a.clone(), &base, TOKEN, device_a);
    let engine_b = engine_for(db_b, &base, TOKEN, device_b);

    // A writes lamport 1 offline and pushes
    let item = Uuid::new_v4();
    let a1 = engine_a
        .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xA1))
        .await
        .unwrap();
    assert_eq!(a1.lamport, 1);
    assert_eq!(engine_a.push_cycle().await.unwrap().pushed, 1);

    // B comes online, pulls A1, and its primary slot is A's version
    let pull = engine_b.pull_cycle().await.unwrap();
    assert_eq!(pull.applied, 1);
    assert_eq!(repo_b.get_state().await.unwrap().local_lamport, 1);
    let view_b = item_view(repo_b.item_ops(item).await.unwrap());
    assert_eq!(view_b.primary.as_ref().unwrap().device_id, device_a);
    assert!(view_b.conflicts.is_empty());

    // Both ends edit offline at the same lamport: B writes 2 starting from lamport 1
    // and pushes; A is unaware (never pulled B2) and also writes 2 starting from 1 —
    // the canonical shape of a genuine conflict
    let b2 = engine_b
        .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xB2))
        .await
        .unwrap();
    assert_eq!(b2.lamport, 2);
    assert_eq!(engine_b.push_cycle().await.unwrap().pushed, 1);

    // Rebuild A's engine instance (same library handle): the clock continues
    // correctly — the next op still follows lamport 2 (local_lamport lives in the
    // library, not the instance)
    let engine_a2 = engine_for(db_a, &base, TOKEN, device_a);
    let a2 = engine_a2
        .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xA2))
        .await
        .unwrap();
    assert_eq!(a2.lamport, 2);
    assert_eq!(engine_a2.push_cycle().await.unwrap().pushed, 1);

    // Each end pulls once -> both oplogs hold the full {A1, B2, A2} set
    let pull_a = engine_a2.pull_cycle().await.unwrap();
    assert_eq!(pull_a.applied, 1); // A1 is its own local op, skipped by dedup
    let pull_b = engine_b.pull_cycle().await.unwrap();
    assert_eq!(pull_b.applied, 1);

    // Convergence assertions: both oplogs hold the same full set, the primary slot
    // converges on the same op (total-order adjudication), the conflict area holds
    // exactly one entry, and both winner/loser ciphertexts survive (no data loss)
    let ops_a = repo_a.item_ops(item).await.unwrap();
    let ops_b = repo_b.item_ops(item).await.unwrap();
    assert_eq!(ops_a.len(), 3);
    assert_eq!(ops_b.len(), 3);
    let view_a = item_view(ops_a);
    let view_b = item_view(ops_b);
    let primary_a = view_a.primary.as_ref().unwrap();
    let primary_b = view_b.primary.as_ref().unwrap();
    assert_eq!(primary_a.op_id, primary_b.op_id);
    assert_eq!(primary_a.device_id, device_a.max(device_b)); // lexicographically larger wins
    assert_eq!(view_a.conflicts.len(), 1);
    assert_eq!(view_b.conflicts.len(), 1);
    assert_eq!(view_a.conflicts[0].op_id, view_b.conflicts[0].op_id);
    // Both version ciphertexts are readable and distinguishable (neither winner nor
    // loser is lost — the stored proof of no data loss)
    let primary_tag = primary_a.payload.as_ref().unwrap().ciphertext[0];
    let conflict_tag = view_a.conflicts[0].payload.as_ref().unwrap().ciphertext[0];
    assert_ne!(primary_tag, conflict_tag);

    task.abort();
}

// Real-TCP alignment test of the SyncAdminApi (core client wire layer) against the
// server contract: handler semantics are already covered by the unit tests above
// (409/422/cascade etc.); this verifies the client-side type conversions (device_id
// Uuid, public_key [u8;32], envelope bytes round-tripping verbatim) and the error
// paths (the 409 message propagates to Err, ghost devices fail closed).
#[tokio::test(flavor = "multi_thread")]
async fn admin_api_client_manages_devices_and_group_keys_over_real_tcp() {
    use persona_core::sync::remote::SyncAdminApi;

    const TOKEN: &str = "sync-admin-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");

    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

    // Register two devices
    let laptop_id = admin
        .register_device("laptop", &[7u8; 32])
        .await
        .expect("register laptop");
    let phone_id = admin
        .register_device("phone", &[9u8; 32])
        .await
        .expect("register phone");
    assert_ne!(laptop_id, phone_id);

    // Duplicate name -> 409, message propagates to Err (the client does not swallow
    // server semantics)
    let dup = admin
        .register_device("laptop", &[1u8; 32])
        .await
        .unwrap_err();
    assert!(
        dup.to_string().contains("already registered"),
        "unexpected error: {dup:#}"
    );

    // List: names + public keys restored byte-for-byte
    let devices = admin.list_devices().await.expect("list devices");
    assert_eq!(devices.len(), 2);
    let laptop = devices
        .iter()
        .find(|d| d.id == laptop_id)
        .expect("laptop in list");
    assert_eq!(laptop.device_name, "laptop");
    assert_eq!(laptop.public_key, [7u8; 32]);
    assert!(!laptop.created_at.is_empty());

    // No envelopes to start with
    assert!(admin.group_keys().await.expect("empty keys").is_empty());

    // Upload an envelope (exactly 80B) -> returned verbatim, sealed_by =
    // AuthTokens::single's device name
    let envelope: Vec<u8> = (0..80).map(|i| i as u8).collect();
    admin
        .put_group_key(laptop_id, &envelope)
        .await
        .expect("put group key");
    // Ghost device fails closed -> Err
    admin
        .put_group_key(Uuid::new_v4(), &[0u8; 80])
        .await
        .expect_err("ghost device must be rejected");
    // Same-device overwrite (upsert) does not error
    admin
        .put_group_key(laptop_id, &[0xAA; 80])
        .await
        .expect("overwrite group key");

    let keys = admin.group_keys().await.expect("group keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].device_id, laptop_id);
    assert_eq!(keys[0].envelope, vec![0xAA; 80]);
    assert_eq!(keys[0].sealed_by, "default");

    // Revoke laptop: idempotent (the second delete is also a 204) + envelope cascades away
    admin.delete_device(laptop_id).await.expect("revoke laptop");
    admin
        .delete_device(laptop_id)
        .await
        .expect("revoke laptop twice is idempotent");
    let devices = admin.list_devices().await.expect("list after revoke");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, phone_id);
    assert!(admin
        .group_keys()
        .await
        .expect("keys after revoke")
        .is_empty());

    task.abort();
}

// First-device bootstrap: on a fresh server nobody can authorize the first device to
// join (envelopes are sealed by an "existing device", and none exists yet) —
// bootstrap_group_if_empty creates the group key and seals its own envelope on an
// empty group; from the second device on, the normal "wait for an existing device to
// authorize" flow resumes. This is the prerequisite for the join flow to work on real
// hardware (step 1 of the phase 3 demo script).
#[tokio::test(flavor = "multi_thread")]
async fn admin_api_bootstrap_creates_group_on_fresh_server_and_second_device_still_pends() {
    use persona_core::sync::device::DeviceIdentity;
    use persona_core::sync::envelope::{open_group_key, seal_group_key};
    use persona_core::sync::remote::SyncAdminApi;

    const TOKEN: &str = "sync-bootstrap-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");

    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

    // First device: after registering, bootstraps the empty group -> true, and the
    // device itself can open its own envelope
    let laptop = DeviceIdentity::generate("laptop").unwrap();
    let laptop_id = admin
        .register_device("laptop", laptop.key_pair.public_bytes())
        .await
        .expect("register first device");
    let bootstrapped = admin
        .bootstrap_group_if_empty(laptop_id, laptop.key_pair.public_bytes())
        .await
        .expect("bootstrap on fresh server");
    assert!(bootstrapped);
    let keys = admin.group_keys().await.expect("keys after bootstrap");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].device_id, laptop_id);
    let group = open_group_key(&keys[0].envelope, laptop.key_pair.secret_bytes())
        .expect("own envelope opens");

    // Second device: the group is non-empty -> no bootstrap (false), waiting for the
    // first device to authorize
    let phone = DeviceIdentity::generate("phone").unwrap();
    let phone_id = admin
        .register_device("phone", phone.key_pair.public_bytes())
        .await
        .expect("register second device");
    let bootstrapped = admin
        .bootstrap_group_if_empty(phone_id, phone.key_pair.public_bytes())
        .await
        .expect("bootstrap on non-empty group");
    assert!(!bootstrapped);

    // First-device authorization on the second's behalf: open its own group key ->
    // seal a new envelope with the other's public key and upload it
    let envelope = seal_group_key(&group, phone.key_pair.public_bytes()).unwrap();
    admin
        .put_group_key(phone_id, &envelope)
        .await
        .expect("authorize phone");
    let keys = admin.group_keys().await.expect("keys after authorize");
    assert_eq!(keys.len(), 2);
    let phone_entry = keys.iter().find(|k| k.device_id == phone_id).unwrap();
    let group_phone = open_group_key(&phone_entry.envelope, phone.key_pair.secret_bytes())
        .expect("phone opens its envelope");
    assert_eq!(group, group_phone, "both devices hold the same group key");

    task.abort();
}

// Full group-key rotation flow (real TCP, phase 3d): A bootstraps the group and
// authorizes B -> A rotates (new envelopes + full re-wrap) -> the envelope set still
// covers exactly the two authorized devices and both open the **new** key; then B and
// the late-joining C each open a session and pull everything — all re-wrapped ops are
// readable and materialize (the old-key batch is ignored as "strictly older versions",
// and the current state is filled in by the re-wrapped ops).
#[tokio::test(flavor = "multi_thread")]
async fn rotate_group_key_swaps_envelopes_and_new_devices_read_rewrapped_ops() {
    use persona_core::crypto::encryption::EncryptionService;
    use persona_core::crypto::key_hierarchy::KeyHierarchy;
    use persona_core::models::credential::{
        Credential, CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
    };
    use persona_core::models::identity::{Identity, IdentityType};
    use persona_core::storage::repository::IdentityRepository;
    use persona_core::storage::{CredentialRepository, Database, Repository};
    use persona_core::sync::device::DeviceIdentity;
    use persona_core::sync::envelope::{open_group_key, seal_group_key};
    use persona_core::sync::remote::SyncAdminApi;
    use persona_core::sync::runtime::SyncSession;

    const TOKEN: &str = "sync-rotate-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");
    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

    // A bootstraps the group; B is authorized (old group-key envelope). After
    // registration, with_device_id backfills the server-assigned UUID (the same
    // order as the desktop's sync_join).
    let dev_a = DeviceIdentity::generate("rotator-a").unwrap();
    let id_a = admin
        .register_device("rotator-a", dev_a.key_pair.public_bytes())
        .await
        .expect("register A");
    let dev_a = dev_a.with_device_id(id_a);
    assert!(admin
        .bootstrap_group_if_empty(id_a, dev_a.key_pair.public_bytes())
        .await
        .expect("bootstrap A"));
    let group_old = open_group_key(
        &admin.group_keys().await.unwrap()[0].envelope,
        dev_a.key_pair.secret_bytes(),
    )
    .expect("A opens own envelope");

    let dev_b = DeviceIdentity::generate("member-b").unwrap();
    let id_b = admin
        .register_device("member-b", dev_b.key_pair.public_bytes())
        .await
        .expect("register B");
    let dev_b = dev_b.with_device_id(id_b);
    admin
        .put_group_key(
            id_b,
            &seal_group_key(&group_old, dev_b.key_pair.public_bytes()).unwrap(),
        )
        .await
        .expect("authorize B");

    // A's local library: two credentials + a real session (HttpSyncRemote)
    let db_a = Database::in_memory().await.unwrap();
    db_a.migrate().await.unwrap();
    let owner = Identity::new("seed".to_string(), IdentityType::Personal);
    IdentityRepository::new(db_a.clone())
        .create(&owner)
        .await
        .unwrap();
    let master_a = EncryptionService::new(&EncryptionService::generate_key());
    let cred_repo = CredentialRepository::new(db_a.clone());
    for (name, secret) in [("cred-one", "one"), ("cred-two", "two")] {
        let item_key = EncryptionService::generate_key();
        let wrapped = master_a.encrypt(&item_key).unwrap();
        let plaintext = CredentialData::Password(PasswordCredentialData {
            password: secret.to_string(),
            email: None,
            security_questions: vec![],
        })
        .to_bytes()
        .unwrap();
        let ciphertext = KeyHierarchy::new(&master_a)
            .encrypt_with_item_key(&item_key, &plaintext)
            .unwrap();
        cred_repo
            .create(&Credential::new(
                owner.id,
                name.to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                ciphertext,
                Some(wrapped),
            ))
            .await
            .unwrap();
    }

    let session_a = SyncSession::open(&db_a, &dev_a, &base, TOKEN, Box::new(|| false))
        .await
        .expect("session A");
    assert_eq!(session_a.backfill_existing(&master_a).await.unwrap(), 2);

    // Rotation: leading drain (the old-key batch of 2) + re-wrap (2 ops) + trailing drain
    let report = session_a.rotate_group_key(&master_a, &admin).await.unwrap();
    assert_eq!((report.rewrapped, report.skipped), (2, 0));
    assert_eq!(report.pushed, 4);

    // Envelope set: still exactly the two authorized devices, and both open the
    // **new** key (different from the old key)
    let keys = admin.group_keys().await.unwrap();
    assert_eq!(keys.len(), 2);
    let group_new = open_group_key(
        &keys.iter().find(|k| k.device_id == id_a).unwrap().envelope,
        dev_a.key_pair.secret_bytes(),
    )
    .expect("A opens rotated envelope");
    let group_new_b = open_group_key(
        &keys.iter().find(|k| k.device_id == id_b).unwrap().envelope,
        dev_b.key_pair.secret_bytes(),
    )
    .expect("B opens rotated envelope");
    assert_eq!(group_new, group_new_b);
    assert_ne!(group_new, group_old);

    // B (session opened after rotation -> holds only the new key) pulls everything:
    // all re-wrapped ops materialize
    let (db_b, master_b) = member_db(owner.id).await;
    let session_b = SyncSession::open(&db_b, &dev_b, &base, TOKEN, Box::new(|| false))
        .await
        .expect("session B");
    let report_b = session_b.run_cycle(&master_b).await.unwrap();
    assert_eq!(report_b.pulled, 4);
    assert_eq!(report_b.materialized, 2);
    assert_eq!(report_b.conflicts, 0);
    assert_eq!(report_b.pending_identity, 0);
    assert_stored_credentials(&db_b, &master_b).await;

    // Late-joining C: authorized with the new key, pulls everything and it is all
    // readable too
    let dev_c = DeviceIdentity::generate("late-c").unwrap();
    let id_c = admin
        .register_device("late-c", dev_c.key_pair.public_bytes())
        .await
        .expect("register C");
    let dev_c = dev_c.with_device_id(id_c);
    admin
        .put_group_key(
            id_c,
            &seal_group_key(&group_new, dev_c.key_pair.public_bytes()).unwrap(),
        )
        .await
        .expect("authorize C");
    let (db_c, master_c) = member_db(owner.id).await;
    let session_c = SyncSession::open(&db_c, &dev_c, &base, TOKEN, Box::new(|| false))
        .await
        .expect("session C");
    let report_c = session_c.run_cycle(&master_c).await.unwrap();
    assert_eq!(report_c.pulled, 4);
    assert_eq!(report_c.materialized, 2);
    assert_stored_credentials(&db_c, &master_c).await;

    task.abort();
}

/// Crashing mid-rotation -> retrying re-runs it and self-heals (E2EE_SYNC_DESIGN §11-2
/// closeout): simulate "begin wins the mutex + crashes after writing a new envelope for
/// only one device" — the envelope family is left in a mixed state (A opens the crashed
/// round's key, B still has the old envelope). After restart, a full rotate_group_key
/// re-reads the epoch and re-runs: the crashed round's leftover envelope is overwritten
/// by the retry round's new envelope (envelope rows do not grow), the epoch counts two
/// begins, and the whole group (B pulls everything) converges and is solvable — the
/// crashed round's re-wrap never existed (it never happened), the leftover only affects
/// envelopes, and being idempotently overwritten by the upsert is the self-heal.
#[tokio::test(flavor = "multi_thread")]
async fn crashed_mid_rotation_retry_rewrites_envelopes_and_converges() {
    use persona_core::crypto::encryption::EncryptionService;
    use persona_core::crypto::key_hierarchy::KeyHierarchy;
    use persona_core::models::credential::{
        Credential, CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
    };
    use persona_core::models::identity::{Identity, IdentityType};
    use persona_core::storage::repository::IdentityRepository;
    use persona_core::storage::{CredentialRepository, Database, Repository};
    use persona_core::sync::device::DeviceIdentity;
    use persona_core::sync::envelope::{open_group_key, seal_group_key};
    use persona_core::sync::keys::GroupKey;
    use persona_core::sync::remote::SyncAdminApi;
    use persona_core::sync::runtime::SyncSession;

    const TOKEN: &str = "sync-rotate-crash-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");
    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

    // A bootstraps the group + authorizes B (isomorphic to the existing rotate
    // full-flow test)
    let dev_a = DeviceIdentity::generate("crashy-a").unwrap();
    let id_a = admin
        .register_device("crashy-a", dev_a.key_pair.public_bytes())
        .await
        .unwrap();
    let dev_a = dev_a.with_device_id(id_a);
    assert!(admin
        .bootstrap_group_if_empty(id_a, dev_a.key_pair.public_bytes())
        .await
        .unwrap());
    let group_old = open_group_key(
        &admin.group_keys().await.unwrap()[0].envelope,
        dev_a.key_pair.secret_bytes(),
    )
    .unwrap();

    let dev_b = DeviceIdentity::generate("survivor-b").unwrap();
    let id_b = admin
        .register_device("survivor-b", dev_b.key_pair.public_bytes())
        .await
        .unwrap();
    let dev_b = dev_b.with_device_id(id_b);
    admin
        .put_group_key(
            id_b,
            &seal_group_key(&group_old, dev_b.key_pair.public_bytes()).unwrap(),
        )
        .await
        .unwrap();

    // A's local library: two credentials + backfill accounted
    let db_a = Database::in_memory().await.unwrap();
    db_a.migrate().await.unwrap();
    let owner = Identity::new("seed".to_string(), IdentityType::Personal);
    IdentityRepository::new(db_a.clone())
        .create(&owner)
        .await
        .unwrap();
    let master_a = EncryptionService::new(&EncryptionService::generate_key());
    let cred_repo = CredentialRepository::new(db_a.clone());
    for (name, secret) in [("cred-one", "one"), ("cred-two", "two")] {
        let item_key = EncryptionService::generate_key();
        let wrapped = master_a.encrypt(&item_key).unwrap();
        let plaintext = CredentialData::Password(PasswordCredentialData {
            password: secret.to_string(),
            email: None,
            security_questions: vec![],
        })
        .to_bytes()
        .unwrap();
        let ciphertext = KeyHierarchy::new(&master_a)
            .encrypt_with_item_key(&item_key, &plaintext)
            .unwrap();
        cred_repo
            .create(&Credential::new(
                owner.id,
                name.to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                ciphertext,
                Some(wrapped),
            ))
            .await
            .unwrap();
    }
    let session_a = SyncSession::open(&db_a, &dev_a, &base, TOKEN, Box::new(|| false))
        .await
        .unwrap();
    assert_eq!(session_a.backfill_existing(&master_a).await.unwrap(), 2);

    // ---- Simulate a mid-crash: begin wins the mutex, writes a new envelope for A
    // only, then "crashes" ----
    let (keys, epoch) = admin.group_keys_with_epoch().await.unwrap();
    assert_eq!(epoch, 0);
    let authorized: std::collections::HashSet<Uuid> = keys.iter().map(|k| k.device_id).collect();
    assert_eq!(authorized.len(), 2);
    admin.begin_group_rotation(epoch).await.unwrap();
    let crashed_key = GroupKey::generate().unwrap();
    admin
        .put_group_key(
            id_a,
            &seal_group_key(crashed_key.as_bytes(), dev_a.key_pair.public_bytes()).unwrap(),
        )
        .await
        .unwrap();
    // The mixed state is visible: A's envelope now holds the crashed round's key, B's
    // envelope still holds the old key
    assert_ne!(
        open_group_key(
            &admin
                .group_keys()
                .await
                .unwrap()
                .iter()
                .find(|k| k.device_id == id_a)
                .unwrap()
                .envelope,
            dev_a.key_pair.secret_bytes()
        )
        .unwrap(),
        group_old
    );

    // ---- Retry after restart: a full rotate_group_key re-run self-heals ----
    let report = session_a.rotate_group_key(&master_a, &admin).await.unwrap();
    assert_eq!((report.rewrapped, report.skipped), (2, 0));
    assert_eq!(report.pushed, 4);

    // Envelope rows do not grow (still exactly the two authorized devices); both
    // devices open the retry round's key — neither the old key nor the crashed
    // round's key (the leftover envelope was overwritten by the upsert)
    let keys_after = admin.group_keys().await.unwrap();
    assert_eq!(keys_after.len(), 2);
    let retried_key_a = open_group_key(
        &keys_after
            .iter()
            .find(|k| k.device_id == id_a)
            .unwrap()
            .envelope,
        dev_a.key_pair.secret_bytes(),
    )
    .unwrap();
    let retried_key_b = open_group_key(
        &keys_after
            .iter()
            .find(|k| k.device_id == id_b)
            .unwrap()
            .envelope,
        dev_b.key_pair.secret_bytes(),
    )
    .unwrap();
    assert_eq!(retried_key_a, retried_key_b);
    assert_ne!(retried_key_a, group_old);
    assert_ne!(retried_key_a, *crashed_key.as_bytes());

    // The epoch counts two begins in total (crashed halfway +1, retry +1)
    let (_, epoch_after) = admin.group_keys_with_epoch().await.unwrap();
    assert_eq!(epoch_after, 2);

    // Whole-group convergence: B opens a fresh session (opens the retry round's key)
    // and pulls everything; all re-wrapped ops materialize
    let (db_b, master_b) = member_db(owner.id).await;
    let session_b = SyncSession::open(&db_b, &dev_b, &base, TOKEN, Box::new(|| false))
        .await
        .unwrap();
    let report_b = session_b.run_cycle(&master_b).await.unwrap();
    assert_eq!(report_b.pulled, 4);
    assert_eq!(report_b.materialized, 2);
    assert_eq!(report_b.conflicts, 0);
    assert_stored_credentials(&db_b, &master_b).await;

    task.abort();
}

// Device revocation closure (real TCP): the same-named SRP enrollment cascades with
// the sync device's revocation — existing short-term tokens become invalid
// **immediately** (not waiting out the 15-minute TTL), and re-login is refused (a 401
// indistinguishable from unregistered); revocation is idempotent. The THREAT_MODEL
// "SRP device authentication endpoint" known limitation "auth_devices has no delete
// path" is closed by this route.
#[tokio::test(flavor = "multi_thread")]
async fn revoked_sync_device_loses_srp_access_and_outstanding_tokens() {
    use persona_core::auth::remote_http::HttpRemoteAuthProvider;
    use persona_core::sync::remote::SyncAdminApi;

    const TOKEN: &str = "sync-revoke-closure-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");

    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();
    let id = admin
        .register_device("laptop", &[7u8; 32])
        .await
        .expect("register sync device");

    // Same-named SRP enrollment + login to obtain a short-term token
    let provider = HttpRemoteAuthProvider::new(base.clone()).unwrap();
    provider
        .register_device(TOKEN, "laptop", "pw-for-device")
        .await
        .expect("SRP enroll");
    let outcome = provider
        .begin_login("laptop")
        .await
        .unwrap()
        .finish("pw-for-device")
        .await
        .expect("SRP login");

    // The token works: it passes require_bearer and reaches the sync endpoint
    let client = reqwest::Client::new();
    let probe = client
        .get(format!("{base}/api/v1/sync/devices"))
        .bearer_auth(&outcome.token)
        .send()
        .await
        .unwrap();
    assert_eq!(probe.status(), StatusCode::OK, "{probe:?}");

    // Revoke the sync device: cascades the SRP row away + revokes in-memory tokens
    // immediately
    admin.delete_device(id).await.expect("revoke");

    // The existing token is 401 immediately (no waiting for the TTL)
    let probe = client
        .get(format!("{base}/api/v1/sync/devices"))
        .bearer_auth(&outcome.token)
        .send()
        .await
        .unwrap();
    assert_eq!(probe.status(), StatusCode::UNAUTHORIZED, "{probe:?}");
    // Re-login via SRP is 401 (the enrollment row is gone — the challenge is 401
    // shaped the same as unregistered, and a failure at any step of the login chain
    // counts as the closure holding)
    let err = match provider.begin_login("laptop").await {
        Ok(handle) => handle
            .finish("pw-for-device")
            .await
            .err()
            .map(|e| e.to_string()),
        Err(e) => Some(e.to_string()),
    };
    let err = err.expect("login must fail after revocation");
    assert!(err.contains("HTTP 401"), "{err}");
    // A second revocation is idempotent
    admin.delete_device(id).await.expect("revoke twice");

    task.abort();
}
