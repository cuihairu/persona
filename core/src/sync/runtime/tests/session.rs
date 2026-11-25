//! Session assembly / backfill / run_cycle domain tests (includes the
//! SharedRemote family of private helpers for two-device convergence).

use super::*;

/// Fully semantic in-memory remote (its pull cursor is isomorphic to the
/// server's, and it supports library snapshot storage), for the two-device
/// convergence equivalence integration tests.
#[derive(Clone)]
struct SharedRemote {
    state: Arc<Mutex<SharedState>>,
}

struct SharedState {
    ops: Vec<SyncOp>,
    snapshot: Option<(i64, Vec<u8>)>,
}

#[async_trait::async_trait]
impl SyncRemote for SharedRemote {
    async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
        let mut state = self.state.lock().unwrap();
        let existing: std::collections::HashSet<Uuid> =
            state.ops.iter().map(|op| op.op_id).collect();
        let accepted = ops
            .iter()
            .filter(|op| !existing.contains(&op.op_id))
            .count() as u64;
        state.ops.extend(ops.iter().cloned());
        Ok((accepted, ops.len() as u64 - accepted))
    }

    async fn pull_ops(
        &self,
        since: Option<&str>,
        limit: u32,
    ) -> Result<(Vec<SyncOp>, Option<String>)> {
        let state = self.state.lock().unwrap();
        let start = match since {
            Some(raw) => crate::sync::cursor::decode_cursor(raw)
                .map(|(seq, _)| seq as usize)
                .unwrap_or(0),
            None => 0,
        };
        let total = state.ops.len();
        let end = start.saturating_add(limit as usize).min(total);
        let page = state.ops[start.min(total)..end].to_vec();
        let next = (end > start).then(|| {
            crate::sync::cursor::encode_cursor(end as i64, &state.ops[end - 1].op_id.to_string())
        });
        Ok((page, next))
    }

    async fn head_seq(&self) -> Result<i64> {
        Ok(self.state.lock().unwrap().ops.len() as i64)
    }

    async fn put_library_snapshot(
        &self,
        seq: i64,
        _device_id: &str,
        ciphertext: &[u8],
    ) -> Result<u64> {
        let mut state = self.state.lock().unwrap();
        let pruned = (seq as usize).min(state.ops.len()) as u64;
        state.snapshot = Some((seq, ciphertext.to_vec()));
        Ok(pruned)
    }

    async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
        Ok(self.state.lock().unwrap().snapshot.clone())
    }
}

fn shared_session(
    db: &Database,
    device_id: Uuid,
    group_key: GroupKey,
    remote: SharedRemote,
) -> SyncSession<SharedRemote> {
    SyncSession {
        engine: Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            remote,
            device_id,
            no_travel(),
        )),
        sync_repo: SyncRepository::new(db.clone()),
        db: db.clone(),
        group_key,
        device_id,
    }
}

// Two-device convergence equivalence (S2 integration test): A produces a
// full set -> manually packs and uploads a snapshot -> B (an empty-database
// new device) bootstraps from the snapshot via run_cycle -> B's master
// database matches A row by row, and B does not re-materialize A's delta
// (the cursor sits at the overwrite position).
#[tokio::test]
async fn snapshot_bootstrap_converges_like_full_replay() {
    let (db_a, identity_a, master_a) = seeded_db().await;
    let cred_a = CredentialRepository::new(db_a.clone());
    store_credential(&cred_a, identity_a.id, "alpha", &master_a, "s1").await;
    store_credential(&cred_a, identity_a.id, "beta", &master_a, "s2").await;

    let group = GroupKey::generate().unwrap();
    let remote = SharedRemote {
        state: Arc::new(Mutex::new(SharedState {
            ops: Vec::new(),
            snapshot: None,
        })),
    };
    let session_a = shared_session(&db_a, Uuid::new_v4(), group.clone(), remote.clone());
    session_a.backfill_existing(&master_a).await.unwrap();
    session_a.run_cycle(&master_a).await.unwrap();

    // A manually packs and uploads (the 1000 threshold does not fire; the
    // integration path drives it directly). The packing callback runs after
    // the engine converges -- the snapshot content and the overwrite
    // watermark both read from the same post-convergence view.
    let (seq, _) = session_a
        .engine
        .upload_library_snapshot(|| async {
            let payload = session_a.snapshot_payload().await.unwrap();
            assert_eq!(payload.ops.len(), 2);
            payload.seal(&group)
        })
        .await
        .unwrap();
    assert_eq!(seq, 2, "覆盖位点 = 已推平水位");

    // B: empty database, same group key, different master -- run_cycle should
    // install the snapshot first, then materialize
    let db_b = Database::in_memory().await.unwrap();
    db_b.migrate().await.unwrap();
    let master_b = EncryptionService::new(&EncryptionService::generate_key());
    // The identity row is a locally pre-seedable device fact (the pairing
    // flow already created it); only credential ops go through the sync
    // chain
    IdentityRepository::new(db_b.clone())
        .create(&Identity {
            id: identity_a.id,
            ..Identity::new("seed".to_string(), IdentityType::Personal)
        })
        .await
        .unwrap();
    let session_b = shared_session(&db_b, Uuid::new_v4(), group, remote.clone());
    session_b.run_cycle(&master_b).await.unwrap();

    let cred_b = CredentialRepository::new(db_b.clone());
    let mut names: Vec<String> = cred_b
        .list_all()
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    names.sort();
    assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);

    // B's cursor has advanced to the overwrite position: a further pull
    // yields an empty delta only
    let watermark = SyncRepository::new(db_b.clone())
        .local_watermark()
        .await
        .unwrap();
    assert_eq!(watermark, 2);
}

// Deep-review Critical regression (2026-11-13): snapshot packing must happen
// after convergence (push/pull).
// A new op that a concurrent device pushes to the server before packing will
// enter the convergence pull and the overwrite watermark at upload time; if
// it is not inside the snapshot ciphertext, the server prunes it by
// `seq <= S` -- restore loses that op permanently.
// The old signature (pack the ciphertext first, then upload) had exactly
// that order; the current signature pins packing to after convergence.
#[tokio::test]
async fn snapshot_upload_packs_after_convergence() {
    let (db_a, identity_a, master_a) = seeded_db().await;
    let cred_a = CredentialRepository::new(db_a.clone());
    store_credential(&cred_a, identity_a.id, "alpha", &master_a, "s1").await;

    let group = GroupKey::generate().unwrap();
    let remote = SharedRemote {
        state: Arc::new(Mutex::new(SharedState {
            ops: Vec::new(),
            snapshot: None,
        })),
    };
    let session_a = shared_session(&db_a, Uuid::new_v4(), group.clone(), remote.clone());
    session_a.backfill_existing(&master_a).await.unwrap();
    session_a.run_cycle(&master_a).await.unwrap();

    // Concurrent device C pushes a new op to the remote before A packs
    let (db_c, identity_c, master_c) = seeded_db().await;
    let cred_c = CredentialRepository::new(db_c.clone());
    store_credential(&cred_c, identity_c.id, "gamma", &master_c, "s3").await;
    let session_c = shared_session(&db_c, Uuid::new_v4(), group.clone(), remote.clone());
    session_c.backfill_existing(&master_c).await.unwrap();
    session_c.run_cycle(&master_c).await.unwrap();
    assert_eq!(remote.state.lock().unwrap().ops.len(), 2);

    // A uploads the snapshot: the packing callback must by now have seen the
    // gamma op pulled in by the convergence pull, otherwise after the server
    // prunes by watermark, gamma is in neither the snapshot nor the oplog.
    let (seq, _) = session_a
        .engine
        .upload_library_snapshot(|| async {
            let payload = session_a.snapshot_payload().await.unwrap();
            assert_eq!(payload.ops.len(), 2, "gamma 必须在快照密文里（收敛后打包）");
            payload.seal(&group)
        })
        .await
        .unwrap();

    // The uploaded ciphertext opens and contains gamma; the overwrite
    // position = the post-convergence head
    let (_, sealed) = remote.state.lock().unwrap().snapshot.clone().unwrap();
    let payload = LibrarySnapshotPayload::open(&sealed, &group).unwrap();
    assert_eq!(payload.ops.len(), 2);
    assert_eq!(seq, 2, "覆盖位点 = 收敛后的水位");
}

// Session orchestration core: backfill is idempotent (N entries seeded on
// the first run, 0 on a rerun) + run_cycle pushes local pending entries to
// the remote + a put produced by capture goes out with the next cycle.
#[tokio::test]
async fn session_backfills_pushes_and_captures() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());
    store_credential(&cred_repo, identity.id, "cred-one", &master, "one").await;
    store_credential(&cred_repo, identity.id, "cred-two", &master, "two").await;

    let (session, pushed_log) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());

    // First run seeds 2 entries; a repeated call is idempotent (0 entries)
    let first = session.backfill_existing(&master).await.unwrap();
    assert_eq!(first, 2);
    let second = session.backfill_existing(&master).await.unwrap();
    assert_eq!(second, 0);

    // The cycle pushes out the 2 pending entries
    let report = session.run_cycle(&master).await.unwrap();
    assert_eq!(report.pushed, 2);
    assert_eq!(report.pulled, 0);
    assert_eq!(report.backfilled, 0);

    // A new put produced by capture goes out with the next cycle (capture
    // holds the engine Arc and shares the same pending queue with
    // run_cycle)
    let capture = session.capture();
    let item_key = EncryptionService::generate_key();
    let sealed = SyncItemSnapshot::from_credential(
        &Credential::new(
            identity.id,
            "fresh".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            Vec::new(),
            None,
        ),
        &data("fresh-secret"),
    )
    .seal(&item_key)
    .unwrap();
    capture
        .capture(
            Uuid::new_v4(),
            ItemKind::Credential,
            OpType::Put,
            Some(sealed),
            Some(Zeroizing::new(item_key)),
        )
        .await;
    let report = session.run_cycle(&master).await.unwrap();
    assert_eq!(report.pushed, 1);
    assert_eq!(pushed_log.lock().unwrap().len(), 3);
}

// Legacy credentials (no wrapped_item_key): backfill skips them without
// erroring
#[tokio::test]
async fn backfill_skips_legacy_credentials() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());
    store_credential(&cred_repo, identity.id, "modern", &master, "secret").await;
    let legacy = Credential::new(
        identity.id,
        "legacy".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        master.encrypt(b"legacy-bytes").unwrap(),
        None,
    );
    cred_repo.create(&legacy).await.unwrap();

    let (session, _) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());
    let count = session.backfill_existing(&master).await.unwrap();
    assert_eq!(count, 1, "legacy 行跳过，modern 行灌入");
}

/// backfill skips bad rows one by one without blocking: one row each for
/// unwrap failure, corrupt ciphertext, and plaintext that is not
/// CredentialData -- all skipped (returns 0, nothing pushed to the remote).
#[tokio::test]
async fn backfill_skips_corrupt_credentials_one_by_one() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());

    // The wrapped key is junk bytes -> item key unwrap fails
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-unwrap".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1, 2, 3],
            Some(vec![9; 48]),
        ))
        .await
        .unwrap();

    // The wrapped key is valid but the ciphertext is corrupt -> credential
    // decrypt fails
    let item_key = EncryptionService::generate_key();
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-ciphertext".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![7; 64],
            Some(master.encrypt(&item_key).unwrap()),
        ))
        .await
        .unwrap();

    // Decryptable but the plaintext is not CredentialData -> from_bytes
    // fails
    let ciphertext = KeyHierarchy::new(&master)
        .encrypt_with_item_key(&item_key, b"not credential data")
        .unwrap();
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-data".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            ciphertext,
            Some(master.encrypt(&item_key).unwrap()),
        ))
        .await
        .unwrap();

    let (session, pushed_log) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());
    let count = session.backfill_existing(&master).await.unwrap();
    assert_eq!(count, 0, "三条坏行全部跳过");
    assert!(pushed_log.lock().unwrap().is_empty());
}

// The cryptographic half-step of open: a bad envelope fails closed
#[cfg(feature = "remote-auth")]
#[test]
fn open_own_envelope_rejects_malformed() {
    let identity = DeviceIdentity::generate("d").unwrap();
    assert!(
        crate::sync::envelope::open_group_key(b"short", identity.key_pair.secret_bytes()).is_err()
    );
    // 80B but not wrapped for this private key (random bytes) --
    // authentication must fail
    assert!(
        crate::sync::envelope::open_group_key(&[0x5Au8; 80], identity.key_pair.secret_bytes())
            .is_err()
    );
}

/// The `conflicts` reported by run_cycle is the count of pending resolution
/// entries (the truth), not the phase-3b misuse of "local primary-position
/// skip count": seed one conflict, run a cycle, and the report says
/// conflicts == 1.
#[tokio::test]
async fn run_cycle_reports_conflict_count_truth() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let (primary, copy) = seeded_conflict(item, &group, identity.id);
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&primary).await.unwrap();
    sync_repo.record_remote_op(&copy).await.unwrap();

    let (session, _) = session_for(&db, Uuid::new_v4(), group);
    let report = session.run_cycle(&master).await.unwrap();
    assert_eq!(report.conflicts, 1);
    // The master position is materialized into the database (the remote's
    // content); the resolution waits for the user
    assert_eq!(report.materialized, 1);
}
