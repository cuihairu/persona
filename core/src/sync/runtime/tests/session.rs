//! 会话装配/backfill/run_cycle 域测试（含双设备收敛 SharedRemote 系私有 helper）。

use super::*;

/// 完整语义内存远端（pull 游标与 server 同构、支持库级快照存取），
/// 双设备收敛等价性集成测试用。
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

// 双设备收敛等价性（S2 集成测试）：A 全量产出 → 手动打包上传快照 →
// B（空库新设备）run_cycle 装快照起步 → B 主库与 A 逐行一致、B 不
// 重复物化 A 的增量（游标在覆盖位点）。
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

    // A 手动打包上传（阈值 1000 不触发，集成路径直接驱动）。打包回调在
    // 引擎收敛之后执行——快照内容与覆盖水位同取收敛后的一致视图。
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

    // B：空库、同组密钥、不同 master —— run_cycle 应先装快照再物化
    let db_b = Database::in_memory().await.unwrap();
    db_b.migrate().await.unwrap();
    let master_b = EncryptionService::new(&EncryptionService::generate_key());
    // 身份行是设备本地可预置事实（配对流程已建）；走同步链的只有凭据 op
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

    // B 的游标推到覆盖位点：再次 pull 只拿到空增量
    let watermark = SyncRepository::new(db_b.clone())
        .local_watermark()
        .await
        .unwrap();
    assert_eq!(watermark, 2);
}

// 深审 Critical 回归（2026-11-13）：快照打包必须在收敛（push/pull）之后。
// 并发设备在打包前推上服务器的新 op 会进上传时的收敛 pull 与覆盖水位，
// 若不在快照密文里就被服务器 `seq ≤ S` 裁剪——restore 永久丢该 op。
// 老签名（先打包密文再上传）正是这个顺序；现签名把打包钉在收敛后。
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

    // 并发设备 C 在 A 打包前把一条新 op 推上远端
    let (db_c, identity_c, master_c) = seeded_db().await;
    let cred_c = CredentialRepository::new(db_c.clone());
    store_credential(&cred_c, identity_c.id, "gamma", &master_c, "s3").await;
    let session_c = shared_session(&db_c, Uuid::new_v4(), group.clone(), remote.clone());
    session_c.backfill_existing(&master_c).await.unwrap();
    session_c.run_cycle(&master_c).await.unwrap();
    assert_eq!(remote.state.lock().unwrap().ops.len(), 2);

    // A 上传快照：打包回调此时必须已看到收敛 pull 拉进的 gamma op，
    // 否则服务器按水位裁剪后 gamma 既不在快照也不在 oplog。
    let (seq, _) = session_a
        .engine
        .upload_library_snapshot(|| async {
            let payload = session_a.snapshot_payload().await.unwrap();
            assert_eq!(payload.ops.len(), 2, "gamma 必须在快照密文里（收敛后打包）");
            payload.seal(&group)
        })
        .await
        .unwrap();

    // 上传的密文可解且含 gamma；覆盖位点 = 收敛后的 head
    let (_, sealed) = remote.state.lock().unwrap().snapshot.clone().unwrap();
    let payload = LibrarySnapshotPayload::open(&sealed, &group).unwrap();
    assert_eq!(payload.ops.len(), 2);
    assert_eq!(seq, 2, "覆盖位点 = 收敛后的水位");
}

// 会话编排核心：backfill 幂等（首次灌入 N 条，再跑 0 条）+ run_cycle
// 把本地 pending 推上远端 + capture 产出的 put 随下一轮周期推走。
#[tokio::test]
async fn session_backfills_pushes_and_captures() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());
    store_credential(&cred_repo, identity.id, "cred-one", &master, "one").await;
    store_credential(&cred_repo, identity.id, "cred-two", &master, "two").await;

    let (session, pushed_log) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());

    // 首次灌入 2 条，重复调用幂等（0 条）
    let first = session.backfill_existing(&master).await.unwrap();
    assert_eq!(first, 2);
    let second = session.backfill_existing(&master).await.unwrap();
    assert_eq!(second, 0);

    // 周期推走 2 条 pending
    let report = session.run_cycle(&master).await.unwrap();
    assert_eq!(report.pushed, 2);
    assert_eq!(report.pulled, 0);
    assert_eq!(report.backfilled, 0);

    // capture 产出的新 put 随下一轮周期推走（capture 持 engine Arc，
    // 与 run_cycle 共享同一 pending 队列）
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

// legacy 凭据（无 wrapped_item_key）：backfill 跳过不报错
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

/// backfill 对坏行逐条跳过不阻断：unwrap 失败、密文坏、明文非
/// CredentialData 三种损坏各一条，全部 skip（返回 0，远端零推送）。
#[tokio::test]
async fn backfill_skips_corrupt_credentials_one_by_one() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());

    // wrapped key 是垃圾字节 → item key unwrap 失败
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

    // wrapped 合法但密文坏 → credential decrypt 失败
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

    // 可解密但明文不是 CredentialData → from_bytes 失败
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

// open 的密码学半步：坏信封 fail-closed
#[cfg(feature = "remote-auth")]
#[test]
fn open_own_envelope_rejects_malformed() {
    let identity = DeviceIdentity::generate("d").unwrap();
    assert!(
        crate::sync::envelope::open_group_key(b"short", identity.key_pair.secret_bytes()).is_err()
    );
    // 80B 但不是包给这把私钥的（随机字节）——认证必失败
    assert!(
        crate::sync::envelope::open_group_key(&[0x5Au8; 80], identity.key_pair.secret_bytes())
            .is_err()
    );
}

/// run_cycle 报告的 conflicts 是待裁决条目数（真值），不是 3b 误用的
/// 「本机主位跳过计数」：灌入一条冲突后跑周期，报告 conflicts == 1。
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
    // 物化主位落库（远端内容），裁决等用户
    assert_eq!(report.materialized, 1);
}
