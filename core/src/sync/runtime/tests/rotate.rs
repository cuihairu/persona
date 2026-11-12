//! group key 轮换/重包域测试。

use super::*;

// 轮换核心（重包半边）：rewrap_all 把主库全部凭据以新组密钥重新
// 入账——新 op 的 item key 信封只有新组密钥拆得开、快照开封内容
// 与原凭据一致、lamport 严格递增（LWW 使其成为新主位）。
// drain_push_queue 只在 remote-auth feature 下存在，测试同 gate。
#[cfg(feature = "remote-auth")]
#[tokio::test]
async fn rewrap_all_reseals_every_credential_with_new_group_key() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());
    store_credential(&cred_repo, identity.id, "cred-one", &master, "one").await;
    store_credential(&cred_repo, identity.id, "cred-two", &master, "two").await;

    let old_group = GroupKey::generate().unwrap();
    let (session, pushed_log) = session_for(&db, Uuid::new_v4(), old_group.clone());
    assert_eq!(session.backfill_existing(&master).await.unwrap(), 2);

    let new_group = GroupKey::generate().unwrap();
    let (rewrapped, skipped) = session.rewrap_all(&master, &new_group).await.unwrap();
    assert_eq!((rewrapped, skipped), (2, 0));

    // drain 后远端共收 4 条：backfill 2 条（旧 key 封）+ 重包 2 条（新 key 封）
    let drained = session.drain_push_queue().await.unwrap();
    assert_eq!(drained, 4);
    let pushed = pushed_log.lock().unwrap();
    assert_eq!(pushed.len(), 4);
    assert_eq!(pushed.len(), 4);
    let (older, newer) = pushed.split_at(2);
    // 新批次 lamport 严格大于旧批次（全序递增）
    assert!(newer.iter().all(|op| op.lamport > older[0].lamport));

    for op in newer {
        let payload = op.payload.as_ref().unwrap();
        // 只有新组密钥拆得开 item key 信封
        let item_key =
            crate::sync::keys::unwrap_item_key_with_group(&payload.wrapped_item_key, &new_group)
                .unwrap();
        let snapshot = SyncItemSnapshot::open(&payload.ciphertext, &item_key).unwrap();
        let expected = if snapshot.name == "cred-one" {
            "one"
        } else {
            "two"
        };
        let opened = match &snapshot.data {
            CredentialData::Password(p) => p.password.clone(),
            #[allow(unreachable_patterns)]
            _ => String::new(),
        };
        assert_eq!(opened, expected);
        // 旧组密钥拆不开新批次（前向边界：被吊销设备持旧 key 读不到）
        assert!(crate::sync::keys::unwrap_item_key_with_group(
            &payload.wrapped_item_key,
            &old_group
        )
        .is_err());
    }
}

// 轮换的 admin 侧失败必须零副作用：时钟不推进、pending 无新增——
// 失败发生在信封重封之前，本地 oplog 未被触碰。
// rotate_group_key/SyncAdminApi 只在 remote-auth feature 下存在，同 gate。
#[cfg(feature = "remote-auth")]
#[tokio::test]
async fn rotate_with_failing_admin_leaves_no_side_effects() {
    let (db, _identity, master) = seeded_db().await;
    let (session, pushed_log) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());
    let admin = crate::sync::remote::SyncAdminApi::new("http://127.0.0.1:1", "t").unwrap();
    let lamport_before = session.sync_repo.get_state().await.unwrap().local_lamport;

    let err = session
        .rotate_group_key(&master, &admin)
        .await
        .expect_err("unreachable admin must fail");
    let _ = err;

    assert!(pushed_log.lock().unwrap().is_empty());
    let lamport_after = session.sync_repo.get_state().await.unwrap().local_lamport;
    assert_eq!(lamport_after, lamport_before);
}

// ---- 重包容错矩阵：legacy / wrapped 损坏 / 密文损坏 / 明文非法，
// 逐条跳过不阻断整批；健康条目正常重包（对照组）。----

#[tokio::test]
async fn rewrap_all_skips_unreadable_credentials_one_by_one() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());

    // ① legacy：无 wrapped item key（取不出 item key）→ skip
    cred_repo
        .create(&Credential::new(
            identity.id,
            "legacy".into(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1u8; 32],
            None,
        ))
        .await
        .unwrap();

    // ② wrapped 损坏（unwrap_item_key 失败）→ skip
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-wrapped".into(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1u8; 32],
            Some(vec![7u8; 8]),
        ))
        .await
        .unwrap();

    // ③ wrapped 有效但密文损坏（decrypt 失败）→ skip
    let item_key = EncryptionService::generate_key();
    let wrapped = master.encrypt(&item_key).unwrap();
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-ciphertext".into(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![9u8; 64],
            Some(wrapped.clone()),
        ))
        .await
        .unwrap();

    // ④ 解密成功但明文不是合法 CredentialData（from_bytes 失败）→ skip
    let junk = KeyHierarchy::new(&master)
        .encrypt_with_item_key(&item_key, b"not-credential-data")
        .unwrap();
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-data".into(),
            CredentialType::Password,
            SecurityLevel::High,
            junk,
            Some(wrapped),
        ))
        .await
        .unwrap();

    // 对照组：健康凭据应正常重包
    store_credential(&cred_repo, identity.id, "healthy", &master, "ok").await;

    let new_group = GroupKey::generate().unwrap();
    let (session, _) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());
    let (rewrapped, skipped) = session.rewrap_all(&master, &new_group).await.unwrap();
    assert_eq!(
        (rewrapped, skipped),
        (1, 4),
        "healthy rewrapped, 4 bad skipped"
    );
}
