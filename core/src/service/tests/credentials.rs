use super::*;

#[tokio::test]
async fn custom_fields_set_read_roundtrip_seals_values() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("CF Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(
        &service,
        identity.id,
        "WithFields",
        CredentialType::Password,
    )
    .await;

    let fields = vec![
        crate::custom_fields::new_custom_field(
            "Server",
            "db.internal:5432",
            crate::models::credential::CustomFieldType::Text,
        ),
        crate::custom_fields::new_custom_field(
            "Recovery code",
            "abcd-efgh",
            crate::models::credential::CustomFieldType::Concealed,
        ),
    ];
    service
        .set_custom_fields(&cred.id, fields.clone())
        .await
        .unwrap();

    let read_back = service.custom_fields(&cred.id).await.unwrap();
    assert_eq!(read_back, fields);

    // 落库形态是密文：metadata blob 不含明文标签或值
    let stored = service.get_credential(&cred.id).await.unwrap().unwrap();
    let blob = stored
        .metadata
        .get(crate::custom_fields::CUSTOM_FIELDS_METADATA_KEY)
        .unwrap();
    assert!(!blob.contains("Recovery code"));
    assert!(!blob.contains("abcd-efgh"));
}

#[tokio::test]
async fn custom_fields_empty_list_removes_blob() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("CF Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "CF", CredentialType::Password).await;

    let fields = vec![crate::custom_fields::new_custom_field(
        "K",
        "V",
        crate::models::credential::CustomFieldType::Text,
    )];
    service.set_custom_fields(&cred.id, fields).await.unwrap();
    service
        .set_custom_fields(&cred.id, Vec::new())
        .await
        .unwrap();

    assert!(service.custom_fields(&cred.id).await.unwrap().is_empty());
    let stored = service.get_credential(&cred.id).await.unwrap().unwrap();
    assert!(!stored
        .metadata
        .contains_key(crate::custom_fields::CUSTOM_FIELDS_METADATA_KEY));
}

#[tokio::test]
async fn custom_fields_locked_vault_fails_closed() {
    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("CF Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "CF", CredentialType::Password).await;
    let fields = vec![crate::custom_fields::new_custom_field(
        "K",
        "V",
        crate::models::credential::CustomFieldType::Text,
    )];
    service.set_custom_fields(&cred.id, fields).await.unwrap();

    service.lock();
    assert!(service.custom_fields(&cred.id).await.is_err());
    assert!(service
        .set_custom_fields(&cred.id, Vec::new())
        .await
        .is_err());
}

#[tokio::test]
async fn custom_fields_duplicate_ids_rejected() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("CF Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "CF", CredentialType::Password).await;

    let mut a = crate::custom_fields::new_custom_field(
        "K",
        "V",
        crate::models::credential::CustomFieldType::Text,
    );
    let b = a.clone();
    a.label = "K2".to_string();
    assert!(service
        .set_custom_fields(&cred.id, vec![a, b])
        .await
        .is_err());
}

#[tokio::test]
async fn credential_history_records_created_updated_deleted() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("History Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let mut cred = seed_credential(&service, identity.id, "Gmail", CredentialType::Password).await;

    // 创建 → created 行 v1（新快照有、旧快照无）
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].change_type, ChangeType::Created);
    assert_eq!(history[0].version, 1);
    assert!(history[0].new_state.is_some());
    assert!(history[0].previous_state.is_none());

    // 元数据变化 → updated 行 v2，字段级 diff 记 username 与 url
    cred.username = Some("alice".to_string());
    cred.url = Some("https://mail.example.com".to_string());
    service.update_credential(&cred).await.unwrap();

    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].change_type, ChangeType::Updated);
    assert_eq!(history[0].version, 2);
    assert_eq!(history[0].changes_summary.len(), 2);
    let username_change = history[0].changes_summary.get("username").unwrap();
    assert_eq!(username_change.old_value, "");
    assert_eq!(username_change.new_value, "alice");

    // 无实质变化的重复 update → 不新增历史行
    service.update_credential(&cred).await.unwrap();
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 2, "no-op update must not add history");

    // 密文变化（密码轮换）→ 只记占位 diff；内容绝不进历史
    cred.encrypted_data = vec![9u8; 8];
    service.update_credential(&cred).await.unwrap();
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let enc_change = history[0].changes_summary.get("encrypted_data").unwrap();
    assert_eq!(enc_change.old_value, "<encrypted>");
    assert_eq!(enc_change.new_value, "<encrypted>");
    let states = serde_json::to_string(&history[0].new_state).unwrap();
    assert!(!states.contains("encrypted_data"));

    // 删除 → deleted 行 v4（凭据行已删，历史仍在）
    service.delete_credential(&cred.id).await.unwrap();
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    assert_eq!(history[0].change_type, ChangeType::Deleted);
    assert_eq!(history[0].version, 4);
}

#[tokio::test]
async fn restore_credential_version_reverts_metadata_and_keeps_secrets() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Restore Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let mut cred = seed_credential(&service, identity.id, "Gmail", CredentialType::Password).await;
    let original_ciphertext = cred.encrypted_data.clone();

    // v2：username/url
    cred.username = Some("alice".to_string());
    cred.url = Some("https://mail.example.com".to_string());
    service.update_credential(&cred).await.unwrap();

    // v3：rename
    cred.name = "Gmail Work".to_string();
    service.update_credential(&cred).await.unwrap();

    // 恢复到 v1（创建态）：元数据回滚，密文原样
    let restored = service
        .restore_credential_version(&cred.id, 1)
        .await
        .unwrap();
    assert_eq!(restored.name, "Gmail");
    assert_eq!(restored.username, None);
    assert_eq!(restored.url, None);
    assert_eq!(restored.tags, Vec::<String>::new());
    assert!(!restored.is_favorite);
    assert!(restored.is_active);
    assert_eq!(
        restored.encrypted_data, original_ciphertext,
        "metadata restore must never touch the secret payload"
    );

    // 历史多一行 restored，reason 标注目标版本
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    assert_eq!(history[0].change_type, ChangeType::Restored);
    assert_eq!(history[0].version, 4);
    assert_eq!(history[0].reason.as_deref(), Some("restore to version 1"));
    let name_change = history[0].changes_summary.get("name").unwrap();
    assert_eq!(name_change.old_value, "Gmail Work");
    assert_eq!(name_change.new_value, "Gmail");
    let username_change = history[0].changes_summary.get("username").unwrap();
    assert_eq!(username_change.old_value, "alice");
    assert_eq!(username_change.new_value, "");

    // 中间版本也可恢复：回到 v2（username=alice、name=Gmail）
    let restored = service
        .restore_credential_version(&cred.id, 2)
        .await
        .unwrap();
    assert_eq!(restored.name, "Gmail");
    assert_eq!(restored.username.as_deref(), Some("alice"));
    assert_eq!(restored.url.as_deref(), Some("https://mail.example.com"));

    // 恢复到当前状态 = 无实质变化 → 不记噪声历史行
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 5);
    service
        .restore_credential_version(&cred.id, 2)
        .await
        .unwrap();
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 5, "no-op restore must not add history");
}

#[tokio::test]
async fn restore_credential_version_rejects_bad_targets() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Restore Errors".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "Temp", CredentialType::Password).await;

    let err = service
        .restore_credential_version(&cred.id, 99)
        .await
        .expect_err("unknown version must fail");
    assert!(err.to_string().contains("no history version 99"));

    let missing = Uuid::new_v4();
    let err = service
        .restore_credential_version(&missing, 1)
        .await
        .expect_err("unknown credential must fail");
    assert!(err.to_string().contains("not found"));

    // 删除后的条目不可恢复（行已不在；历史仍可查但不重建秘密外壳）
    service.delete_credential(&cred.id).await.unwrap();
    let err = service
        .restore_credential_version(&cred.id, 1)
        .await
        .expect_err("deleted credential must not restore");
    assert!(err.to_string().contains("not found"));
}

/// 编辑 payload 的核心不变量：wrapped_item_key 字节不动，新 payload 走
/// 同一 item key 重封，已挂附件仍可解密，item history 落 Updated 行。
#[tokio::test]
async fn update_credential_data_reuses_item_key_and_keeps_attachments() {
    let (db, mut service) = unlocked_service().await;

    let identity = service
        .create_identity("Edit Owner".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity.id,
        "edit target",
        CredentialType::Password,
    )
    .await;
    let wrapped_before = credential.wrapped_item_key.clone().unwrap();

    // 先挂一个加密附件（用当前 item key 封存）
    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db.clone())
        .await
        .unwrap();
    let file_path = dir.path().join("edit-attach.bin");
    std::fs::write(&file_path, b"attachment-before-edit").unwrap();
    let attachment_id = service
        .attach_file(credential.id, &file_path, true)
        .await
        .unwrap();

    // 编辑 payload
    let edited = CredentialData::Password(PasswordCredentialData {
        password: "rotated-secret".to_string(),
        email: Some("edited@example.com".to_string()),
        security_questions: vec![],
    });
    let updated = service
        .update_credential_data(&credential.id, &edited)
        .await
        .unwrap();

    // wrapped key 字节不变（附件不变量的硬保障）
    assert_eq!(
        updated.wrapped_item_key.as_deref(),
        Some(&wrapped_before[..])
    );

    // 新 payload 读回逐字保留
    let data = service
        .get_credential_data(&credential.id)
        .await
        .unwrap()
        .unwrap();
    match data {
        CredentialData::Password(p) => {
            assert_eq!(p.password, "rotated-secret");
            assert_eq!(p.email.as_deref(), Some("edited@example.com"));
        }
        other => panic!("unexpected credential data: {other:?}"),
    }

    // 附件仍可解密（同一 item key）
    let plain = service
        .retrieve_attachment(&attachment_id, true)
        .await
        .unwrap();
    assert_eq!(plain, b"attachment-before-edit".to_vec());

    // item history 落 Updated 行（created + updated 至少两行）
    let history = service
        .get_entity_history(EntityType::Credential, &credential.id)
        .await
        .unwrap();
    assert!(history.iter().any(|e| e.change_type == ChangeType::Updated));
}

/// legacy 行（wrapped_item_key NULL）编辑 payload 时升级为 per-item key：
/// 升级后新密文走 item key 解密、行获得 wrapped key。
#[tokio::test]
async fn update_credential_data_upgrades_legacy_row_to_item_key() {
    let (db, service) = unlocked_service().await;

    let identity = service
        .create_identity("Legacy Edit Owner".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // 手工构造 legacy 行（同 attach 升级测试的模式）
    let master = service.get_master_encryption_service().unwrap();
    let plaintext = CredentialData::Password(PasswordCredentialData {
        password: "legacy-pw".to_string(),
        email: None,
        security_questions: vec![],
    })
    .to_bytes()
    .unwrap();
    let sealed = master.encrypt(&plaintext).unwrap();
    let credential = Credential::new(
        identity.id,
        "legacy edit row".to_string(),
        CredentialType::Password,
        SecurityLevel::Medium,
        sealed,
        None,
    );
    let credentials = crate::storage::CredentialRepository::new(db.clone());
    credentials.create(&credential).await.unwrap();

    let edited = CredentialData::Password(PasswordCredentialData {
        password: "edited-pw".to_string(),
        email: None,
        security_questions: vec![],
    });
    let updated = service
        .update_credential_data(&credential.id, &edited)
        .await
        .unwrap();
    assert!(updated.wrapped_item_key.is_some());

    // 新密文走 item key 路径解密（legacy 分支不再命中）
    let data = service
        .get_credential_data(&credential.id)
        .await
        .unwrap()
        .unwrap();
    match data {
        CredentialData::Password(p) => assert_eq!(p.password, "edited-pw"),
        other => panic!("unexpected credential data: {other:?}"),
    }
}

/// 编辑不存在的凭据报 InvalidInput（而非静默成功）。
#[tokio::test]
async fn update_credential_data_rejects_unknown_id() {
    let (_db, service) = unlocked_service().await;
    let err = service
        .update_credential_data(
            &Uuid::new_v4(),
            &CredentialData::Password(PasswordCredentialData {
                password: "x".to_string(),
                email: None,
                security_questions: vec![],
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not found"), "unexpected error: {err}");
}

/// 凭据删除级联清附件：blob 元数据随行消失，不留不可解密的孤儿。
#[tokio::test]
async fn delete_credential_cascades_attachments() {
    let (db, mut service) = unlocked_service().await;

    let identity = service
        .create_identity("Cascade Attach".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity.id,
        "cascade attach",
        CredentialType::Password,
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db)
        .await
        .unwrap();

    let file_path = dir.path().join("cascade.bin");
    std::fs::write(&file_path, b"cascade-bytes").unwrap();
    let attachment_id = service
        .attach_file(credential.id, &file_path, true)
        .await
        .unwrap();
    assert_eq!(
        service.get_attachments(&credential.id).await.unwrap().len(),
        1
    );

    assert!(service.delete_credential(&credential.id).await.unwrap());

    assert!(service
        .get_attachments(&credential.id)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .retrieve_attachment(&attachment_id, true)
        .await
        .is_err());
}

/// delete_credential 双分支：存在的凭据返回 true 并写 CredentialDeleted
/// 审计；再删一次（已不存在）返回 false，不重复写审计。
#[tokio::test]
async fn delete_credential_true_then_false_with_audit() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Delete Audit".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "Doomed", CredentialType::Password).await;

    assert!(service.delete_credential(&cred.id).await.unwrap());
    assert!(!service.delete_credential(&cred.id).await.unwrap());

    let logs = service
        .query_audit_logs(AuditLogQuery::default())
        .await
        .unwrap();
    let deleted = logs
        .iter()
        .filter(|l| l.action == AuditAction::CredentialDeleted)
        .collect::<Vec<_>>();
    assert_eq!(deleted.len(), 1, "audit written once, not for the miss");
    assert_eq!(
        deleted[0].resource_id.as_deref(),
        Some(cred.id.to_string()).as_deref()
    );
    assert!(deleted[0].success);
}

/// 同步捕获缝：attach(Some) 后写凭据递 Put 给捕获实现；attach(None)
/// 后写路径静默跳过。捕获失败/未装配不阻断主操作由类型保证——
/// 这里验证的是装配 ↔ 捕获的接线本身。
#[tokio::test]
async fn attach_sync_capture_feeds_credential_puts_only_while_attached() {
    use std::sync::Mutex;

    struct RecordingCapture(std::sync::Arc<Mutex<Vec<String>>>);

    #[async_trait::async_trait]
    impl crate::sync::capture::SyncCapture for RecordingCapture {
        async fn capture(
            &self,
            _item_id: Uuid,
            kind: crate::sync::oplog::ItemKind,
            op: crate::sync::oplog::OpType,
            _ciphertext: Option<Vec<u8>>,
            _item_key: Option<zeroize::Zeroizing<[u8; 32]>>,
        ) {
            self.0.lock().unwrap().push(format!("{kind:?}:{op:?}"));
        }
    }

    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Capture Seam".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    service
        .attach_sync_capture(Some(Arc::new(RecordingCapture(log.clone()))))
        .await;

    seed_credential(&service, identity.id, "Synced", CredentialType::Password).await;
    assert_eq!(*log.lock().unwrap(), vec!["Credential:Put".to_string()]);

    service.attach_sync_capture(None).await;
    seed_credential(&service, identity.id, "Unsynced", CredentialType::Password).await;
    assert_eq!(
        *log.lock().unwrap(),
        vec!["Credential:Put".to_string()],
        "detached capture must not observe further writes"
    );
}

/// apply_meta_snapshot 的整份校验语义：坏快照逐字段报 InvalidInput，
/// 且失败时凭据元数据一个字段都不落（不半套）。
#[test]
fn apply_meta_snapshot_validates_before_mutating() {
    let mut cred = Credential::new(
        Uuid::new_v4(),
        "Original".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        b"ciphertext".to_vec(),
        None,
    );

    fn apply(cred: &mut Credential, snapshot: &serde_json::Value) -> Result<()> {
        PersonaService::apply_meta_snapshot(cred, snapshot)
    }

    // 非对象 / 缺 name / 缺 tags / tags 非字符串数组 / 缺布尔字段
    assert!(apply(&mut cred, &serde_json::json!("nope"))
        .unwrap_err()
        .to_string()
        .contains("not an object"));
    assert!(apply(&mut cred, &serde_json::json!({}))
        .unwrap_err()
        .to_string()
        .contains("missing field name"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "High"
        })
    )
    .unwrap_err()
    .to_string()
    .contains("missing field tags"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "High",
            "tags": [7]
        })
    )
    .unwrap_err()
    .to_string()
    .contains("tag is not a string"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "High",
            "tags": []
        })
    )
    .unwrap_err()
    .to_string()
    .contains("missing field is_favorite"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "High",
            "tags": [], "is_favorite": true
        })
    )
    .unwrap_err()
    .to_string()
    .contains("missing field is_active"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "extreme",
            "tags": [], "is_favorite": true, "is_active": true
        })
    )
    .unwrap_err()
    .to_string()
    .contains("Unknown security level"));

    // 全部失败后凭据未被半套
    assert_eq!(cred.name, "Original");

    // 合法快照：元数据全部落上，秘密外壳字段保持原样
    apply(
        &mut cred,
        &serde_json::json!({
            "name": "Restored", "credential_type": "ApiKey", "security_level": "Medium",
            "username": "u", "url": "https://x", "notes": "n", "tags": ["a", "b"],
            "is_favorite": true, "is_active": false
        }),
    )
    .unwrap();
    assert_eq!(cred.name, "Restored");
    assert_eq!(cred.credential_type.to_string(), "ApiKey");
    assert_eq!(cred.security_level.to_string(), "Medium");
    assert_eq!(cred.username.as_deref(), Some("u"));
    assert_eq!(cred.tags, vec!["a".to_string(), "b".to_string()]);
    assert!(cred.is_favorite);
    assert!(!cred.is_active);
    assert_eq!(cred.encrypted_data, b"ciphertext".to_vec());
}

/// restore 命中「版本存在但无 new_state」的 Deleted 历史行 → 报
/// no restorable state，凭据本体不动。
#[tokio::test]
async fn restore_credential_version_rejects_tombstone_history() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Tombstone Restore".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "Target", CredentialType::Password).await;

    // 记一条 Deleted 历史（new_state=None）；凭据本体仍在库中
    service
        .record_credential_history(ChangeType::Deleted, Some(&cred), None, None)
        .await;
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    let deleted_version = history
        .iter()
        .find(|h| h.change_type.to_string() == "deleted")
        .expect("Deleted history row was recorded")
        .version;

    let err = service
        .restore_credential_version(&cred.id, deleted_version)
        .await
        .expect_err("tombstone history has nothing to restore");
    assert!(err.to_string().contains("no restorable state"));

    let after = service
        .credential_repo
        .find_by_id(&cred.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.name, "Target", "failed restore must not mutate");
}

/// 历史记录的尽力而为语义：(None, None) 直通返回；底层表不可用时
/// 只告警不阻断主写（业务事实已提交，历史是派生数据）。
#[tokio::test]
async fn credential_history_is_best_effort() {
    let (db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Hist".into(), IdentityType::Personal)
        .await
        .unwrap();

    // (None, None) 直通：无实体可记
    service
        .record_credential_history(ChangeType::Created, None, None, None)
        .await;

    // 表不可用 → 记录失败仅告警，凭据创建照常成功
    sqlx::query("DROP TABLE change_history")
        .execute(db.pool())
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity.id,
        "after drop",
        CredentialType::Password,
    )
    .await;
    assert!(service
        .get_credential(&credential.id)
        .await
        .unwrap()
        .is_some());
}
