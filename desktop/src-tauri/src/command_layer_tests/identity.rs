//! Command-layer integration tests — `identity` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn service_lifecycle_through_init_reauth_and_lock() {
    let app = mock_app();

    // Before initialization the service-dependent commands degrade loudly.
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(false));

    // First-time init creates the user and leaves the service unlocked.
    init_service_ok(&app, "correct-horse").await;
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true), "fresh init must be unlocked");

    // Re-init against the same vault with a wrong password is rejected.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("reinit.db");
    std::mem::forget(dir);
    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(db_path.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "re-init with the right password succeeds");
    let resp = init_service(
        InitRequest {
            master_password: "wrong-password".to_string(),
            db_path: Some(db_path.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid master password"));

    // Lock, then re-auth: wrong password rejected, right one restores.
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false), "locked after lock_service");

    let resp = reauth_verify(
        ReauthRequest {
            master_password: "wrong-password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid master password"));

    let resp = reauth_verify(
        ReauthRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "correct re-auth failed: {:?}", resp.error);
}
#[tokio::test]
async fn identity_crud_commands_round_trip() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // Create.
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Work".to_string(),
            identity_type: "work".to_string(),
            description: Some("day job".to_string()),
            email: Some("work@example.com".to_string()),
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let created = resp.data.expect("created identity returned");
    assert_eq!(created.name, "Work");

    // List + get.
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().iter().any(|i| i.id == created.id));

    let resp = get_identity(created.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().map(|i| i.name), Some("Work".to_string()));

    // Update (name + tags).
    let resp = update_identity(
        UpdateIdentityRequest {
            id: created.id.clone(),
            name: "Work (renamed)".to_string(),
            identity_type: "work".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: Some(vec!["ops".to_string()]),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let updated = resp.data.expect("updated identity returned");
    assert_eq!(updated.name, "Work (renamed)");
    assert_eq!(updated.tags, vec!["ops".to_string()]);

    // Delete + confirm gone.
    let resp = delete_identity(created.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap());
    let resp = get_identity(created.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().is_none(), "deleted identity is gone");
}
#[tokio::test]
async fn identity_commands_reject_bad_uuids_and_missing_service() {
    let app = mock_app();

    // Without a service every identity command fails closed.
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "correct-horse").await;

    // Malformed ids never reach the repository.
    let resp = get_identity("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("Invalid UUID format"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    let resp = delete_identity("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("Invalid UUID format"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    // A well-formed id that does not exist is a clean None, not an error.
    let missing = uuid::Uuid::new_v4().to_string();
    let resp = get_identity(missing.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().is_none());
    let resp = update_identity(
        UpdateIdentityRequest {
            id: missing,
            name: "ghost".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "updating a missing identity must fail");
}
#[tokio::test]
async fn active_identity_commands_round_trip() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // Initially nothing is active (fresh workspace row).
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(
        resp.data,
        Some(None),
        "fresh workspace has no active identity"
    );

    // Create an identity and activate it.
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Solo".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let identity = resp.data.expect("created identity");
    let identity_id = identity.id.clone();

    let resp = set_active_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(Some(identity_id.clone())));

    // Clear returns to the empty state.
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(None));
}
#[tokio::test]
async fn generate_password_and_statistics_serve_values() {
    let app = mock_app();

    let resp = generate_password(16, true, app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "correct-horse").await;

    let resp = generate_password(16, true, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 16);

    let resp = get_statistics(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let stats = resp.data.expect("statistics returned");
    assert!(stats.is_object(), "statistics is a JSON object: {stats}");
}
#[tokio::test]
async fn generate_password_advanced_works_without_unlocked_service() {
    // 纯计算命令：不建 app、不解锁，直接调用即应出数（Quick Access/锁屏
    // 场景的前置条件）。
    let resp = generate_password_advanced(16, true, true, true, true, false, 3, None)
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("passwords returned");
    assert_eq!(data.passwords.len(), 3);
    assert!(data.passwords.iter().all(|p| p.len() == 16));
    // 26 + 26 + 10 + 24 = 86；熵 = log2(86) × 16
    assert_eq!(data.pool_size, 86);
    let expected = 86f64.log2() * 16.0;
    assert!((data.entropy_bits - expected).abs() < 1e-9);

    // 选项收敛：只留数字集，池 = 10，字符全来自数字集
    let resp = generate_password_advanced(12, false, false, true, false, false, 1, None)
        .await
        .unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data.pool_size, 10);
    assert!(data
        .passwords
        .iter()
        .all(|p| p.chars().all(|c| c.is_ascii_digit())));
}
#[tokio::test]
async fn generate_password_advanced_pronounceable_entropy_and_clamps() {
    // 可发音（仅小写）：辅音 21 / 元音 5 交替；长度 20 → 10×log2(21)+10×log2(5)
    let resp = generate_password_advanced(20, true, false, false, false, true, 1, None)
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.unwrap();
    let expected = 10.0 * 21f64.log2() + 10.0 * 5f64.log2();
    assert!((data.entropy_bits - expected).abs() < 1e-9);
    assert_eq!(data.pool_size, 21);

    // count / length 夹取：0 → 1 条、下限 4；上限防滥用
    let resp = generate_password_advanced(0, true, true, true, true, false, 0, None)
        .await
        .unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data.passwords.len(), 1);
    assert_eq!(data.passwords[0].len(), 4);

    let resp = generate_password_advanced(10_000, true, true, true, true, false, 99, None)
        .await
        .unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data.passwords.len(), 10);
    assert_eq!(data.passwords[0].len(), 256);
}
#[tokio::test]
async fn generate_password_advanced_surfaces_validation_errors() {
    // 无字符集 / 可发音无字母：core 校验错误透传，不 panic 不静默
    let resp = generate_password_advanced(16, false, false, false, false, false, 1, None)
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.unwrap().contains("At least one character set"),
        "unexpected error"
    );

    let resp = generate_password_advanced(16, false, false, true, true, true, 1, None)
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .unwrap()
            .contains("Pronounceable passwords require lowercase and/or uppercase"),
        "unexpected error"
    );
}
#[tokio::test]
async fn generate_password_advanced_words_mode_entropy_and_validation() {
    // Words mode (Diceware-style): 6 words from 7772-word EFF list, hyphen-separated.
    // Entropy = 6 * log2(7772).
    let resp = generate_password_advanced(16, true, true, true, true, false, 1, Some(6))
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.unwrap();
    assert_eq!(data.passwords.len(), 1);
    let passphrase = &data.passwords[0];
    // 6 words → 5 hyphens
    assert_eq!(passphrase.matches('-').count(), 5);
    let words: Vec<&str> = passphrase.split('-').collect();
    assert_eq!(words.len(), 6);
    // All words must be lowercase [a-z]+
    for word in &words {
        assert!(
            word.chars().all(|c| c.is_ascii_lowercase()),
            "word {word} not all lowercase"
        );
    }
    // Entropy: 6 * log2(7772)
    let expected = 6.0 * 7772f64.log2();
    assert!((data.entropy_bits - expected).abs() < 1e-9);
    assert_eq!(data.pool_size, 7772);

    // Word count bounds: 2 and 11 are rejected.
    for word_count in [2usize, 11] {
        let resp =
            generate_password_advanced(16, true, true, true, true, false, 1, Some(word_count))
                .await
                .unwrap();
        assert!(!resp.success, "word_count {word_count} should be rejected");
        assert!(
            resp.error.unwrap().contains("between 3 and 10"),
            "unexpected error"
        );
    }

    // Words mode ignores length and character sets (length=3, no sets).
    let resp = generate_password_advanced(3, false, false, false, false, false, 1, Some(5))
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.unwrap();
    assert_eq!(data.passwords[0].matches('-').count(), 4);

    // Words + pronounceable is rejected.
    let resp = generate_password_advanced(16, true, true, true, true, true, 1, Some(6))
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .unwrap()
            .contains("cannot be combined with pronounceable"),
        "unexpected error"
    );
}
#[tokio::test]
async fn export_identity_command_returns_exportable_json() {
    let (app, identity_id) = app_with_identity().await;

    let resp = export_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let export = resp.data.expect("export returned");
    assert!(!export.exported_at.is_empty());
    assert!(export.data.is_object(), "export payload is JSON");
}
/// export_identity 的成功/错误路径 + audit_cleanup 与 reauth 的门禁。
#[tokio::test]
async fn export_identity_and_audit_cleanup_gates() {
    let app = mock_app();
    let bad_uuid = uuid::Uuid::new_v4().to_string();

    // 无服务分支：export/audit_cleanup/reauth 全部降级报错；
    // passkey 导出则先在本地拒绝坏 UUID。
    let resp = export_identity(bad_uuid.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = audit_cleanup(30, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = reauth_verify(
        ReauthRequest {
            master_password: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = passkey_export_private_key("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    let (app, identity_id) = app_with_identity().await;

    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 导出成功：身份 + 凭据 JSON 负载（元数据，不含密文）。
    let resp = export_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let export = resp.data.expect("identity exported");
    assert_eq!(export.data["identity"]["name"], "Cred Holder");
    assert_eq!(export.data["credentials"].as_array().map(Vec::len), Some(1));
    assert!(!export.exported_at.is_empty());

    // 不存在的身份：无专用错误码 → 常规错误串。
    let resp = export_identity(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("Failed to export identity"));

    // 锁定后：export/audit_cleanup 都带 SERVICE_LOCKED 错误码。
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = export_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = audit_cleanup(30, app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));
}
/// workspace 路径推导：裸文件名的 parent 是空串而非 None
/// （Path::parent 语义），落库时由上层 filter 回落到默认名。
#[test]
fn workspace_path_for_db_path_handles_bare_names() {
    assert_eq!(workspace_path_for_db_path("/tmp/x/vault.db"), "/tmp/x");
    // Path::new("bare.db").parent() == Some("")，不触发 unwrap_or_else。
    assert_eq!(workspace_path_for_db_path("bare.db"), "");
}
/// update_identity 的 identity_type 全臂 + 可选字段"空白即清除"归一化。
#[tokio::test]
async fn identity_update_type_matrix_and_optional_field_normalization() {
    let (app, identity_id) = app_with_identity().await;

    // 逐个驱动 identity_type 的映射臂（Personal 已由既有测试覆盖）。
    for (type_str, expected) in [
        ("Work", "Work"),
        ("Social", "Social"),
        ("Financial", "Financial"),
        ("Gaming", "Gaming"),
        ("Team Secret", "Team Secret"),
    ] {
        let resp = update_identity(
            UpdateIdentityRequest {
                id: identity_id.clone(),
                name: "Matrix Identity".to_string(),
                identity_type: type_str.to_string(),
                description: None,
                email: None,
                phone: None,
                tags: None,
            },
            app.state::<AppState>(),
        )
        .await
        .unwrap();
        assert!(resp.success, "{type_str}: {:?}", resp.error);
        let updated = resp.data.expect("identity updated");
        assert_eq!(updated.identity_type, expected, "arm for {type_str}");
    }

    // description/email/phone 传纯空白 → 归一化为 None（三个 and_then 臂）。
    let resp = update_identity(
        UpdateIdentityRequest {
            id: identity_id.clone(),
            name: "Cleared".to_string(),
            identity_type: "personal".to_string(),
            tags: None,
            description: Some("   ".to_string()),
            email: Some(" \t ".to_string()),
            phone: Some("  ".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let updated = resp.data.expect("identity updated");
    assert_eq!(updated.description, None);
    assert_eq!(updated.email, None);
    assert_eq!(updated.phone, None);

    // 不存在的 id → "Identity not found"。
    let resp = update_identity(
        UpdateIdentityRequest {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Ghost".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Identity not found"));
}
/// get/set/clear_active_identity 在 db_path 打不开时大声报错
///（from_file/migrate 错误臂）。
#[tokio::test]
async fn active_identity_commands_report_db_failures() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    let state = || app.state::<AppState>();

    // 垃圾文件：connect 打开成功、migrate 才报 not a database。
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, b"still not a database").unwrap();
    std::mem::forget(dir);
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some(junk.to_string_lossy().to_string());
    }

    // 基础设施失败一律 Ok(ApiResponse::error)：success=false + error 落消息。
    let resp = get_active_identity(state()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    let resp = set_active_identity(uuid::Uuid::new_v4().to_string(), state())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    let resp = clear_active_identity(state()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    // 不存在目录：from_file 的 connect 直接失败。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some("/nonexistent-dir-for-persona-tests/x.db".to_string());
    }
    let resp = get_active_identity(state()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Database connection failed")),
        "got: {:?}",
        resp.error
    );
}
/// 删除当前活跃的 identity 时，workspace 的 active_identity_id 指针被清空。
#[tokio::test]
async fn delete_active_identity_clears_workspace_pointer() {
    let (app, identity_id) = app_with_identity().await;

    let resp = set_active_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(Some(identity_id.clone())));

    let resp = delete_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(
        resp.data,
        Some(None),
        "deleting the active identity must clear the pointer"
    );
}
#[tokio::test]
async fn identity_commands_surface_db_errors_from_garbage_vault() {
    let app = app_with_garbage_db_service().await;
    let state = app.state::<AppState>();
    let bogus = "00000000-0000-0000-0000-000000000000".to_string();
    let expect_db_err = |msg: &str| {
        assert!(
            msg.contains("file is not a database"),
            "expected sqlite error, got: {msg}"
        );
    };

    // list 走精确消息（探针验证过的形态），其余断言前缀 + 底层错误。
    let resp = get_identities(state.clone()).await.unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some(
            "Failed to get identities: Database operation failed: error returned from database: (code: 26) file is not a database"
        )
    );

    let resp = get_identity(bogus.clone(), state.clone()).await.unwrap();
    expect_db_err(resp.error.as_deref().unwrap_or_default());

    let resp = create_identity(
        CreateIdentityRequest {
            name: "X".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref().map(|m| &m[..17]),
        Some("Failed to create ")
    );
    expect_db_err(resp.error.as_deref().unwrap_or_default());

    let resp = update_identity(
        UpdateIdentityRequest {
            id: bogus.clone(),
            name: "X".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get identity"),
        "got: {:?}",
        resp.error
    );

    let resp = delete_identity(bogus.clone(), state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to delete identity"),
        "got: {:?}",
        resp.error
    );

    let resp = export_identity(bogus.clone(), state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to export identity"),
        "got: {:?}",
        resp.error
    );

    let resp = get_statistics(state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get statistics"),
        "got: {:?}",
        resp.error
    );

    let resp = search_credentials("needle".to_string(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to search credentials"),
        "got: {:?}",
        resp.error
    );

    // touch 只动内存时间戳，坏库也必须成功。
    let resp = touch_activity(state).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));
}
#[tokio::test]
async fn missing_and_malformed_ids_take_their_own_error_arms() {
    let app = mock_app();

    // 未初始化：各命令的 None service 臂。
    let resp = get_identity(
        "00000000-0000-0000-0000-000000000000".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = create_identity(
        CreateIdentityRequest {
            name: "X".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = create_credential(
        password_credential_request("00000000-0000-0000-0000-000000000000"),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = toggle_credential_favorite(
        "00000000-0000-0000-0000-000000000000".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // 初始化后：合法 UUID 但不存在的资源。
    let (app, _identity_id) = app_with_identity().await;
    let bogus = "00000000-0000-0000-0000-000000000000".to_string();

    // get 对缺失 id 返回 Ok(None)（success=true，无 error）。
    let resp = get_identity(bogus.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success);
    assert!(
        matches!(resp.data, Some(None)),
        "missing identity returns Ok(None)"
    );

    // update 先查再改：缺失 id 在查询步就被拒。
    let resp = update_identity(
        UpdateIdentityRequest {
            id: bogus.clone(),
            name: "X".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Identity not found"));

    let resp = create_credential(
        password_credential_request("not-a-uuid"),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    let resp = toggle_credential_favorite(bogus.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Credential not found"));

    let resp = delete_credential(bogus.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.data, Some(false), "delete of missing id is a no-op");

    // 非法 UUID 先于 repo 到达自己的错误臂。
    let resp = delete_credential("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));
}
#[tokio::test]
async fn get_active_identity_without_db_path_degrades_loudly() {
    let app = mock_app();

    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );
}
/// active identity 三命令的前置臂：未初始化、锁定、非法 UUID、db_path 缺失，
/// 外加 clear_active_identity 的成功路径（此前只有失败路径有覆盖）。
#[tokio::test]
async fn active_identity_precondition_matrix() {
    // 未初始化：None service 臂在 UUID 解析之前拦下 set。
    let app = mock_app();
    let resp = set_active_identity("not-even-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // 锁定态：unlock 检查在 UUID 解析之前。
    let (app, identity_id) = app_with_identity().await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = set_active_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    // 已解锁：UUID 解析在 db_path 检查之前，非法 UUID 走自己的错误臂。
    let (app, identity_id) = app_with_identity().await;
    let resp = set_active_identity("bad-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    // db_path 缺失：set/clear 都落同一句 ApiResponse 错误。
    let original_db_path = {
        let state = app.state::<AppState>();
        let path = state.db_path.lock().await.clone();
        *state.db_path.lock().await = None;
        path.expect("init_service_ok set a db path")
    };
    let resp = set_active_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );

    // 恢复路径后 clear 走完整成功链（ensure_workspace → 清指针 → 落库）。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some(original_db_path);
    }
    let resp = set_active_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(None), "clear must remove the pointer");
}
/// create_identity 的 identity_type 大写/自定义全臂（354-359 的 match）。
#[tokio::test]
async fn create_identity_type_match_arms_all_reachable() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // 大写形式走专用枚举臂，任意其他字符串走 Custom 原样回显。
    for label in [
        "Personal",
        "Work",
        "Social",
        "Financial",
        "Gaming",
        "banking-alt",
    ] {
        let resp = create_identity(
            CreateIdentityRequest {
                name: format!("Typed {label}"),
                identity_type: label.to_string(),
                description: None,
                email: None,
                phone: None,
            },
            app.state::<AppState>(),
        )
        .await
        .unwrap();
        assert!(resp.success, "{label}: {:?}", resp.error);
        let identity = resp.data.expect("identity created");
        assert_eq!(identity.name, format!("Typed {label}"));
    }
}
/// ensure_workspace_for_path 的 create 分支：workspace_path 无 file_name
/// （如 "/"）时工作区名叫 "Persona"。需要空库——已有单个 workspace 时
/// 先走 len==1 迁移分支（改写 path 返回），到不了 name 计算。
#[tokio::test]
async fn workspace_name_falls_back_to_persona_for_root_paths() {
    assert_eq!(workspace_path_for_db_path("/"), ".");

    let dir = tempfile::tempdir().unwrap();
    let db = persona_core::Database::from_file(dir.path().join("w.db"))
        .await
        .unwrap();
    db.migrate().await.unwrap();

    let ws = ensure_workspace_for_path(&db, "/").await.unwrap();
    assert_eq!(ws.name, "Persona");
    assert_eq!(ws.path.to_string_lossy(), "/");

    // 同路径二次调用走 find 分支，名字不被重建覆盖。
    let ws = ensure_workspace_for_path(&db, "/").await.unwrap();
    assert_eq!(ws.name, "Persona");
}
