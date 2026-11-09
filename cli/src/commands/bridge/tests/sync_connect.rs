use super::*;

// ---- sync_connect（协议 v6，M5 批1）----

/// 纯装配回环：本地生成设备身份 + 本地密封信封 → open_own_group_key
/// 还原 group key（不经过服务器，覆盖信封寻址与拆封两条路径）。
#[test]
fn sync_connect_opens_own_group_key_from_entries() {
    let identity = device_identity(1);
    let group_key = [7u8; 32];
    let envelope =
        persona_core::sync::envelope::seal_group_key(&group_key, identity.key_pair.public_bytes())
            .unwrap();
    let entries = vec![persona_core::sync::remote::SyncGroupKeyEntry {
        device_id: identity.device_id,
        envelope,
        sealed_by: "test".to_string(),
        created_at: "2026-10-07T00:00:00Z".to_string(),
    }];

    let opened = open_own_group_key(&entries, &identity).unwrap();
    assert_eq!(&opened, &group_key);
}

/// 信封表里没有本机设备 → sync_not_authorized（待授权语义，fail-closed）。
#[test]
fn sync_connect_rejects_missing_envelope() {
    let identity = device_identity(1);
    let other = device_identity(2);
    let envelope =
        persona_core::sync::envelope::seal_group_key(&[1u8; 32], other.key_pair.public_bytes())
            .unwrap();
    let entries = vec![persona_core::sync::remote::SyncGroupKeyEntry {
        device_id: other.device_id,
        envelope,
        sealed_by: "test".to_string(),
        created_at: "2026-10-07T00:00:00Z".to_string(),
    }];

    let err = open_own_group_key(&entries, &identity).unwrap_err();
    assert!(
        err.to_string().starts_with("sync_not_authorized"),
        "got: {err}"
    );
}

/// 无 workspace/settings → sync_not_configured（免解锁读 settings 的
/// 错误分类锚点；run_sync_connect 的 keyring/服务器分支依赖真机
/// secret service 与真服务器，留在 M6 实机走查覆盖）。
#[tokio::test]
async fn sync_connect_reports_not_configured_on_fresh_vault() {
    let (_dir, db_path, _state_dir, _identity) = seeded_bridge().await;

    // seeded_bridge 建的 workspace 行没有 path 列值，find_by_path 落空
    let err = read_sync_server_url(&db_path).await.unwrap_err();
    assert!(
        err.to_string().starts_with("sync_not_configured"),
        "got: {err}"
    );
}

/// settings 里 sync.server_url 在场时免解锁读出（正路径）。settings
/// JSON 必须是完整默认形态——row_to_workspace_v2 对解析失败静默回退
/// 默认值（sync=None），残缺 JSON 会伪装成「未配置」。
#[tokio::test]
async fn sync_connect_reads_server_url_from_workspace_settings() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = open_db(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let settings =
        workspace_settings_json(Some(("http://127.0.0.1:8080".to_string(), "".to_string())));
    insert_workspace_row(&db, dir.path().to_string_lossy().as_ref(), &settings).await;

    let url = read_sync_server_url(&db_path).await.unwrap();
    assert_eq!(url, "http://127.0.0.1:8080");
}

/// settings.sync.server_url 为空串 = 未配置（与桌面 read_sync_config
/// 同口径：空白与缺省同义）。
#[tokio::test]
async fn sync_connect_treats_blank_server_url_as_not_configured() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = open_db(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let settings = workspace_settings_json(Some(("".to_string(), "".to_string())));
    insert_workspace_row(&db, dir.path().to_string_lossy().as_ref(), &settings).await;

    let err = read_sync_server_url(&db_path).await.unwrap_err();
    assert!(
        err.to_string().starts_with("sync_not_configured"),
        "got: {err}"
    );
}

/// 跨语言 fixture 锚定（M5 批1）：扩展侧 cloudSync.ts 解密+解码的
/// 对象由 Rust 侧同一 fixture 反向校验——Rust 拆 group 包裹 → 拆快照
/// → 与 expected 逐字段比对。任何一侧格式漂移都会在此红掉。
#[test]
fn sync_item_fixture_round_trips_with_rust() {
    for file in ["sync_item_fixture.json", "sync_item_fixture_sparse.json"] {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../browser/chromium-extension/src/__fixtures__/"
        )
        .to_string()
            + file;
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let fixture: serde_json::Value =
            serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("parse {path}: {e}"));
        let s = |k: &str| fixture[k].as_str().unwrap().to_string();

        let group_key_bytes: [u8; 32] =
            hex::decode(s("group_key_hex")).unwrap().try_into().unwrap();
        let group_key = persona_core::sync::keys::GroupKey::from_bytes(group_key_bytes);
        let wrapped = base64::engine::general_purpose::STANDARD
            .decode(s("wrapped_item_key_b64"))
            .unwrap();
        let item_key = persona_core::sync::keys::unwrap_item_key_with_group(&wrapped, &group_key)
            .unwrap_or_else(|e| panic!("{file}: unwrap failed: {e}"));

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(s("ciphertext_b64"))
            .unwrap();
        let snap = persona_core::sync::snapshot::SyncItemSnapshot::open(&ciphertext, &item_key)
            .unwrap_or_else(|e| panic!("{file}: open failed: {e}"));

        let expected = &fixture["expected"];
        assert_eq!(
            snap.identity_id.to_string(),
            expected["identity_id"],
            "{file}"
        );
        assert_eq!(snap.name, expected["name"], "{file}");
        assert_eq!(
            format!("{}", snap.credential_type),
            expected["credential_type"],
            "{file}"
        );
        assert_eq!(
            format!("{}", snap.security_level),
            expected["security_level"],
            "{file}"
        );
        assert_eq!(snap.url.as_deref(), expected["url"].as_str(), "{file} url");
        assert_eq!(
            snap.username.as_deref(),
            expected["username"].as_str(),
            "{file} username"
        );
        assert_eq!(snap.is_favorite, expected["is_favorite"], "{file}");
        assert_eq!(snap.is_active, expected["is_active"], "{file}");
    }
}

/// fixture 再生成（改了 SyncItemSnapshot/CredentialData 结构时用）：
/// `cargo test -p persona-cli emit_sync_item_fixture -- --ignored --nocapture`
/// 输出两份 JSON 覆盖 `browser/chromium-extension/src/__fixtures__/`。
#[test]
#[ignore = "fixture generator; run with --ignored --nocapture"]
fn emit_sync_item_fixture() {
    use persona_core::models::{
        CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
    };
    use persona_core::sync::keys::wrap_item_key_with_group;
    use persona_core::sync::snapshot::SyncItemSnapshot;

    let fixture = |name: &str,
                   identity_id: uuid::Uuid,
                   cred_type: CredentialType,
                   level: SecurityLevel,
                   url: Option<&str>,
                   username: Option<&str>,
                   favorite: bool,
                   password: &str| {
        let snap = SyncItemSnapshot {
            identity_id,
            name: name.to_string(),
            credential_type: cred_type,
            security_level: level,
            url: url.map(str::to_string),
            username: username.map(str::to_string),
            notes: None,
            tags: vec!["work".to_string()],
            metadata: [("env".to_string(), "prod".to_string())]
                .into_iter()
                .collect(),
            is_favorite: favorite,
            is_active: true,
            data: CredentialData::Password(PasswordCredentialData {
                password: password.to_string(),
                email: None,
                security_questions: vec![],
            }),
        };
        let item_key: [u8; 32] = [0x11; 32];
        let group_key = [0x22; 32];
        let wrapped = wrap_item_key_with_group(
            &item_key,
            &persona_core::sync::keys::GroupKey::from_bytes(group_key),
        );
        let ciphertext = snap.seal(&item_key).unwrap();
        let expected = serde_json::json!({
            "identity_id": identity_id.to_string(),
            "name": snap.name,
            "credential_type": format!("{}", snap.credential_type),
            "security_level": format!("{}", snap.security_level),
            "url": snap.url,
            "username": snap.username,
            "is_favorite": snap.is_favorite,
            "is_active": snap.is_active,
        });
        serde_json::json!({
            "group_key_hex": hex::encode(group_key),
            "item_key_hex": hex::encode(item_key),
            "wrapped_item_key_b64": base64::engine::general_purpose::STANDARD.encode(&wrapped),
            "ciphertext_b64": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            "expected": expected,
        })
    };

    let rich = fixture(
        "GitHub (Work)",
        uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap(),
        CredentialType::Password,
        SecurityLevel::High,
        Some("https://github.com"),
        Some("alice@example.com"),
        true,
        "hunter2-strong",
    );
    let sparse = fixture(
        "Custom Note",
        uuid::Uuid::parse_str("99999999-8888-7777-6666-555555555555").unwrap(),
        CredentialType::Custom("内部工具".to_string()),
        SecurityLevel::Medium,
        None,
        None,
        false,
        "plain-note-secret",
    );
    println!("===RICH===");
    println!("{}", serde_json::to_string_pretty(&rich).unwrap());
    println!("===SPARSE===");
    println!("{}", serde_json::to_string_pretty(&sparse).unwrap());
}
