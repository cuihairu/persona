use super::*;

// ---- sync_connect (protocol v6, M5 batch 1) ----

/// A pure-assembly round trip: generate the device identity locally + seal the envelope
/// locally → open_own_group_key restores the group key (no server involved, covering both
/// the envelope-addressing and unwrapping paths).
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

/// The envelope table has no entry for this machine → sync_not_authorized (awaiting-authorization semantics; fail-closed).
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

/// The local envelope exists but is sealed to **another device** (the device_id does not
/// match the key) → sync_group_key_failed: distinguished from "missing envelope" (the latter
/// is unauthorized, the former is corrupt/mismatched data); fails closed, no silent fallback.
#[test]
fn sync_connect_rejects_envelope_sealed_for_other_device() {
    let identity = device_identity(1);
    let other = device_identity(2);
    // The envelope is sealed with other's public key but the entry hangs under identity — a mismatched identity.
    let envelope =
        persona_core::sync::envelope::seal_group_key(&[1u8; 32], other.key_pair.public_bytes())
            .unwrap();
    let entries = vec![persona_core::sync::remote::SyncGroupKeyEntry {
        device_id: identity.device_id,
        envelope,
        sealed_by: "test".to_string(),
        created_at: "2026-10-07T00:00:00Z".to_string(),
    }];

    let err = open_own_group_key(&entries, &identity).unwrap_err();
    assert!(
        err.to_string().starts_with("sync_group_key_failed"),
        "got: {err}"
    );
}

/// SyncConnectRequest.user_gesture is a required bool (no default): omitting it →
/// deserialization error (the extension must carry the gesture explicitly, a popup click).
#[test]
fn sync_connect_request_requires_explicit_gesture() {
    let err = serde_json::from_value::<SyncConnectRequest>(serde_json::json!({})).unwrap_err();
    assert!(
        err.to_string().contains("user_gesture"),
        "missing user_gesture must fail deserialization, got: {err}"
    );

    let req: SyncConnectRequest =
        serde_json::from_value(serde_json::json!({ "user_gesture": true })).unwrap();
    assert!(req.user_gesture);
}

/// SyncConnectPayload snake_case wire-shape round trip: the extension reads server_url/token/
/// device_id/device_name/group_key_hex (per §17, sensitive material stays in session memory only).
#[test]
fn sync_connect_payload_round_trips_snake_case() {
    let payload = SyncConnectPayload {
        server_url: "https://sync.example.com".to_string(),
        token: "tok-123".to_string(),
        device_id: "dev-9".to_string(),
        device_name: "Alice's Laptop".to_string(),
        group_key_hex: "aabbcc".to_string(),
    };
    let json = serde_json::to_value(&payload).unwrap();
    assert_eq!(json["server_url"], "https://sync.example.com");
    assert_eq!(json["group_key_hex"], "aabbcc");

    let back: SyncConnectPayload = serde_json::from_value(json).unwrap();
    assert_eq!(back.token, "tok-123");
    assert_eq!(back.device_name, "Alice's Laptop");
}

/// No workspace/settings → sync_not_configured (the error-classification anchor for the
/// unlock-free settings read; the keyring/server branches of run_sync_connect depend on a
/// real secret service and a real server and are left to the M6 real-machine walkthrough).
#[tokio::test]
async fn sync_connect_reports_not_configured_on_fresh_vault() {
    let (_dir, db_path, _state_dir, _identity) = seeded_bridge().await;

    // The workspace row seeded by seeded_bridge has no path column value, so find_by_path comes up empty
    let err = read_sync_server_url(&db_path).await.unwrap_err();
    assert!(
        err.to_string().starts_with("sync_not_configured"),
        "got: {err}"
    );
}

/// When sync.server_url is present in settings it is read without unlocking (happy path).
/// The settings JSON must be the full default shape — row_to_workspace_v2 silently falls
/// back to defaults (sync=None) on a parse failure, so truncated JSON would masquerade as
/// "not configured".
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

/// An empty settings.sync.server_url = not configured (same terms as the desktop
/// read_sync_config: blank and default are synonymous).
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

/// Cross-language fixture anchoring (M5 batch 1): the object the extension's cloudSync.ts
/// decrypts+decodes is reverse-verified against the same fixture on the Rust side — Rust
/// unwraps the group wrap → unwraps the snapshot → compares field-by-field with expected.
/// Format drift on either side goes red here.
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

/// Fixture regeneration (use when the SyncItemSnapshot/CredentialData structures change):
/// `cargo test -p persona-cli emit_sync_item_fixture -- --ignored --nocapture`
/// writes two JSON files over `browser/chromium-extension/src/__fixtures__/`.
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
