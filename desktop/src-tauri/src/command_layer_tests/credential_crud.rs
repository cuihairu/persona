//! Command-layer integration tests — `credential_crud` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn credential_commands_round_trip_search_favorite_and_totp() {
    let (app, identity_id) = app_with_identity().await;

    // Create (also normalizes notes/tags whitespace).
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");
    assert_eq!(cred.name, "Example Login");
    assert_eq!(cred.tags, vec!["web".to_string(), "work".to_string()]);
    assert_eq!(cred.notes.as_deref(), Some("note with padding"));

    // List for identity.
    let resp = get_credentials_for_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 1);

    // Decrypted data round-trips through the encrypted vault.
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "Password");
    assert_eq!(data.data["password"], "s3cret-password");

    // Search by name.
    let resp = search_credentials("example".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().iter().any(|c| c.id == cred.id));

    // Toggle favorite twice: on, then off.
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_favorite);
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.data.unwrap().is_favorite);

    // TOTP credential: create with an RFC-vector secret and read a code.
    let mut totp_req = password_credential_request(&identity_id);
    totp_req.name = "GitHub TOTP".to_string();
    totp_req.credential_type = "TwoFactor".to_string();
    totp_req.credential_data = CredentialDataRequest::TwoFactor {
        secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
        issuer: "GitHub".to_string(),
        account_name: "alice@example.com".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
        hotp: None,
        initial_counter: None,
    };
    let resp = create_credential(totp_req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let totp_cred = resp.data.expect("totp credential created");

    let resp = get_totp_code(totp_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let code = resp.data.expect("totp code returned");
    assert_eq!(code.code.len(), 6);
    assert!(code.remaining_seconds <= 30);

    // Delete both credentials; the identity listing empties out.
    for id in [cred.id, totp_cred.id] {
        let resp = delete_credential(id, app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(resp.data.unwrap());
    }
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().is_empty());
}
/// G1.5: the create-form path — CredentialDataRequest::GameToken goes through
/// the create_credential command into the db, and reads back as a GameToken
/// variant and produces a code (steam_guard).
#[tokio::test]
async fn create_credential_accepts_game_token_request() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Steam Guard (form)".to_string();
    req.credential_type = "TwoFactor".to_string();
    req.credential_data = CredentialDataRequest::GameToken {
        provider: "steam_guard".to_string(),
        secret_key: "MDEyMzQ1Njc4OWFiY2RlZmdoaWo=".to_string(),
        issuer: "Steam".to_string(),
        account_name: "player_one".to_string(),
        url: Some("https://store.steampowered.com".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("game token credential created");

    // Read back: the data is a GameToken variant (secret_key is never sent back in JSON).
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "GameToken");
    assert_eq!(data.data["provider"], "steam_guard");
    assert_eq!(data.data["issuer"], "Steam");
    assert_eq!(data.data["account_name"], "player_one");
    assert!(data.data.get("secret_key").is_none());

    // steam_guard code generation goes through the unified scheduler.
    let resp = get_totp_code(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let code = resp.data.expect("game token code returned");
    assert_eq!(code.code.len(), 5);
    assert_eq!(code.period, 30);

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// 1Password alignment batch A: the Secure Note create-form path —
/// CredentialDataRequest::SecureNote goes through create_credential into the db,
/// credential_type is a real SecureNote variant, and the body reads back
/// verbatim (a per-item key encryption round trip).
#[tokio::test]
async fn create_credential_accepts_secure_note_request() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Recovery codes (form)".to_string();
    req.credential_type = "SecureNote".to_string();
    req.credential_data = CredentialDataRequest::SecureNote {
        note: "1111-2222\n3333-4444".to_string(),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("secure note created");

    // Read back: both the type label and the body are kept (multiline content is not collapsed).
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "SecureNote");
    assert_eq!(data.data["note"], "1111-2222\n3333-4444");

    // List read back: credential_type survives the db round trip without degrading to Custom.
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "SecureNote" && c.name == "Recovery codes (form)"));

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// 1Password alignment batch B: the Identity / Software License create-form
/// path — both CredentialDataRequest kinds go through create_credential into the
/// db, credential_type is a real variant, and the read-back fields are kept
/// verbatim (a per-item key encryption round trip) without degrading to Custom.
#[tokio::test]
async fn create_credential_accepts_identity_and_license_requests() {
    let (app, identity_id) = app_with_identity().await;

    // Identity: sensitive fields such as the document number are read back in full (get_credential_data goes through the sensitive gate).
    let mut req = password_credential_request(&identity_id);
    req.name = "Passport (main)".to_string();
    req.credential_type = "Identity".to_string();
    req.credential_data = CredentialDataRequest::Identity {
        first_name: "Alice".to_string(),
        last_name: "Zhang".to_string(),
        username: None,
        email: Some("alice@example.com".to_string()),
        phone: Some("+86 13800000000".to_string()),
        birthday: Some("1990-01-31".to_string()),
        address: Some("1 Main St\nBeijing".to_string()),
        id_number: Some("110101199001310011".to_string()),
        passport_number: Some("E12345678".to_string()),
        driver_license: None,
        tax_id: None,
        organization: Some("Example Inc".to_string()),
        job_title: Some("Engineer".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let identity_cred = resp.data.expect("identity credential created");

    let resp = get_credential_data(identity_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "Identity");
    assert_eq!(data.data["first_name"], "Alice");
    assert_eq!(data.data["id_number"], "110101199001310011");
    assert_eq!(data.data["passport_number"], "E12345678");
    assert_eq!(data.data["address"], "1 Main St\nBeijing");
    assert_eq!(data.data["seats"], serde_json::Value::Null);

    // SoftwareLicense: license_key reads back and seats round trips as a number.
    let mut req = password_credential_request(&identity_id);
    req.name = "JetBrains All Products".to_string();
    req.credential_type = "SoftwareLicense".to_string();
    req.credential_data = CredentialDataRequest::SoftwareLicense {
        license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
        version: Some("2024.2".to_string()),
        publisher: Some("JetBrains".to_string()),
        purchase_date: Some("2024-05-01".to_string()),
        order_number: None,
        support_email: None,
        download_url: Some("https://example.com/dl".to_string()),
        seats: Some(3),
        valid_until: Some("2027-05-01".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let license_cred = resp.data.expect("license credential created");

    let resp = get_credential_data(license_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "SoftwareLicense");
    assert_eq!(data.data["license_key"], "AAAA-BBBB-CCCC-DDDD");
    assert_eq!(data.data["seats"], serde_json::json!(3));
    assert_eq!(data.data["order_number"], serde_json::Value::Null);

    // List read back: both credential_type values survive the db round trip without degrading to Custom.
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "Identity" && c.name == "Passport (main)"));
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "SoftwareLicense" && c.name == "JetBrains All Products"));

    let resp = delete_credential(identity_cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = delete_credential(license_cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// Desktop stabilization: the credential-editing closed loop —
/// update_credential changes metadata and update_credential_data swaps the
/// ciphertext payload (reusing the original item key, the wrapped key stays
/// unchanged); both read back are verified verbatim; a nonexistent id errors.
#[tokio::test]
async fn update_credential_metadata_and_payload_round_trip() {
    let (app, identity_id) = app_with_identity().await;

    let req = password_credential_request(&identity_id);
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let created = resp.data.expect("credential created");
    assert_eq!(created.username.as_deref(), Some("alice"));

    // A metadata edit: rename + updating username/notes/tags (passing an empty string for url = clearing it).
    let resp = update_credential(
        UpdateCredentialRequest {
            id: created.id.clone(),
            name: "Renamed login".to_string(),
            security_level: Some("Critical".to_string()),
            url: Some("  ".to_string()),
            username: Some("newuser".to_string()),
            notes: Some("edited note".to_string()),
            tags: Some(vec!["work".to_string(), " ".to_string()]),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let meta = resp.data.expect("metadata updated");
    assert_eq!(meta.name, "Renamed login");
    assert_eq!(meta.security_level, "Critical");
    assert_eq!(meta.url, None, "blank url must clear");
    assert_eq!(meta.username.as_deref(), Some("newuser"));
    assert_eq!(meta.notes.as_deref(), Some("edited note"));
    assert_eq!(meta.tags, vec!["work".to_string()]);

    // A payload edit: changing the password (re-sealed with the original item key).
    let resp = update_credential_data(
        UpdateCredentialDataRequest {
            credential_id: created.id.clone(),
            credential_data: CredentialDataRequest::Password {
                password: "rotated-secret".to_string(),
                email: Some("edited@example.com".to_string()),
                security_questions: vec![],
            },
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let payload = resp.data.expect("payload updated");
    assert_eq!(
        payload.name, "Renamed login",
        "metadata survives payload edit"
    );
    // The item-key reuse invariant (the wrapped key bytes stay put) is asserted
    // in a dedicated core-layer test; SerializableCredential does not send back
    // key material, so the command layer does not duplicate that coverage.

    // Read back: the new password is kept verbatim and the metadata edits are all present.
    let resp = get_credential_data(created.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp
        .data
        .expect("credential data returned")
        .expect("present");
    assert_eq!(data.data["password"], "rotated-secret");
    assert_eq!(data.data["email"], "edited@example.com");

    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    let stored = creds
        .iter()
        .find(|c| c.id == created.id)
        .expect("credential listed");
    assert_eq!(stored.name, "Renamed login");
    assert_eq!(stored.username.as_deref(), Some("newuser"));
    assert_eq!(stored.notes.as_deref(), Some("edited note"));

    // A nonexistent id: both commands error explicitly.
    let ghost = uuid::Uuid::new_v4().to_string();
    let resp = update_credential(
        UpdateCredentialRequest {
            id: ghost.clone(),
            name: "x".to_string(),
            security_level: None,
            url: None,
            username: None,
            notes: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not found"));

    let resp = update_credential_data(
        UpdateCredentialDataRequest {
            credential_id: ghost,
            credential_data: CredentialDataRequest::Password {
                password: "x".to_string(),
                email: None,
                security_questions: vec![],
            },
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);

    let resp = delete_credential(created.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// 1Password alignment batch B: item history — creating and toggling
/// favorite write history rows automatically, and get_credential_history returns
/// the timeline (newest first) with field-level diffs.
#[tokio::test]
async fn credential_history_tracks_create_and_favorite_toggle() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Historied".to_string();
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");

    // Initially: created (v1) + the immediately following metadata top-up
    // updated (v2) — the desktop create command is create-then-update by
    // architecture, so two db writes are two real history entries
    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let history = resp.data.expect("history returned");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].change_type, "updated");
    assert_eq!(history[0].version, 2);
    // The top-up diff = the four metadata fields of the form: url/username/notes/tags
    assert_eq!(history[0].changes.len(), 4);
    assert!(history[0]
        .changes
        .iter()
        .all(|c| c.field != "encrypted_data"));
    assert_eq!(history[1].change_type, "created");
    assert_eq!(history[1].version, 1);

    // Toggling favorite -> an updated row whose diff contains only is_favorite
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    let history = resp.data.expect("history returned");
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].change_type, "updated");
    assert_eq!(history[0].version, 3);
    assert_eq!(history[0].changes.len(), 1);
    assert_eq!(history[0].changes[0].field, "is_favorite");
    assert_eq!(history[0].changes[0].old_value, "false");
    assert_eq!(history[0].changes[0].new_value, "true");

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// restore-to-version: metadata rolls back to the target version and a
/// restored history row is written; secrets are not rolled back (the history
/// snapshot holds no ciphertext).
#[tokio::test]
async fn restore_credential_version_reverts_metadata() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Versioned".to_string();
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");

    // Edit the metadata once more -> one more version
    let resp = update_credential(
        UpdateCredentialRequest {
            id: cred.id.clone(),
            name: "Renamed".to_string(),
            security_level: None,
            url: Some("https://renamed.example.com".to_string()),
            username: Some("bob".to_string()),
            notes: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Restore to v1 (the created state): the form top-up and the rename roll back together
    let resp = restore_credential_version(cred.id.clone(), 1, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let restored = resp.data.expect("restored");
    assert_eq!(restored.name, "Versioned");
    assert_eq!(restored.username, None);
    assert_eq!(restored.url, None);

    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    let history = resp.data.expect("history returned");
    assert_eq!(history[0].change_type, "restored");
    assert!(
        history[0].restorable,
        "restore rows carry a restorable state"
    );
    assert!(history[1].restorable);

    // An unknown version -> a business error rather than a panic
    let resp = restore_credential_version(cred.id.clone(), 99, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap_or_default().contains("99"));

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// The matrix of credential_type/security_level string arms of
/// create_credential, plus the normalization arms of url/username/notes/tags.
#[tokio::test]
async fn create_credential_type_and_security_level_matrix() {
    let (app, identity_id) = app_with_identity().await;

    let base = |name: &str, type_str: &str, level: &str| CreateCredentialRequest {
        identity_id: identity_id.clone(),
        name: name.to_string(),
        credential_type: type_str.to_string(),
        security_level: level.to_string(),
        url: Some("https://matrix.example".to_string()),
        username: Some("alice".to_string()),
        notes: Some("  kept  ".to_string()),
        tags: Some(vec!["a".to_string(), "  ".to_string(), "b".to_string()]),
        credential_data: CredentialDataRequest::Raw {
            data: vec![1, 2, 3],
        },
    };

    // The non-Password arms of credential_type (Password/TwoFactor already have test coverage).
    for type_str in [
        "CryptoWallet",
        "SshKey",
        "ApiKey",
        "BankCard",
        "GameAccount",
        "ServerConfig",
        "Certificate",
        "CustomStyle",
    ] {
        let resp = create_credential(
            base("Matrix", type_str, "Critical"),
            app.state::<AppState>(),
        )
        .await
        .unwrap();
        assert!(resp.success, "{type_str}: {:?}", resp.error);
        let cred = resp.data.expect("credential created");
        assert_eq!(cred.credential_type, type_str);
        assert_eq!(cred.security_level, "Critical");
        assert_eq!(cred.url.as_deref(), Some("https://matrix.example"));
        assert_eq!(cred.username.as_deref(), Some("alice"));
        assert_eq!(cred.notes.as_deref(), Some("kept"));
        assert_eq!(cred.tags, vec!["a".to_string(), "b".to_string()]);

        // The remaining arms of security_level + an unknown value falling back to Medium.
        for (level, expected) in [("High", "High"), ("Low", "Low"), ("Bogus", "Medium")] {
            let mut req = base("Levels", type_str, level);
            req.name = format!("Levels-{type_str}-{level}");
            let resp = create_credential(req, app.state::<AppState>())
                .await
                .unwrap();
            assert!(resp.success, "{type_str}/{level}: {:?}", resp.error);
            assert_eq!(resp.data.expect("credential").security_level, expected);
        }

        let resp = delete_credential(cred.id, app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{:?}", resp.error);
    }

    // A bad identity UUID also fails closed on get_credentials_for_identity.
    let resp = get_credentials_for_identity("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));
}
/// get_credential_data emits the right type label for all 8 CredentialData
/// variants. BankCard/ServerConfig have no corresponding command-layer request
/// variant, so they are constructed via the service directly.
#[tokio::test]
async fn get_credential_data_returns_type_labels_for_all_variants() {
    use persona_core::models::credential::{BankCardData, ServerConfigData};

    let (app, identity_id) = app_with_identity().await;
    let identity_uuid = uuid::Uuid::parse_str(&identity_id).unwrap();

    // Build 6 of them through the command layer (Password/CryptoWallet/SshKey/ApiKey/TwoFactor/Raw).
    let request_for = |name: &str, data: CredentialDataRequest| CreateCredentialRequest {
        identity_id: identity_id.clone(),
        name: name.to_string(),
        credential_type: "Raw".to_string(),
        security_level: "Medium".to_string(),
        url: None,
        username: None,
        notes: None,
        tags: None,
        credential_data: data,
    };
    let mut ids: Vec<(String, String)> = Vec::new();
    let variants: Vec<(&str, CredentialDataRequest)> = vec![
        (
            "PW",
            CredentialDataRequest::Password {
                password: "s3cret".to_string(),
                email: None,
                security_questions: vec![],
            },
        ),
        (
            "CW",
            CredentialDataRequest::CryptoWallet {
                wallet_type: "hd".to_string(),
                mnemonic_phrase: None,
                private_key: None,
                public_key: "pub".to_string(),
                address: "0xabc".to_string(),
                network: "Ethereum".to_string(),
                bip39_passphrase: Some("tungsten".to_string()),
            },
        ),
        (
            "SSH",
            CredentialDataRequest::SshKey {
                private_key: "priv".to_string(),
                public_key: "pub".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: None,
            },
        ),
        (
            "API",
            CredentialDataRequest::ApiKey {
                api_key: "key".to_string(),
                api_secret: None,
                token: None,
                permissions: vec![],
                expires_at: None,
            },
        ),
        (
            "TOTP",
            CredentialDataRequest::TwoFactor {
                secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
                issuer: "i".to_string(),
                account_name: "a".to_string(),
                algorithm: "SHA1".to_string(),
                digits: 6,
                period: 30,
                hotp: None,
                initial_counter: None,
            },
        ),
        ("RAW", CredentialDataRequest::Raw { data: vec![9] }),
    ];
    for (name, data) in variants {
        let resp = create_credential(request_for(name, data), app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{name}: {:?}", resp.error);
        ids.push((resp.data.expect("created").id, name.to_string()));
    }

    // BankCard/ServerConfig are built via the service directly (the command-layer request enum has neither of these).
    {
        let state = app.state::<AppState>();
        let guard = state.service.lock().await;
        let service = guard.as_ref().expect("service initialized");
        for data in [
            persona_core::models::credential::CredentialData::BankCard(BankCardData {
                card_number: "4111111111111111".to_string(),
                cardholder_name: "Alice".to_string(),
                expiry_date: "12/30".to_string(),
                cvv: "123".to_string(),
                bank_name: "Test Bank".to_string(),
                card_type: "visa".to_string(),
            }),
            persona_core::models::credential::CredentialData::ServerConfig(ServerConfigData {
                hostname: "server.example".to_string(),
                ip_address: None,
                port: 22,
                protocol: "ssh".to_string(),
                username: "root".to_string(),
                password: None,
                ssh_key_id: None,
                additional_config: std::collections::HashMap::new(),
            }),
        ] {
            let cred = service
                .create_credential(
                    identity_uuid,
                    format!("direct-{}", ids.len()),
                    persona_core::models::credential::CredentialType::Custom("Direct".into()),
                    persona_core::models::credential::SecurityLevel::Medium,
                    &data,
                )
                .await
                .unwrap();
            ids.push((cred.id.to_string(), "DIRECT".to_string()));
        }
    }

    // Read each one back: the type labels correspond one-to-one with the stored variants.
    for (id, _) in &ids {
        let resp = get_credential_data(id.clone(), app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{id}: {:?}", resp.error);
        let wrapper = resp.data.expect("data returned").expect("data present");
        assert!(
            [
                "Password",
                "CryptoWallet",
                "SshKey",
                "ApiKey",
                "TwoFactor",
                "Raw",
                "BankCard",
                "ServerConfig"
            ]
            .contains(&wrapper.credential_type.as_str()),
            "unexpected label {}",
            wrapper.credential_type
        );
    }
    // The labels of the 8 credentials together must cover all 8 kinds.
    let mut labels = std::collections::HashSet::new();
    for (id, _) in &ids {
        let resp = get_credential_data(id.clone(), app.state::<AppState>())
            .await
            .unwrap();
        labels.insert(resp.data.unwrap().unwrap().credential_type);
    }
    assert_eq!(labels.len(), 8, "all 8 variant labels covered: {labels:?}");

    // A bad UUID is still a format error.
    let resp = get_credential_data("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));
}
/// The service-error arms of the credential/identity commands while locked
/// (this batch of arms emits an ordinary error message and does not map to an
/// error code) + the mapped-error-code arms of the three audit commands.
#[tokio::test]
async fn locked_service_credential_error_surface() {
    let (app, identity_id) = app_with_identity().await;
    let existing = uuid::Uuid::new_v4().to_string();
    lock_service(app.state::<AppState>()).await.unwrap();

    // The get_identity Err arm of update_identity.
    let resp = update_identity(
        UpdateIdentityRequest {
            id: existing.clone(),
            name: "n".to_string(),
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
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get identity"),
        "got: {:?}",
        resp.error
    );

    // The get_credential Err arm of toggle_credential_favorite.
    let resp = toggle_credential_favorite(existing.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get credential"),
        "got: {:?}",
        resp.error
    );

    // The delete Err arm of delete_credential.
    let resp = delete_credential(existing.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to delete credential"),
        "got: {:?}",
        resp.error
    );

    // The query/statistics/cleanup Err arms of the three audit commands.
    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = audit_statistics(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = audit_cleanup(30, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    // After unlocking and recovering, statistics return normally (proving the failures above came only from being locked).
    let resp = reauth_verify(
        ReauthRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = audit_statistics(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    // The identity_id is still there (all the operations above failed and rolled back).
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(resp.data.unwrap().iter().any(|i| i.id == identity_id));
}
#[tokio::test]
async fn credential_commands_surface_db_errors_from_garbage_vault() {
    let app = app_with_garbage_db_service().await;
    let state = app.state::<AppState>();
    let bogus = "00000000-0000-0000-0000-000000000000".to_string();

    let resp = get_credentials_for_identity(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get credentials"),
        "got: {:?}",
        resp.error
    );

    let resp = create_credential(password_credential_request(&bogus), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to create credential"),
        "got: {:?}",
        resp.error
    );

    let resp = toggle_credential_favorite(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get credential"),
        "got: {:?}",
        resp.error
    );

    let resp = delete_credential(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to delete credential"),
        "got: {:?}",
        resp.error
    );

    let resp = get_credential_data(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get credential data"),
        "got: {:?}",
        resp.error
    );

    // totp follows the same discipline as the other commands: an infrastructure error lands as Ok(ApiResponse::error).
    let resp = get_totp_code(bogus.clone(), state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("file is not a database")),
        "expected sqlite error, got: {:?}",
        resp.error
    );

    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: bogus.clone(),
            field: "password".to_string(),
            item_password: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to reveal secret"),
        "got: {:?}",
        resp.error
    );

    // The scan relies on the repo pulling every credential, so a bad db must yield an error report (an Ok wrapping an error body).
    let resp = health_scan(None, state).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("file is not a database"),
        "got: {:?}",
        resp.error
    );
}
