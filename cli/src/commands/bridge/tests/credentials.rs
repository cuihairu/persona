use super::*;

/// Bridge protocol v4 write path: find_for_save matching + save_credential
/// create/update semantics and every gate on the way (gesture, empty
/// password, origin binding, identity scoping, lock state).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn save_credential_protocol_cases() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
    // Same deterministic no-desktop setup as the passkey cases: auto
    // mode with no socket ⇒ the plain gesture gate applies.
    std::env::remove_var("PERSONA_BRIDGE_DESKTOP_APPROVAL");
    let no_socket = std::env::temp_dir().join(format!(
        "persona-no-approval-{}-save-protocol",
        std::process::id()
    ));
    std::env::set_var("PERSONA_PASSKEY_APPROVAL_SOCKET", &no_socket);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

    // ---- find_for_save: empty vault for this host ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "find_for_save",
            serde_json::json!({
                "origin": "https://example.com",
                "username": "bob@example.com"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "find_for_save must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "find_for_save_response");
    assert_eq!(
        resp.payload.unwrap()["matches"].as_array().unwrap().len(),
        0
    );

    // ---- save_credential: gesture required ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "username": "bob@example.com",
                "password": "s3cret-new"
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().starts_with("user_gesture_required"),
        "got: {err}"
    );

    // ---- save_credential: empty password refused ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "username": "bob@example.com",
                "password": "",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("invalid_payload"), "got: {err}");

    // ---- save_credential: create happy path ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "username": "Bob@Example.com",
                "password": "s3cret-new",
                "name_hint": "Example Login",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "save create must succeed: {:?}", resp.error);
    let payload = resp.payload.unwrap();
    assert_eq!(payload["action"], "created");
    assert_eq!(payload["name"], "Example Login");
    let item_id = payload["item_id"].as_str().unwrap().to_string();

    // Presentation fields landed: url = origin, username = submitted
    // (trimmed), email picked up from the username, payload decryptable.
    let service = {
        let db = open_db(&db_path).await.unwrap();
        let mut service = crate::commands::service::new_service(db.clone())
            .await
            .unwrap();
        assert_eq!(
            service.authenticate_user(PASSWORD).await.unwrap(),
            persona_core::auth::authentication::AuthResult::Success
        );
        drop(db);
        service
    };
    let created_id = uuid::Uuid::parse_str(&item_id).unwrap();
    let created = service.get_credential(&created_id).await.unwrap().unwrap();
    assert_eq!(created.url.as_deref(), Some("https://example.com"));
    assert_eq!(created.username.as_deref(), Some("Bob@Example.com"));
    match service.get_credential_data(&created_id).await.unwrap() {
        Some(CredentialData::Password(p)) => {
            assert_eq!(p.password, "s3cret-new");
            assert_eq!(p.email.as_deref(), Some("Bob@Example.com"));
        }
        other => panic!("expected password payload, got {other:?}"),
    }

    // ---- find_for_save now matches (username compare is case-insensitive) ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "find_for_save",
            serde_json::json!({
                "origin": "https://example.com",
                "username": "bob@example.com"
            }),
        ),
    )
    .await
    .unwrap();
    let matches = resp.payload.unwrap()["matches"].as_array().unwrap().clone();
    assert_eq!(matches.len(), 1, "case-insensitive username match");
    assert_eq!(matches[0]["item_id"], item_id);

    // ---- find_for_save: different username → no match ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "find_for_save",
            serde_json::json!({
                "origin": "https://example.com",
                "username": "someone-else@example.com"
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.payload.unwrap()["matches"].as_array().unwrap().len(),
        0
    );

    // ---- save_credential: update happy path keeps non-password payload ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": item_id,
                "password": "rotated-pass-2",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "save update must succeed: {:?}", resp.error);
    let payload = resp.payload.unwrap();
    assert_eq!(payload["action"], "updated");
    assert_eq!(payload["item_id"], item_id.as_str());
    match service.get_credential_data(&created_id).await.unwrap() {
        Some(CredentialData::Password(p)) => {
            assert_eq!(p.password, "rotated-pass-2");
            assert_eq!(
                p.email.as_deref(),
                Some("Bob@Example.com"),
                "update must preserve non-password payload fields"
            );
        }
        other => panic!("expected password payload, got {other:?}"),
    }

    // ---- save_credential: update a non-password item is refused ----
    use persona_core::models::credential::{BankCardData, SecurityLevel};
    let card = service
        .create_credential(
            identity_id,
            "Test Card".to_string(),
            CredentialType::BankCard,
            SecurityLevel::Medium,
            &CredentialData::BankCard(BankCardData {
                card_number: "4111111111111111".to_string(),
                cardholder_name: "Bob".to_string(),
                expiry_date: "12/30".to_string(),
                cvv: "123".to_string(),
                bank_name: "Test Bank".to_string(),
                card_type: "visa".to_string(),
            }),
        )
        .await
        .unwrap();
    drop(service);
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": card.id.to_string(),
                "password": "x",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().starts_with("unsupported_credential_type"),
        "got: {err}"
    );

    // ---- save_credential: update unknown item ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": uuid::Uuid::new_v4().to_string(),
                "password": "x",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("not_found"), "got: {err}");

    // ---- save_credential: update across origins is refused ----
    // (credential bound to example.com, request origin is other.example)
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://other.example",
                "item_id": item_id,
                "password": "x",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("origin_mismatch"), "got: {err}");

    // ---- save_credential: wrong identity ----
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": item_id,
                "password": "x",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("wrong_identity"), "got: {err}");

    // ---- save_credential: create without an active identity ----
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = NULL")
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "username": "bob@example.com",
                "password": "x",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().starts_with("no_active_identity"),
        "got: {err}"
    );
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(identity_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    // ---- locked vault (no PERSONA_MASTER_PASSWORD) ----
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "save_credential",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": item_id,
                "password": "x",
                "user_gesture": true
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("locked"), "got: {err}");

    std::env::remove_var("PERSONA_PASSKEY_APPROVAL_SOCKET");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
}

/// Bridge protocol v5 password generator: defaults, custom
/// charsets, passphrase mode, the locked gate, and the payload
/// validation rails (extension UI shows invalid_payload verbatim).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn generate_password_protocol_cases() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
    std::env::remove_var("PERSONA_BRIDGE_DESKTOP_APPROVAL");
    let no_socket = std::env::temp_dir().join(format!(
        "persona-no-approval-{}-generate",
        std::process::id()
    ));
    std::env::set_var("PERSONA_PASSKEY_APPROVAL_SOCKET", &no_socket);

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

    const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    // ---- defaults: 16 chars over all character sets ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("generate_password", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert!(resp.ok, "default generation must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "generate_password_response");
    let default_password = resp.payload.unwrap()["password"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(default_password.len(), 16);

    // ---- custom length with symbols off ⇒ no symbol characters ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "generate_password",
            serde_json::json!({
                "length": 24,
                "include_symbols": false
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "custom generation must succeed: {:?}", resp.error);
    let custom_payload = resp.payload.unwrap();
    let password = custom_payload["password"].as_str().unwrap();
    assert_eq!(password.len(), 24);
    assert!(
        !password.chars().any(|c| SYMBOLS.contains(c)),
        "symbols disabled but password contains one: {password}"
    );

    // ---- passphrase mode: n words joined with '-' ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("generate_password", serde_json::json!({ "words": 3 })),
    )
    .await
    .unwrap();
    assert!(
        resp.ok,
        "passphrase generation must succeed: {:?}",
        resp.error
    );
    let passphrase_payload = resp.payload.unwrap();
    let passphrase = passphrase_payload["password"].as_str().unwrap();
    assert_eq!(
        passphrase.split('-').count(),
        3,
        "3-word passphrase must be exactly 3 hyphen-joined words: {passphrase}"
    );

    // NOTE: generation is vault-independent (pure entropy — no db
    // open, no master password), so there is no "locked" state to
    // test here; the pairing/HMAC session gate above is the only
    // auth on the message, same as get_suggestions.

    // ---- validation rails ----
    for (label, payload) in [
        ("length below minimum", serde_json::json!({ "length": 3 })),
        (
            "length above maximum",
            serde_json::json!({ "length": 10_001 }),
        ),
        (
            "all charsets disabled",
            serde_json::json!({
                "include_lowercase": false,
                "include_uppercase": false,
                "include_digits": false,
                "include_symbols": false
            }),
        ),
        ("words below range", serde_json::json!({ "words": 2 })),
        ("words above range", serde_json::json!({ "words": 11 })),
    ] {
        let err = handle_request(&db_path, &state_dir, request("generate_password", payload))
            .await
            .unwrap_err();
        assert!(
            err.to_string().starts_with("invalid_payload"),
            "{label}: got {err}"
        );
    }

    std::env::remove_var("PERSONA_PASSKEY_APPROVAL_SOCKET");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
}
