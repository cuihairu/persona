use super::*;

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn passkey_bridge_protocol_cases() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
    // Deterministic desktop-approval state: auto mode with no socket, so
    // every case below exercises the plain gesture-gate behavior.
    std::env::remove_var("PERSONA_BRIDGE_DESKTOP_APPROVAL");
    let no_socket = std::env::temp_dir().join(format!(
        "persona-no-approval-{}-passkey-protocol",
        std::process::id()
    ));
    std::env::set_var("PERSONA_PASSKEY_APPROVAL_SOCKET", &no_socket);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

    // ---- hello: request declaring v2 still gets the v7 capability set
    // (server reports its own protocol_version; old extensions stay
    // compatible by receiving unknown_type for new messages) ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "hello",
            serde_json::json!({
                "extension_id": "test-extension",
                "extension_version": "0.1.0",
                "protocol_version": 2,
                "client_instance_id": "instance-1"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "hello must succeed: {:?}", resp.error);
    let payload = resp.payload.unwrap();
    assert_eq!(payload["protocol_version"], 7);
    for capability in [
        "passkey_list",
        "passkey_create",
        "passkey_assert",
        "passkey_credential_provider_list",
        "passkey_credential_provider_assert",
        "find_for_save",
        "save_credential",
    ] {
        assert!(
            payload["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == capability),
            "capability {capability} must be advertised"
        );
    }
    let options_json = serde_json::json!({
        "rp": { "id": "example.com", "name": "Example" },
        "user": {
            "id": URL_SAFE_NO_PAD.encode(b"bridge-user-handle"),
            "name": "bob@example.com",
            "displayName": "Bob"
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    });
    let non_es256_options = serde_json::json!({
        "rp": { "id": "example.com" },
        "user": { "id": URL_SAFE_NO_PAD.encode(b"u"), "name": "b@example.com" },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -257 }],
    });

    // ---- passkey_list: happy path returns the seeded credential ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_list",
            serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "list must succeed: {:?}", resp.error);
    let items = resp.payload.unwrap()["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["rp_id"], "example.com");
    assert_eq!(items[0]["user_name"], "alice@example.com");
    assert!(items[0].get("credential_id").is_none(), "no key material");

    // ---- passkey_list: rp_id that doesn't match the origin ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_list",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "rp_id": "evil.example"
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("passkey_rp_mismatch"));

    // ---- passkey_list: missing gesture ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_list",
            serde_json::json!({ "origin": "https://example.com" }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("user_gesture_required"));

    // ---- passkey_create: happy path ----
    let client_data = local_client_data_for("https://example.com", "Y3JlYXRlLWNoYWxsZW5nZQ");
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "request_json": options_json,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&client_data),
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "create must succeed: {:?}", resp.error);
    let payload = resp.payload.unwrap();
    let attestation = URL_SAFE_NO_PAD
        .decode(payload["attestation_object_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        payload["transports"][0], "internal",
        "transports must be present"
    );
    assert!(attestation.len() > 100);

    // ---- passkey_create: non-ES256 algorithm refused ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "request_json": non_es256_options,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("passkey_alg_unsupported"));

    // ---- passkey_create: no active identity ----
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = NULL")
        .execute(db.pool())
        .await
        .unwrap();
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "request_json": options_json,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("no_active_identity"));
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(identity_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    // ---- passkey_create: missing gesture ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({
                "origin": "https://example.com",
                "request_json": options_json,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("user_gesture_required"));

    // ---- passkey_assert: happy path, verified by core's RP-check ----
    // The list's single item plus the one created above.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_list",
            serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
        ),
    )
    .await
    .unwrap();
    let items = resp.payload.unwrap()["items"].as_array().unwrap().clone();
    // The create case above added a second credential for the same RP;
    // assert against the seeded one explicitly (list order is not fixed).
    let item_id = items
        .iter()
        .find(|i| i["user_name"] == "alice@example.com")
        .expect("seeded passkey must be listed")["id"]
        .as_str()
        .unwrap()
        .to_string();

    let get_client_data =
            r#"{"type":"webauthn.get","challenge":"YXNzZXJ0LWNoYWxsZW5nZQ","origin":"https://example.com"}"#.to_string()
                .into_bytes();
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": item_id,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "assert must succeed: {:?}", resp.error);
    let payload = resp.payload.unwrap();
    let auth_data = URL_SAFE_NO_PAD
        .decode(payload["authenticator_data_b64"].as_str().unwrap())
        .unwrap();
    let signature = URL_SAFE_NO_PAD
        .decode(payload["signature_der_b64"].as_str().unwrap())
        .unwrap();
    let credential_id = URL_SAFE_NO_PAD
        .decode(payload["credential_id_b64"].as_str().unwrap())
        .unwrap();
    let user_handle = URL_SAFE_NO_PAD
        .decode(payload["user_handle_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(user_handle, b"user-handle-bytes");

    // Rebuild the public key from the stored COSE and verify like an RP.
    let db = open_db(&db_path).await.unwrap();
    let repo = persona_core::storage::PasskeyRepository::new(std::sync::Arc::new(db));
    let all = repo.find_by_rp_id("example.com").await.unwrap();
    let stored = all
        .iter()
        .find(|p| p.credential_id == credential_id)
        .expect("asserted credential must exist");
    persona_core::crypto::verify_assertion(
        &stored.public_key_cose,
        "example.com",
        &get_client_data,
        &auth_data,
        &signature,
    )
    .expect("bridge assertion must verify against the stored public key");

    // ---- passkey_credential_provider_list: same data, provider framing ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_credential_provider_list",
            serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "provider list must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "passkey_credential_provider_list_response");
    let provider_items = resp.payload.unwrap()["items"].as_array().unwrap().clone();
    assert_eq!(
        provider_items.len(),
        2,
        "same RP enumeration as passkey_list"
    );
    assert!(
        provider_items[0].get("credential_id").is_none(),
        "no key material"
    );

    // ---- provider list: rp_id that doesn't match the origin ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_credential_provider_list",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "rp_id": "evil.com"
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("passkey_rp_mismatch"));

    // ---- provider list: missing gesture ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_credential_provider_list",
            serde_json::json!({ "origin": "https://example.com" }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("user_gesture_required"));

    // ---- passkey_credential_provider_assert: provider trust path, same
    // product (desktop approval Unavailable in tests), audit via=os_provider ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_credential_provider_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": item_id,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "provider assert must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "passkey_credential_provider_assert_response");
    let payload = resp.payload.unwrap();
    assert_eq!(
        payload["item_id"], item_id,
        "provider path signs the same stored credential"
    );

    // ---- provider assert: unknown item ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_credential_provider_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": uuid::Uuid::new_v4().to_string(),
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("passkey_item_not_found"));

    // ---- passkey_list: explicit rp_id that matches the origin ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_list",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "rp_id": "example.com"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "list with rp_id must succeed: {:?}", resp.error);

    // ---- passkey_assert: passkey belongs to another identity ----
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(db.pool())
        .await
        .unwrap();
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": item_id,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("wrong_identity"));
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(identity_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    // ---- unknown message type yields an error response ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("definitely_not_a_type", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert!(!resp.ok, "unknown type must not succeed");
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("unknown_type")),
        "unexpected error: {:?}",
        resp.error
    );

    // ---- passkey_assert: origin does not match the passkey's rp_id ----
    let evil_client_data = local_client_data_for("https://evil.example", "ZXZpbA");
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://evil.example",
                "user_gesture": true,
                "item_id": item_id,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&evil_client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("passkey_rp_mismatch"));

    // ---- passkey_assert: unknown item ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": uuid::Uuid::new_v4().to_string(),
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("passkey_item_not_found"));

    // ---- passkey_assert: silent signing refused ----
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": item_id,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("user_gesture_required"));

    // ---- passkey_assert: corrupted sealed key surfaces as assert_failed ----
    // (last data-touching case: it invalidates the stored key material)
    let db = open_db(&db_path).await.unwrap();
    sqlx::query(
        "UPDATE passkeys SET encrypted_private_key = x'00', wrapped_item_key = x'00' WHERE id = ?",
    )
    .bind(item_id.clone())
    .execute(db.pool())
    .await
    .unwrap();
    drop(db);
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": item_id,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("passkey_assert_failed"));

    // ---- locked vault (no PERSONA_MASTER_PASSWORD) ----
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_list",
            serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("locked:"));
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    // ---- passkey_create: require mode with no desktop fails closed ----
    std::env::set_var("PERSONA_BRIDGE_DESKTOP_APPROVAL", "require");
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "request_json": options_json,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(local_client_data_for(
                    "https://example.com",
                    "Y3JlYXRlLWNoYWxsZW5nZQ",
                )),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("passkey_desktop_approval_required"),
        "got: {err}"
    );
    std::env::remove_var("PERSONA_BRIDGE_DESKTOP_APPROVAL");

    std::env::remove_var("PERSONA_PASSKEY_APPROVAL_SOCKET");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_passkey_payload_validation_errors() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;
    let good_client_data = local_client_data_for("https://example.com", "Y2hhbGxlbmdl");

    // passkey_list: malformed payload.
    let err = handle_request(
        &db_path,
        &state_dir,
        request("passkey_list", serde_json::json!({})),
    )
    .await
    .expect_err("passkey_list without origin must fail");
    assert!(
        err.to_string().contains("invalid payload for passkey_list"),
        "got: {err}"
    );

    // passkey_create: malformed payload (no request_json at all).
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
        ),
    )
    .await
    .expect_err("passkey_create without request_json must fail");
    assert!(
        err.to_string()
            .contains("invalid payload for passkey_create"),
        "got: {err}"
    );

    // passkey_create: client_data_json_b64 is not base64url.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "request_json": {
                    "rp": { "id": "example.com" },
                    "user": {
                        "id": URL_SAFE_NO_PAD.encode(b"u"),
                        "name": "b@example.com"
                    },
                    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
                },
                "client_data_json_b64": "!!!not-base64url!!!"
            }),
        ),
    )
    .await
    .expect_err("non-base64url client data must fail");
    assert!(
        err.to_string()
            .contains("client_data_json_b64 must be base64url"),
        "got: {err}"
    );

    // passkey_create: creation options rejected by core; the PersonaError
    // prefix is flattened away by flat_persona_error.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "request_json": {
                    "rp": { "id": "example.com" },
                    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
                },
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&good_client_data)
            }),
        ),
    )
    .await
    .expect_err("creation options without user must fail");
    assert!(
        err.to_string().starts_with("invalid_request"),
        "flat_persona_error must strip the human prefix, got: {err}"
    );

    // passkey_assert: malformed payload.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
        ),
    )
    .await
    .expect_err("passkey_assert without item_id must fail");
    assert!(
        err.to_string()
            .contains("invalid payload for passkey_assert"),
        "got: {err}"
    );

    // passkey_assert: non-UUID item id.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": "not-a-uuid",
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&good_client_data)
            }),
        ),
    )
    .await
    .expect_err("passkey_assert with a non-uuid item must fail");
    assert!(
        err.to_string().starts_with("invalid_request: item_id uuid"),
        "got: {err}"
    );

    // passkey_assert: client_data_json_b64 is not base64url.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": uuid::Uuid::new_v4().to_string(),
                "client_data_json_b64": "!!!not-base64url!!!"
            }),
        ),
    )
    .await
    .expect_err("non-base64url assert client data must fail");
    assert!(
        err.to_string()
            .contains("client_data_json_b64 must be base64url"),
        "got: {err}"
    );

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_passkey_assert_rejects_foreign_identity() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

    // The seeded passkey belongs to the seeded identity; read its id.
    let item_id: String = {
        let db = open_db(&db_path).await.unwrap();
        let row = sqlx::query("SELECT id FROM passkeys LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let id: String = sqlx::Row::get(&row, "id");
        drop(db);
        id
    };

    // Point the workspace at another identity: the assertion preflight
    // must refuse the passkey with wrong_identity.
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
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "item_id": item_id,
                "client_data_json_b64": "e30",
                "user_gesture": true
            }),
        ),
    )
    .await
    .expect_err("assert for a foreign identity must fail");
    assert!(err.to_string().starts_with("wrong_identity"), "got: {err}");

    // Restore the active identity so other assertions hold.
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE workspaces SET active_identity_id = ?")
        .bind(identity_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
