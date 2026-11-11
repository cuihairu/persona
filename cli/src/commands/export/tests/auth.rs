use super::*;

// ------------------------------------------------------------------
// execute_with: authenticated workspaces.
// ------------------------------------------------------------------

#[tokio::test]
async fn authenticated_sensitive_export_includes_credentials_and_passkey() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = authenticated_workspace(&dir, "master-pin").await;
    seed_credentials(&config, "master-pin").await;
    seed_passkey(&config, "master-pin", true).await;

    let out = dir.path().join("alice.json");
    let mut a = with_output(args(&["alice"], "json"), &out);
    a.include_sensitive = true;
    // The unlock prompt is answered twice: once during name validation,
    // once inside the JSON exporter; include_sensitive adds a second
    // confirmation between them.
    let ui = ScriptedUi::new()
        .password("master-pin")
        .confirm(true)
        .confirm(true)
        .password("master-pin");
    execute_with(a, &config, &ui)
        .await
        .expect("authenticated sensitive export succeeds");
    assert!(ui.exhausted());

    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let identities = value["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 1);
    let creds = identities[0]["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 2, "both credentials exported");
    let login = creds
        .iter()
        .find(|c| c["name"] == "Web login")
        .expect("login credential present");
    assert!(
        login.get("data").is_some(),
        "sensitive export decrypts data"
    );
    assert!(login.get("encrypted_data").is_none());
    let token = creds
        .iter()
        .find(|c| c["name"] == "API token")
        .expect("api credential present");
    assert!(token.get("data").is_some());

    let passkeys = identities[0]["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert!(
        passkeys[0].get("private_key").is_some(),
        "exportable passkey carries its private key"
    );
}

#[tokio::test]
async fn authenticated_sensitive_export_warns_on_corrupt_passkey_key() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = authenticated_workspace(&dir, "master-pin").await;
    let pk_id = seed_passkey(&config, "master-pin", true).await;

    // Corrupt the sealed key material so unsealing fails at export time.
    // (The repository's update() does not persist key columns, so poke
    // the row directly.)
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        sqlx::query("UPDATE passkeys SET encrypted_private_key = $2 WHERE id = $1")
            .bind(pk_id.to_string())
            .bind(vec![0xDEu8, 0xAD, 0xBE, 0xEF])
            .execute(db.pool())
            .await
            .unwrap();
    }

    let out = dir.path().join("alice-corrupt.json");
    let mut a = with_output(args(&["alice"], "json"), &out);
    a.include_sensitive = true;
    let ui = ScriptedUi::new()
        .password("master-pin")
        .confirm(true)
        .confirm(true)
        .password("master-pin");
    execute_with(a, &config, &ui)
        .await
        .expect("export succeeds despite the corrupt passkey");
    assert!(ui.exhausted());

    // The metadata row survives; only the private key is skipped.
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let passkeys = value["identities"][0]["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert!(
        passkeys[0].get("private_key").is_none(),
        "corrupt key is skipped with a warning"
    );
}

#[tokio::test]
async fn authenticated_export_without_sensitive_keeps_encrypted_blob() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = authenticated_workspace(&dir, "master-pin").await;
    seed_credentials(&config, "master-pin").await;
    // Non-exportable passkey: even a sensitive export skips the key.
    seed_passkey(&config, "master-pin", false).await;

    let out = dir.path().join("alice-safe.json");
    let ui = ScriptedUi::new()
        .password("master-pin")
        .confirm(true)
        .password("master-pin");
    execute_with(with_output(args(&["alice"], "json"), &out), &config, &ui)
        .await
        .expect("authenticated metadata export succeeds");
    assert!(ui.exhausted());

    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let identity = &value["identities"][0];
    let login = identity["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Web login")
        .unwrap()
        .clone();
    assert!(
        login.get("encrypted_data").is_some(),
        "metadata export keeps the encrypted blob"
    );
    assert!(login.get("data").is_none());
    let passkeys = identity["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert!(passkeys[0].get("private_key").is_none());
}

#[tokio::test]
async fn sensitive_export_warns_for_non_exportable_passkey() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = authenticated_workspace(&dir, "master-pin").await;
    seed_passkey(&config, "master-pin", false).await;

    let out = dir.path().join("alice-warn.json");
    let mut a = with_output(args(&["alice"], "json"), &out);
    a.include_sensitive = true;
    // Two unlocks (validation + JSON exporter) plus the plain and the
    // sensitive confirmations; the non-exportable passkey only warns.
    let ui = ScriptedUi::new()
        .password("master-pin")
        .confirm(true)
        .confirm(true)
        .password("master-pin");
    execute_with(a, &config, &ui)
        .await
        .expect("sensitive export with a non-exportable passkey succeeds");
    assert!(ui.exhausted());

    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let passkeys = value["identities"][0]["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert!(
        passkeys[0].get("private_key").is_none(),
        "non-exportable passkey must not carry its private key"
    );
}

#[tokio::test]
async fn execute_with_wrong_password_fails_during_validation() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = authenticated_workspace(&dir, "master-pin").await;

    // Name validation unlocks the workspace first: a scripted wrong
    // password aborts before any export happens.
    let ui = ScriptedUi::new().password("wrong-pin");
    let err = execute_with(
        with_output(args(&["alice"], "json"), &dir.path().join("x.json")),
        &config,
        &ui,
    )
    .await
    .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Authentication failed"));
    assert!(ui.exhausted());
}

#[tokio::test]
async fn authenticated_csv_export_unlocks_with_scripted_password() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = authenticated_workspace(&dir, "master-pin").await;
    seed_credentials(&config, "master-pin").await;

    let out = dir.path().join("alice.csv");
    // Name validation unlocks first, then the confirm gate, then the CSV
    // exporter unlocks again.
    let ui = ScriptedUi::new()
        .password("master-pin")
        .confirm(true)
        .password("master-pin");
    execute_with(with_output(args(&["alice"], "csv"), &out), &config, &ui)
        .await
        .expect("authenticated csv export succeeds");
    assert!(ui.exhausted());

    let csv = std::fs::read_to_string(&out).unwrap();
    assert!(csv.starts_with("Name,Type,Description,Email,Created,Modified"));
    assert!(csv.contains("alice"));
}

#[tokio::test]
async fn authenticated_csv_export_rejects_late_wrong_password() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = authenticated_workspace(&dir, "master-pin").await;
    seed_credentials(&config, "master-pin").await;

    // The name validation unlocks with the right password, then the CSV
    // exporter's own unlock fails — reaching the exporter's bail that a
    // single env-provided password can never hit.
    let out = dir.path().join("alice.csv");
    let ui = ScriptedUi::new()
        .password("master-pin")
        .confirm(true)
        .password("wrong-pin");
    let err = execute_with(with_output(args(&["alice"], "csv"), &out), &config, &ui)
        .await
        .expect_err("late wrong password must abort the csv export");
    assert!(
        err.to_string()
            .contains("Authentication failed: InvalidCredentials"),
        "got: {err}"
    );
    assert!(ui.exhausted());
    assert!(!out.exists(), "failed export writes nothing");
}
