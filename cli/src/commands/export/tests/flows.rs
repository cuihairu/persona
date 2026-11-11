use super::*;

#[tokio::test]
async fn encrypted_export_round_trips_through_passphrase_prompt() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;
    let out = dir.path().join("enc.json");

    let mut a = with_output(args(&["alice"], "json"), &out);
    a.encrypt = true;
    let ui = ScriptedUi::new().confirm(true).password("pass-phrase-1");
    execute_with(a, &config, &ui)
        .await
        .expect("encrypted export succeeds");
    assert!(ui.exhausted());

    // The output is no longer plaintext but decrypts back to the JSON.
    let raw = std::fs::read(&out).unwrap();
    assert!(
        raw.starts_with(b"PERSENC1"),
        "output carries the magic header"
    );
    let decrypted = crate::utils::file_crypto::decrypt_file_to_temp(&out, "pass-phrase-1")
        .expect("correct passphrase decrypts");
    let content = std::fs::read_to_string(&decrypted).unwrap();
    assert!(content.contains("alice"));
    std::fs::remove_file(&decrypted).unwrap();

    let err = crate::utils::file_crypto::decrypt_file_to_temp(&out, "wrong")
        .expect_err("wrong passphrase must fail");
    assert!(err.to_string().contains("Decryption failed"));
}

#[tokio::test]
async fn compressed_export_writes_gzip_archive() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;
    let out = dir.path().join("out.json");
    let gz = dir.path().join("out.json.gz");

    let mut a = with_output(args(&["alice"], "json"), &out);
    a.compression = 6;
    let ui = ScriptedUi::new().confirm(true);
    execute_with(a, &config, &ui)
        .await
        .expect("compressed export succeeds");
    assert!(ui.exhausted());
    assert!(!out.exists(), "plaintext file is replaced by the archive");
    assert!(gz.exists());

    let f = std::fs::File::open(&gz).unwrap();
    let mut decoder = flate2::read::GzDecoder::new(f);
    use std::io::Read;
    let mut restored = String::new();
    decoder.read_to_string(&mut restored).unwrap();
    assert!(restored.contains("alice"));
}

#[tokio::test]
async fn interactive_selection_maps_multi_select_indices() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice", "bob", "carol"]).await;

    // The scripted multi-select indices map back onto the listed
    // identities. find_all makes no ordering guarantee, so only the set
    // shape is asserted: indices 0 and 2 resolve to two distinct seeded
    // names.
    let ui = ScriptedUi::new().multi_select(&[0, 2]);
    let selected = select_identities_interactive(&config, &ui)
        .await
        .expect("interactive selection resolves names");
    assert!(ui.exhausted());
    let mut unique = selected.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 2, "indices 0 and 2 must map to distinct rows");
    assert!(selected
        .iter()
        .all(|n| ["alice", "bob", "carol"].contains(&n.as_str())));

    // A failing multi-select prompt propagates instead of panicking.
    let inner = ScriptedUi::new();
    let ui = FailOn::new(&inner, PromptKind::MultiSelect);
    let err = select_identities_interactive(&config, &ui)
        .await
        .expect_err("failing multi-select must abort");
    assert!(err.to_string().contains("failing ui: multi-select prompt"));
}

#[tokio::test]
async fn sensitive_export_skips_locked_passkey_private_keys() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = authenticated_workspace(&dir, "master-pin").await;
    seed_passkey(&config, "master-pin", false).await;

    let out = dir.path().join("locked-passkey.json");
    let mut a = with_output(args(&["alice"], "json"), &out);
    a.include_sensitive = true;
    let ui = ScriptedUi::new()
        .password("master-pin")
        .confirm(true)
        .confirm(true)
        .password("master-pin");
    execute_with(a, &config, &ui)
        .await
        .expect("sensitive export with a locked passkey still succeeds");
    assert!(ui.exhausted());

    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let passkeys = value["identities"][0]["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert!(
        passkeys[0].get("private_key").is_none(),
        "non-exportable passkeys must not carry a private key"
    );

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");
}
