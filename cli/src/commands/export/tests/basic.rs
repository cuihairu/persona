use super::*;

#[tokio::test]
async fn export_json_unencrypted_workspace_round_trip() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice", "bob"]).await;
    let out = dir.path().join("nested").join("out.json");

    perform_export(
        &["alice".to_string(), "bob".to_string()],
        &out,
        &args(&["alice", "bob"], "json"),
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("json export must succeed");

    let content = std::fs::read_to_string(&out).unwrap();
    let value: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(value["export_info"]["identities_count"], 2);
    let names: Vec<&str> = value["identities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"alice"));
    assert!(names.contains(&"bob"));
}

#[tokio::test]
async fn export_authenticated_path_with_master_password() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["carol"]).await;
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }

    // Wrong password fails before any file is written.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
    let out = dir.path().join("carol.json");
    let err = perform_export(
        &["carol".to_string()],
        &out,
        &args(&["carol"], "json"),
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Authentication failed"));

    // Correct password exports the identity.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
    perform_export(
        &["carol".to_string()],
        &out,
        &args(&["carol"], "json"),
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("correct password must export");
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("carol"));

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn export_yaml_and_csv_formats_without_users() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;

    let yaml_out = dir.path().join("out.yaml");
    perform_export(
        &["alice".to_string()],
        &yaml_out,
        &args(&["alice"], "yaml"),
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("yaml export must succeed");
    let yaml = std::fs::read_to_string(&yaml_out).unwrap();
    assert!(yaml.contains("alice"), "yaml contains identity");

    let csv_out = dir.path().join("out.csv");
    perform_export(
        &["alice".to_string()],
        &csv_out,
        &args(&["alice"], "csv"),
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("csv export must succeed");
    let csv = std::fs::read_to_string(&csv_out).unwrap();
    assert!(csv.starts_with("Name,Type,Description,Email,Created,Modified"));
    assert!(csv.contains("alice"));
}
