use super::*;

#[test]
fn determine_output_path_variants() {
    let out = determine_output_path(
        &ExportArgs {
            output: Some(PathBuf::from("/tmp/out.json")),
            ..args(&["alice"], "json")
        },
        &["alice".to_string()],
    )
    .unwrap();
    assert_eq!(out, PathBuf::from("/tmp/out.json"));

    let single = determine_output_path(&args(&["alice"], "json"), &["alice".to_string()]).unwrap();
    let name = single.to_string_lossy();
    assert!(name.starts_with("persona_export_alice_"));
    assert!(name.ends_with(".json"));

    let multi = determine_output_path(
        &args(&["alice"], "json"),
        &["alice".to_string(), "bob".to_string(), "carol".to_string()],
    )
    .unwrap();
    let name = multi.to_string_lossy();
    assert!(name.starts_with("persona_export_3_"));
    assert!(name.ends_with(".json"));
}

#[tokio::test]
async fn get_all_names_and_validation_without_users() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice", "bob"]).await;

    let all = get_all_identity_names(&config, &crate::utils::prompt::TerminalUi)
        .await
        .unwrap();
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["alice".to_string(), "bob".to_string()]);

    validate_identity_names(
        &["alice".to_string()],
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("existing name validates");
    let err = validate_identity_names(
        &["ghost".to_string()],
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("unknown name must fail");
    assert!(err.to_string().contains("Identity 'ghost' not found"));
}

#[test]
fn compress_creates_gzip_and_removes_source() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, b"payload").unwrap();

    compress_file(&path, 6).unwrap();

    let gz = dir.path().join("data.json.gz");
    assert!(gz.exists(), "gzip file created");
    assert!(!path.exists(), "source removed");

    // Decompressing restores the payload.
    let f = std::fs::File::open(&gz).unwrap();
    let mut decoder = flate2::read::GzDecoder::new(f);
    use std::io::Read;
    let mut restored = Vec::new();
    decoder.read_to_end(&mut restored).unwrap();
    assert_eq!(restored, b"payload");
}

#[tokio::test]
async fn perform_export_rejects_unknown_format() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;
    let out = dir.path().join("out.xml");

    let err = perform_export(
        &["alice".to_string()],
        &out,
        &args(&["alice"], "xml"),
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("unknown format must fail");
    assert!(err.to_string().contains("Unsupported export format: xml"));
}

#[test]
fn summary_and_info_render_without_state() {
    let dir = TempDir::new().unwrap();
    let config = CliConfig::default();
    let _ = config;

    let mut args = ExportArgs {
        names: vec!["alice".to_string(), "bob".to_string()],
        output: None,
        format: "json".to_string(),
        include_sensitive: true,
        encrypt: true,
        compression: 9,
        interactive: false,
    };
    args.compression = 9;
    let path = dir.path().join("out.json");
    std::fs::write(&path, "{}").unwrap();

    show_export_summary(&["alice".to_string(), "bob".to_string()], &path, &args).unwrap();
    show_export_info(&path).unwrap();
    // Missing files take the "no metadata" branch.
    show_export_info(&dir.path().join("missing.json")).unwrap();
}
