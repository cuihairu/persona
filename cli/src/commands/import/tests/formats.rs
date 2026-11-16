use super::*;

fn sample_yaml() -> String {
    "export_info:\n  version: \"1.0\"\n  created: \"2024-01-01\"\nidentities:\n  - name: alice\n    type: personal\n  - name: bob\n    type: work\n".to_string()
}

fn sample_csv() -> String {
    "Name,Type,Description,Email,Created,Modified\ncarol,personal,desc,c@d.e,2024,2024\n"
        .to_string()
}

#[test]
fn parse_errors_name_the_offending_part() {
    // Broken JSON.
    let err = parse_json_import("{not json").expect_err("bad json must fail");
    assert!(err.to_string().contains("Failed to parse JSON"));

    // Missing export_info.
    let err = parse_json_import(r#"{"identities": []}"#).expect_err("must fail");
    assert!(err.to_string().contains("Missing export_info"));

    // Missing identities array.
    let err = parse_json_import(r#"{"export_info": {}}"#).expect_err("must fail");
    assert!(err.to_string().contains("identities"));

    // Missing identity name.
    let err = parse_json_import(r#"{"export_info": {}, "identities": [{"type": "personal"}]}"#)
        .expect_err("must fail");
    assert!(err.to_string().contains("Missing identity name"));

    // Broken YAML.
    let err = parse_yaml_import("identities: [unclosed").expect_err("bad yaml must fail");
    assert!(err.to_string().contains("YAML"));

    // An empty CSV yields zero identities.
    let data = parse_csv_import("Name,Type,Description,Email\n").unwrap();
    assert!(data.identities.is_empty());
}

#[test]
fn parse_import_file_handles_yml_extension() {
    let dir = TempDir::new().unwrap();
    let yml_path = dir.path().join("data.yml");
    std::fs::write(&yml_path, sample_yaml()).unwrap();
    let data = parse_import_file(&yml_path).unwrap();
    assert_eq!(data.identities.len(), 2);
}

#[test]
fn parse_all_three_formats_and_reject_unknown() {
    let dir = TempDir::new().unwrap();

    let json_path = dir.path().join("data.json");
    std::fs::write(&json_path, sample_json()).unwrap();
    let data = parse_import_file(&json_path).unwrap();
    assert_eq!(data.version, "1.0");
    assert_eq!(data.identities.len(), 2);
    assert_eq!(data.identities[0].name, "alice");
    assert_eq!(data.identities[0].email.as_deref(), Some("a@b.c"));
    assert_eq!(data.identities[0].tags, vec!["work".to_string()]);

    let yaml_path = dir.path().join("data.yaml");
    std::fs::write(&yaml_path, sample_yaml()).unwrap();
    let data = parse_import_file(&yaml_path).unwrap();
    assert_eq!(data.identities.len(), 2);
    assert_eq!(data.identities[1].name, "bob");

    let csv_path = dir.path().join("data.csv");
    std::fs::write(&csv_path, sample_csv()).unwrap();
    let data = parse_import_file(&csv_path).unwrap();
    assert_eq!(data.version, "csv");
    assert_eq!(data.identities.len(), 1);
    assert_eq!(data.identities[0].name, "carol");
    assert_eq!(data.identities[0].email.as_deref(), Some("c@d.e"));

    // CSV rows with fewer than 4 fields are skipped.
    let short_csv = dir.path().join("short.csv");
    std::fs::write(&short_csv, "Name,Type\nbroken,row\n").unwrap();
    let data = parse_import_file(&short_csv).unwrap();
    assert!(data.identities.is_empty());

    let txt_path = dir.path().join("data.txt");
    std::fs::write(&txt_path, "junk").unwrap();
    let err = parse_import_file(&txt_path).expect_err("unknown format must fail");
    assert!(err.to_string().contains("Unsupported import format: txt"));
}

#[test]
fn validate_warns_on_oversized_file_and_csv_maps_empty_email() {
    let dir = TempDir::new().unwrap();
    // A sparse file reports >100 MB without occupying that much disk;
    // validation still passes (the size check only warns).
    let big = dir.path().join("huge.json");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(101 * 1024 * 1024).unwrap();
    drop(f);
    validate_import_file(&big).expect("oversized file still validates");

    // A CSV row with an empty email column stores None, not Some("").
    let data = parse_csv_import("Name,Type,Description,Email\nzed,personal,quiet,\n").unwrap();
    assert_eq!(data.identities.len(), 1);
    assert_eq!(data.identities[0].name, "zed");
    assert_eq!(data.identities[0].description, "quiet");
    assert_eq!(data.identities[0].email, None);
}
