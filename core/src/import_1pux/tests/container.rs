use super::*;

use proptest::prelude::*;

#[test]
fn non_zip_input_is_rejected() {
    assert!(parse_1pux(b"definitely not a zip file").is_err());
}

#[test]
fn invalid_json_is_rejected() {
    let bytes = make_1pux(&attributes_json(3), "not json at all");
    let err = parse_1pux(&bytes).unwrap_err().to_string();
    assert!(err.contains("export.data"), "unexpected error: {err}");
}

#[test]
fn missing_export_data_is_rejected() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "export.attributes",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    writer.write_all(attributes_json(3).as_bytes()).unwrap();
    let bytes = writer.finish().unwrap().into_inner();

    let err = parse_1pux(&bytes).unwrap_err().to_string();
    assert!(err.contains("export.data"), "unexpected error: {err}");
}

#[test]
fn unexpected_version_parses_with_warning() {
    let bytes = make_1pux(&attributes_json(2), &json!({ "accounts": [] }).to_string());
    assert!(parse_1pux(&bytes).is_ok());
}

proptest! {
    #[test]
    fn parse_arbitrary_bytes_never_panics(data in prop::collection::vec(any::<u8>(), 0..8192)) {
        // Whether it parses or errors, arbitrary input must not panic.
        let _ = parse_1pux(&data);
    }
}
