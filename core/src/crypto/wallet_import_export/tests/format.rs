use super::*;

#[test]
fn test_format_parsing() {
    assert_eq!(
        parse_import_format("mnemonic").unwrap(),
        ImportFormat::Mnemonic
    );
    assert_eq!(
        parse_import_format("private_key").unwrap(),
        ImportFormat::PrivateKey
    );
    assert_eq!(parse_import_format("json").unwrap(), ImportFormat::Json);
    assert_eq!(
        parse_import_format("keystore").unwrap(),
        ImportFormat::Keystore
    );
    assert_eq!(parse_export_format("json").unwrap(), ExportFormat::Json);
}

#[test]
fn format_parsing_covers_every_variant_and_is_case_insensitive() {
    use ExportFormat as E;
    use ImportFormat as F;

    for (s, expected) in [
        ("MNEMONIC", F::Mnemonic),
        ("phrase", F::Mnemonic),
        ("Seed", F::Mnemonic),
        ("privatekey", F::PrivateKey),
        ("PRIVATE_KEY", F::PrivateKey),
        ("key", F::PrivateKey),
        ("JSON", F::Json),
        ("keystore", F::Keystore),
        ("WIF", F::Wif),
    ] {
        assert_eq!(parse_import_format(s).unwrap(), expected, "{s}");
    }
    assert!(parse_import_format("yaml")
        .err()
        .unwrap()
        .to_string()
        .contains("Unknown import format"));

    for (s, expected) in [
        ("mnemonic", E::Mnemonic),
        ("PHRASE", E::Mnemonic),
        ("seed", E::Mnemonic),
        ("privatekey", E::PrivateKey),
        ("private_key", E::PrivateKey),
        ("KEY", E::PrivateKey),
        ("wif", E::Wif),
        ("xpub", E::Xpub),
        ("extended_public_key", E::Xpub),
        ("json", E::Json),
        ("keystore", E::Keystore),
    ] {
        assert_eq!(parse_export_format(s).unwrap(), expected, "{s}");
    }
    assert!(parse_export_format("csv")
        .err()
        .unwrap()
        .to_string()
        .contains("Unknown export format"));
}
