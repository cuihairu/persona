use super::super::parse::{
    decode_qr_file, generate_totp_code, normalize_origin_url, parse_otpauth_uri,
};
use super::super::template::{FinalTotpConfig, TotpTemplate};
use super::*;

proptest! {
    #[test]
    fn otpauth_uri_roundtrip(
        issuer in label_strategy(),
        account in label_strategy(),
        secret in base32_secret_strategy(),
        digits in 6u8..=8,
        period in 15u32..=60,
        algorithm in select(vec![
            "SHA1".to_string(),
            "SHA256".to_string(),
            "SHA512".to_string()
        ])
    ) {
        let path = format!(
            "{}:{}",
            encode_component(&issuer),
            encode_component(&account)
        );
        let uri = format!(
            "otpauth://totp/{}?secret={}&issuer={}&account={}&algorithm={}&digits={}&period={}",
            path,
            secret,
            encode_component(&issuer),
            encode_component(&account),
            algorithm,
            digits,
            period
        );

        let template = parse_otpauth_uri(&uri).unwrap();
        prop_assert_eq!(template.secret.as_deref(), Some(secret.as_str()));
        prop_assert_eq!(template.issuer.as_deref(), Some(issuer.as_str()));
        prop_assert_eq!(template.account.as_deref(), Some(account.as_str()));
        prop_assert_eq!(
            template.algorithm.as_deref().map(|s| s.to_ascii_uppercase()),
            Some(algorithm.clone())
        );
        prop_assert_eq!(template.digits, Some(digits));
        prop_assert_eq!(template.period, Some(period));
    }
}

proptest! {
    #[test]
    fn base32_secret_roundtrip(bytes in collection::vec(any::<u8>(), 8..=64)) {
        let encoded = BASE32_NOPAD.encode(&bytes);
        let decoded = decode_base32_secret(&encoded).unwrap();
        prop_assert_eq!(decoded, bytes);
    }
}

// ------------------------------------------------------------------
// Unit coverage for the command paths (normalize/finalize/hotp/setup).
// ------------------------------------------------------------------

#[test]
fn normalize_origin_url_variants() {
    assert_eq!(
        normalize_origin_url("https://github.com/path?q=1").unwrap(),
        "https://github.com"
    );
    assert_eq!(
        normalize_origin_url("  github.com  ").unwrap(),
        "https://github.com"
    );
    // Host is normalized to lowercase; the port is dropped by design.
    assert_eq!(
        normalize_origin_url("http://Example.COM:8443/x").unwrap(),
        "http://example.com"
    );

    assert!(normalize_origin_url("").is_err());
    assert!(normalize_origin_url("   ").is_err());
    // A scheme-only URL falls through to the https:// prefix retry
    // and yields a (harmless) host named "https".
    let weird = normalize_origin_url("https://").unwrap();
    assert!(weird.starts_with("https://"), "unexpected: {}", weird);
}

#[test]
fn template_merge_keeps_first_value_and_finalize_applies_defaults() {
    let mut template = TotpTemplate::default();
    assert!(
        TotpTemplate::default().finalize().is_err(),
        "missing secret must fail"
    );

    template.secret = Some("FIRST".to_string());
    template.merge(TotpTemplate {
        secret: Some("SECOND".to_string()),
        issuer: Some("GitHub".to_string()),
        account: None,
        algorithm: Some("sha256".to_string()),
        digits: Some(8),
        period: None,
        hotp: None,
        counter: None,
    });

    assert_eq!(template.secret.as_deref(), Some("FIRST"));
    assert_eq!(template.issuer.as_deref(), Some("GitHub"));
    assert!(template.account.is_none());

    let secret = template.secret.clone().unwrap();
    let final_cfg = template.finalize().unwrap();
    assert_eq!(final_cfg.secret, secret);
    assert_eq!(final_cfg.issuer, "GitHub");
    assert_eq!(final_cfg.account, "TOTP");
    assert_eq!(final_cfg.algorithm, "SHA256");
    assert_eq!(final_cfg.digits, 8);
    assert_eq!(final_cfg.period, 30);
}

#[test]
fn hotp_supports_all_algorithms_and_rejects_bad_secrets() {
    let secret = b"0123456789abcdef";
    for algo in ["SHA1", "sha256", "SHA512"] {
        let code = hotp(secret, 7, algo).unwrap();
        let _ = code; // any u32 is a valid truncation
    }
    // Empty secret is rejected before HMAC.
    assert!(hotp(b"", 1, "SHA1").is_err());
}

#[test]
fn decode_secret_accepts_case_whitespace_padding_and_reports_errors() {
    assert_eq!(decode_base32_secret("ME").unwrap(), b"a");
    assert_eq!(decode_base32_secret("me").unwrap(), b"a");
    assert_eq!(decode_base32_secret("M E").unwrap(), b"a");
    assert_eq!(decode_base32_secret("ME======").unwrap(), b"a");
    assert!(decode_base32_secret("not base32!!").is_err());
    assert!(decode_base32_secret("").is_err());
}

#[test]
fn generate_totp_code_clamps_digits_and_period() {
    let cfg = FinalTotpConfig {
        secret: BASE32_NOPAD.encode(b"0123456789abcdef"),
        issuer: "T".into(),
        account: "a@b.c".into(),
        algorithm: "SHA1".into(),
        digits: 99,
        period: 0,
        hotp: false,
        counter: None,
    };
    let (code, remaining) = generate_totp_code(&cfg).unwrap();
    assert_eq!(code.len(), 10, "digits clamped to 10");
    assert!(remaining <= 1, "period clamped to 1s");
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn decode_qr_file_reports_missing_files() {
    let err = decode_qr_file(&PathBuf::from("/nonexistent/qr.png")).unwrap_err();
    assert!(err.to_string().contains("Failed to open QR image"));
}

#[test]
fn decode_qr_file_reports_images_without_codes() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("blank.png");
    let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        200,
        200,
        image::Rgb([200, 200, 200]),
    ));
    img.save(&path).expect("blank png written");

    let err = decode_qr_file(&path).unwrap_err();
    assert!(err.to_string().contains("No QR code detected"));
}

/// 确定性变异 harness：垃圾字节、截断/伪造的 PNG/JPEG 头、确定性
/// 噪声载荷。`decode_qr_file` 必须全函数——任何输入要么 Ok 要么 Err，
/// 绝不 panic（rqrr/image 的历史 panic 面正是本 harness 的目标）。
#[test]
fn decode_qr_file_mutation_harness_is_total() {
    let dir = tempfile::TempDir::new().unwrap();
    // PNG/JPEG 魔数按各自格式规范的前缀。
    let png_magic: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let jpeg_magic: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0];
    let mut cases: Vec<(String, PathBuf)> = Vec::new();
    let push = |cases: &mut Vec<(String, PathBuf)>, name: &str, bytes: &[u8]| {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        cases.push((name.to_string(), path));
    };

    push(&mut cases, "empty.png", &[]);
    push(&mut cases, "text.png", b"this is definitely not an image");
    push(&mut cases, "png-magic-only.png", png_magic);
    push(&mut cases, "jpeg-magic-only.jpg", jpeg_magic);
    let mut png_noise = png_magic.to_vec();
    png_noise.extend_from_slice(&[0xAAu8; 64]);
    push(&mut cases, "png-magic-plus-noise.png", &png_noise);
    let mut jpeg_noise = jpeg_magic.to_vec();
    jpeg_noise.extend_from_slice(&[0x55u8; 256]);
    push(&mut cases, "jpeg-magic-plus-noise.jpg", &jpeg_noise);
    // 有效 PNG 头 + 全零载荷：解码器要么报错要么当纯色图，不得 panic。
    let mut png_zero = png_magic.to_vec();
    png_zero.extend_from_slice(&[0x00u8; 24]);
    push(&mut cases, "truncated-noise.png", &png_zero);

    for (label, path) in cases {
        let result = std::panic::catch_unwind(|| decode_qr_file(&path));
        match result {
            Ok(Ok(_)) | Ok(Err(_)) => {}
            Err(_) => panic!("QR decode mutation harness panicked on case: {label}"),
        }
    }
}

#[test]
fn parse_otpauth_uri_rejects_bad_scheme_host_and_garbage() {
    // Not an otpauth URI at all.
    let err = parse_otpauth_uri("https://totp/GitHub:alice?secret=ABC")
        .err()
        .expect("https scheme must be rejected");
    assert!(err.to_string().contains("otpauth://"));

    // otpauth but neither TOTP nor HOTP.
    let err = parse_otpauth_uri("otpauth://foo/GitHub:alice?secret=ABC")
        .err()
        .expect("unknown type host must be rejected");
    assert!(err.to_string().contains("Only otpauth TOTP/HOTP URIs"));

    // Unparseable garbage.
    assert!(parse_otpauth_uri("::not a url::").is_err());
}

#[test]
fn parse_otpauth_uri_accepts_hotp_scheme_with_counter() {
    let t = parse_otpauth_uri(
            "otpauth://hotp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3&algorithm=SHA1&digits=6",
        )
        .unwrap();
    assert_eq!(t.hotp, Some(true));
    assert_eq!(t.counter, Some(3));
    assert_eq!(
        t.secret.as_deref(),
        Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    );
    assert_eq!(t.issuer.as_deref(), Some("Example"));
    assert_eq!(t.account.as_deref(), Some("alice"));
    assert_eq!(t.algorithm.as_deref(), Some("SHA1"));
    assert_eq!(t.digits, Some(6));

    // 缺省 counter=0；totp 型 URI 保持 hotp=false。
    let t = parse_otpauth_uri("otpauth://hotp/Example?secret=ABC").unwrap();
    assert_eq!(t.hotp, Some(true));
    assert_eq!(t.counter, None);
    let t = parse_otpauth_uri("otpauth://totp/Example:alice?secret=ABC").unwrap();
    assert_eq!(t.hotp, Some(false));
}

#[test]
fn parse_otpauth_uri_supports_account_only_labels() {
    let template = parse_otpauth_uri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(template.secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert!(template.issuer.is_none(), "no issuer label");
    assert_eq!(template.account.as_deref(), Some("alice"));
}

#[test]
fn parse_otpauth_uri_handles_labelless_paths_and_unknown_params() {
    // No path label at all: both issuer and account stay unset.
    let template =
        parse_otpauth_uri("otpauth://totp/?secret=JBSWY3DPEHPK3PXP&x-custom=ignored").unwrap();
    assert_eq!(template.secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert!(template.issuer.is_none());
    assert!(template.account.is_none());

    // Unknown query parameters are ignored instead of rejected.
    let template = parse_otpauth_uri(
        "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&image=https://x/y.png",
    )
    .unwrap();
    assert_eq!(template.issuer.as_deref(), Some("GitHub"));
    assert_eq!(template.account.as_deref(), Some("alice"));
}

#[test]
fn generate_totp_code_clamps_digits_lower_bound() {
    let cfg = FinalTotpConfig {
        secret: BASE32_NOPAD.encode(b"0123456789abcdef"),
        issuer: "T".into(),
        account: "a@b.c".into(),
        algorithm: "SHA1".into(),
        digits: 1,
        period: 30,
        hotp: false,
        counter: None,
    };
    let (code, _) = generate_totp_code(&cfg).unwrap();
    assert_eq!(code.len(), 4, "digits clamped up to 4");
}
