use super::*;

#[test]
fn pairing_code_shape_and_normalization() {
    for _ in 0..64 {
        let code = generate_pairing_code();
        assert_eq!(code.len(), PAIRING_CODE_LEN);
        assert!(
            code.chars().all(|c| CROCKFORD.contains(&(c as u8))),
            "非法字形: {code}"
        );
    }
    // 易混字形映射 + 分隔符剔除
    assert_eq!(normalize_pairing_code("o i l-u"), "011V");
    assert_eq!(normalize_pairing_code("abcd-efgh"), "ABCDEFGH");
    assert_eq!(
        normalize_pairing_code(&generate_pairing_code()).len(),
        PAIRING_CODE_LEN
    );
}

#[test]
fn wrapped_group_key_with_bad_length_is_rejected() {
    let err = open_group_key_with(&[0u8; 32], &[0u8; 10]).unwrap_err();
    assert!(matches!(err, PersonaError::CryptographicError(_)));
}
