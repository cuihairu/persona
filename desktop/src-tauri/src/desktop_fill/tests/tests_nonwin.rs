use super::{classify_fields, fill_supported, FieldState};

#[test]
fn platform_reports_unsupported() {
    assert!(!fill_supported(), "non-windows must report unsupported");
}

#[test]
fn classification_requires_eligible_es_password_field() {
    let f = |hwnd: isize, pwd: bool, vis: bool, en: bool, ro: bool| FieldState {
        hwnd,
        is_password: pwd,
        visible: vis,
        enabled: en,
        read_only: ro,
    };
    // Normal case: username is the first eligible non-password field, password is
    // the first eligible password-styled field
    let ok = vec![
        f(1, false, true, true, false),
        f(2, true, true, true, false),
        f(3, true, true, true, false),
    ];
    let c = classify_fields(&ok).unwrap();
    assert_eq!(c.username_hwnd, Some(1));
    assert_eq!(c.password_hwnd, 2);
    // No password-styled field at all: **reject outright** (no longer guessing
    // "the second field")
    let plain_only = vec![
        f(7, false, true, true, false),
        f(8, false, true, true, false),
    ];
    assert!(classify_fields(&plain_only).is_none());
    // All password fields: no username field, fill the password only
    let all_pwd = vec![f(1, true, true, true, false), f(2, true, true, true, false)];
    let c = classify_fields(&all_pwd).unwrap();
    assert_eq!(c.username_hwnd, None);
    assert_eq!(c.password_hwnd, 1);
    // Read-only password field is ineligible → reject
    let ro = vec![f(9, true, true, true, true)];
    assert!(classify_fields(&ro).is_none());
    // Hidden password field is ineligible → reject
    let hidden = vec![f(10, true, false, true, false)];
    assert!(classify_fields(&hidden).is_none());
    // Disabled password field is ineligible → reject
    let disabled = vec![f(11, true, true, false, false)];
    assert!(classify_fields(&disabled).is_none());
    // Password field eligible but all username fields ineligible: fill the
    // password only
    let pwd_only = vec![
        f(12, false, false, true, true),
        f(13, true, true, true, false),
    ];
    let c = classify_fields(&pwd_only).unwrap();
    assert_eq!(c.username_hwnd, None);
    assert_eq!(c.password_hwnd, 13);
    // Empty target
    assert!(classify_fields(&[]).is_none());
}
