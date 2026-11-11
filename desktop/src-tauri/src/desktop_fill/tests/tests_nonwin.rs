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
    // 正常：用户名第一个合格非密码框，密码第一个合格密码样式框
    let ok = vec![
        f(1, false, true, true, false),
        f(2, true, true, true, false),
        f(3, true, true, true, false),
    ];
    let c = classify_fields(&ok).unwrap();
    assert_eq!(c.username_hwnd, Some(1));
    assert_eq!(c.password_hwnd, 2);
    // 没有任何密码样式框：**整体拒绝**（不再猜"第二个框"）
    let plain_only = vec![
        f(7, false, true, true, false),
        f(8, false, true, true, false),
    ];
    assert!(classify_fields(&plain_only).is_none());
    // 全密码框：没有用户名框，只填密码
    let all_pwd = vec![f(1, true, true, true, false), f(2, true, true, true, false)];
    let c = classify_fields(&all_pwd).unwrap();
    assert_eq!(c.username_hwnd, None);
    assert_eq!(c.password_hwnd, 1);
    // 只读密码框不合格 → 拒绝
    let ro = vec![f(9, true, true, true, true)];
    assert!(classify_fields(&ro).is_none());
    // 隐藏密码框不合格 → 拒绝
    let hidden = vec![f(10, true, false, true, false)];
    assert!(classify_fields(&hidden).is_none());
    // 禁用密码框不合格 → 拒绝
    let disabled = vec![f(11, true, true, false, false)];
    assert!(classify_fields(&disabled).is_none());
    // 密码框合格但用户名框全部不合格：只填密码
    let pwd_only = vec![
        f(12, false, false, true, true),
        f(13, true, true, true, false),
    ];
    let c = classify_fields(&pwd_only).unwrap();
    assert_eq!(c.username_hwnd, None);
    assert_eq!(c.password_hwnd, 13);
    // 空目标
    assert!(classify_fields(&[]).is_none());
}
