//! Command-layer integration tests — `credential_attach` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn attachment_commands_round_trip_encrypted() {
    let (app, identity_id) = app_with_identity().await;

    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");

    // 命令测试的 db 在 leaked tempdir 里；附件 blob 跟随同一目录
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("recovery-codes.txt");
    std::fs::write(&source, b"attachment-round-trip-payload").unwrap();

    // 加密挂载：元数据回读（is_encrypted / 文件名 / 大小）
    let resp = attach_file_to_credential(
        cred.id.clone(),
        source.to_string_lossy().to_string(),
        true,
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let attachment = resp.data.expect("attachment metadata returned");
    assert_eq!(attachment.filename, "recovery-codes.txt");
    assert!(attachment.is_encrypted);
    assert_eq!(
        attachment.size,
        b"attachment-round-trip-payload".len() as u64
    );
    let attachment_id = attachment.id;

    // 列表
    let resp = list_attachments(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let listed = resp.data.expect("attachments listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, attachment_id);

    // 解密保存：读回与源字节一致（凭据 item key 封存的核心保障）
    let out = source_dir.path().join("restored.txt");
    let resp = save_attachment_to_file(
        attachment_id.clone(),
        out.to_string_lossy().to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(
        std::fs::read(&out).unwrap(),
        b"attachment-round-trip-payload".to_vec()
    );

    // 删除 → 列表清空
    let resp = delete_attachment(attachment_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = list_attachments(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.expect("list after delete").is_empty());
}
#[tokio::test]
async fn attachment_commands_validate_uuid_and_delete_credential_cascades() {
    let (app, identity_id) = app_with_identity().await;

    // 坏 UUID 在四命令上都得到统一错误
    let resp = list_attachments("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    let resp = delete_attachment("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // 凭据删除级联清附件（命令层只验证可见效果：列表清空）
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let cred = resp.data.expect("credential created");

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("cascade.bin");
    std::fs::write(&source, b"cascade-payload").unwrap();
    let resp = attach_file_to_credential(
        cred.id.clone(),
        source.to_string_lossy().to_string(),
        true,
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = delete_credential(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = list_attachments(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.expect("cascade cleared").is_empty());
}
