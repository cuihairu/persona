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

    // The command tests' db lives in a leaked tempdir; attachment blobs follow the same directory
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("recovery-codes.txt");
    std::fs::write(&source, b"attachment-round-trip-payload").unwrap();

    // Encrypted attach: metadata read back (is_encrypted / filename / size)
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

    // Listing
    let resp = list_attachments(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let listed = resp.data.expect("attachments listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, attachment_id);

    // Decrypted save: read back identical to the source bytes (the core guarantee of the credential item key seal)
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

    // Delete -> the list is emptied
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

    // A bad UUID yields the same error on all four commands
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

    // Deleting a credential cascades to its attachments (the command layer only verifies the visible effect: the list is emptied)
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
