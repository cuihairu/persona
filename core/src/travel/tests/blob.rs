use super::*;

#[tokio::test]
async fn blob_files_round_trip_with_hash_check() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("attachments");
    std::fs::create_dir_all(&root).unwrap();
    let bytes = b"sealed attachment bytes \xf0\x9f\x94\x92".to_vec();
    let storage_path = format!("{}/att1/file.bin", uuid::Uuid::new_v4());
    let full = root.join(&storage_path);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(&full, &bytes).unwrap();

    // read -> pack -> write back into a new root, byte for byte identical
    let file = TravelBlobFile {
        storage_path: storage_path.clone(),
        sha256: sha256_hex(&bytes),
        data_b64: BASE64.encode(&bytes),
    };
    let new_root = dir.path().join("attachments2");
    std::fs::create_dir_all(&new_root).unwrap();
    write_blob_files(&new_root, &[file]).unwrap();
    assert_eq!(std::fs::read(new_root.join(&storage_path)).unwrap(), bytes);

    // Deletion (with NotFound tolerance) and escape defense
    assert!(delete_blob_files(
        &root,
        &[TravelBlobFile {
            storage_path: storage_path.clone(),
            sha256: String::new(),
            data_b64: String::new(),
        }]
    )
    .is_empty());
    assert!(!full.exists());
    assert!(
        delete_blob_files(
            &root,
            &[TravelBlobFile {
                storage_path: storage_path.clone(),
                sha256: String::new(),
                data_b64: String::new(),
            }]
        )
        .is_empty(),
        "already-deleted file is not a failure"
    );

    let escaped = TravelBlobFile {
        storage_path: "../escape.bin".to_string(),
        sha256: String::new(),
        data_b64: String::new(),
    };
    assert!(!delete_blob_files(&root, std::slice::from_ref(&escaped)).is_empty());
    let err = write_blob_files(&new_root, std::slice::from_ref(&escaped)).unwrap_err();
    assert!(err.to_string().contains("escapes storage root"), "{err}");

    // A hash mismatch refuses the write-back
    let tampered = TravelBlobFile {
        storage_path: "x/y.bin".to_string(),
        sha256: sha256_hex(b"different"),
        data_b64: BASE64.encode(&bytes),
    };
    let err = write_blob_files(&new_root, &[tampered]).unwrap_err();
    assert!(err.to_string().contains("integrity check failed"), "{err}");
}

/// The three IO failure arms of write_blob_file: path escape, parent
/// directory creation failure (the attachment root itself is a regular
/// file), and write failure (the target is already a directory).
#[test]
fn write_blob_file_failure_arms() {
    let dir = tempfile::tempdir().unwrap();
    let err = write_blob_file(dir.path(), "../escape.bin", b"x").unwrap_err();
    assert!(err.to_string().contains("escapes storage root"), "{err}");

    let as_file = dir.path().join("iam-a-file");
    std::fs::write(&as_file, b"f").unwrap();
    let err = write_blob_file(&as_file, "sub/file.bin", b"x").unwrap_err();
    assert!(
        err.to_string().contains("failed to create attachment dir"),
        "{err}"
    );

    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("occupied")).unwrap();
    let err = write_blob_file(&root, "occupied", b"x").unwrap_err();
    assert!(
        err.to_string().contains("failed to write attachment"),
        "{err}"
    );
}

/// Non-NotFound failures of delete_blob_files must be surfaced (exit
/// self-healing relies on the failures list being visible);
/// write_blob_files rejects bad base64 payloads.
#[test]
fn blob_file_delete_failure_and_bad_base64_are_surfaced() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("att");
    std::fs::create_dir_all(root.join("a-dir")).unwrap();
    let failures = delete_blob_files(
        &root,
        &[TravelBlobFile {
            storage_path: "a-dir".to_string(),
            sha256: String::new(),
            data_b64: String::new(),
        }],
    );
    assert_eq!(failures, vec!["a-dir".to_string()]);

    let err = write_blob_files(
        &root,
        &[TravelBlobFile {
            storage_path: "x.bin".to_string(),
            sha256: String::new(),
            data_b64: "!!not-base64!!".to_string(),
        }],
    )
    .unwrap_err();
    assert!(err.to_string().contains("bad base64"), "{err}");
}
