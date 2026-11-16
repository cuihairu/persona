use super::*;
use crate::models::{Attachment, AttachmentChunk};
use crate::storage::FileSystem;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_detect_mime_type_covers_known_extensions() {
    let store = BlobStore::new("/tmp/unused");
    let cases = [
        ("a.pdf", "application/pdf"),
        ("a.doc", "application/msword"),
        (
            "a.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        ("a.xls", "application/vnd.ms-excel"),
        (
            "a.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        ("a.txt", "text/plain"),
        ("a.jpg", "image/jpeg"),
        ("a.jpeg", "image/jpeg"),
        ("a.png", "image/png"),
        ("a.gif", "image/gif"),
        ("a.zip", "application/zip"),
        ("a.json", "application/json"),
        ("a.xml", "application/xml"),
        ("a.unknownext", "application/octet-stream"),
        ("noextension", "application/octet-stream"),
        ("UPPER.PNG", "image/png"),
    ];
    for (filename, expected) in cases {
        assert_eq!(store.detect_mime_type(filename), expected, "for {filename}");
    }
}

#[test]
fn test_chunk_and_path_helpers() {
    let root = Path::new("/tmp/blob-root");
    let store = BlobStore::with_chunk_size(root, 4);
    let credential_id = Uuid::new_v4();
    let attachment_id = Uuid::new_v4();

    // Chunking splits on the configured chunk size, last chunk keeps the rest.
    assert_eq!(
        store.chunk_data(&[1, 2, 3, 4, 5, 6]),
        vec![vec![1, 2, 3, 4], vec![5, 6]]
    );
    assert!(store.chunk_data(&[]).is_empty());

    let file_path = store.get_file_path(&credential_id, &attachment_id, "f.txt");
    assert_eq!(
        file_path,
        root.join(credential_id.to_string())
            .join(attachment_id.to_string())
            .join("f.txt")
    );

    let chunk_dir = store.get_chunk_dir(&credential_id, &attachment_id);
    assert_eq!(
        chunk_dir,
        root.join(credential_id.to_string())
            .join(attachment_id.to_string())
            .join("chunks")
    );

    let chunk_path = store.get_chunk_path(&credential_id, &attachment_id, 3);
    assert_eq!(chunk_path, chunk_dir.join("chunk_0003"));

    // Known SHA-256 vector.
    assert_eq!(
        store.calculate_hash(b"hello"),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[tokio::test]
async fn test_store_file_missing_errors() {
    let temp_dir = tempdir().unwrap();
    let store = BlobStore::new(temp_dir.path().join("storage"));

    let err = store
        .store_file(
            temp_dir.path().join("nope.txt"),
            Uuid::new_v4(),
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("File does not exist"));
}

#[tokio::test]
async fn test_store_file_rejects_unnameable_path() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let store = BlobStore::new(&storage_dir);
    store.init().await.unwrap();

    // `storage/..` resolves to an existing directory but has no file name.
    let weird = storage_dir.join("..");
    let err = store
        .store_file(&weird, Uuid::new_v4(), false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Invalid filename"));
}

#[tokio::test]
async fn test_store_file_encryption_requires_key_and_valid_length() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let store = BlobStore::new(&storage_dir);
    store.init().await.unwrap();
    let file = small_test_file(temp_dir.path(), "secret.txt", b"payload");

    // encrypt=true but no key.
    let err = store
        .store_file(&file, Uuid::new_v4(), true, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Encryption key required"));

    // Key that is not 32 bytes.
    let err = store
        .store_file(&file, Uuid::new_v4(), true, Some(&b"short"[..]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Invalid encryption key length"));
}

#[tokio::test]
async fn test_chunked_store_retrieve_and_hash_mismatch() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    // Chunk threshold of 8 bytes forces chunking for a 16-byte file.
    let store = BlobStore::with_test_limits(&storage_dir, 8, 8);
    store.init().await.unwrap();
    let credential_id = Uuid::new_v4();

    let contents = b"0123456789abcdef"; // 16 bytes → 2 chunks of 8
    let file = small_test_file(temp_dir.path(), "big.bin", contents);

    let mut attachment = store
        .store_file(&file, credential_id, false, None)
        .await
        .unwrap();
    assert!(attachment.chunk_count > 1);
    assert_eq!(attachment.size as usize, contents.len());

    // Collect the chunk metadata the store just wrote.
    let chunk_dir = store.get_chunk_dir(&credential_id, &attachment.id);
    let mut paths = FileSystem::read_dir(&chunk_dir).await.unwrap();
    paths.sort();
    let mut chunks = Vec::new();
    for (i, p) in paths.iter().enumerate() {
        let data = FileSystem::read(p).await.unwrap();
        let relative = p
            .strip_prefix(&storage_dir)
            .unwrap()
            .to_string_lossy()
            .to_string();
        chunks.push(AttachmentChunk::new(
            attachment.id,
            i as u32,
            data.len() as u32,
            store.calculate_hash(&data),
            relative,
        ));
    }

    // Clean reconstruction works.
    let rebuilt = store
        .retrieve_file(&attachment, &chunks, false, None)
        .await
        .unwrap();
    assert_eq!(rebuilt, contents);

    // Corrupting one chunk hash must abort reconstruction.
    let mut tampered = chunks.clone();
    tampered[1].content_hash = "0".repeat(64);
    let err = store
        .retrieve_file(&attachment, &tampered, false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("hash mismatch"));

    // Tampering with the whole-content hash must also fail.
    attachment.content_hash = "f".repeat(64);
    let err = store
        .retrieve_file(&attachment, &chunks, false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Content hash mismatch"));

    // Deleting the chunked attachment removes every chunk and the directory.
    store.delete_file(&attachment, &chunks).await.unwrap();
    assert!(!FileSystem::exists(&chunk_dir).await);
    // Deleting again is a no-op (paths already gone).
    store.delete_file(&attachment, &chunks).await.unwrap();
}

#[tokio::test]
async fn test_retrieve_single_file_content_hash_mismatch_and_missing() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let store = BlobStore::new(&storage_dir);
    store.init().await.unwrap();
    let credential_id = Uuid::new_v4();

    let mut attachment = Attachment::new(
        credential_id,
        "f.txt".to_string(),
        "text/plain".to_string(),
        5,
        "f.txt".to_string(),
        store.calculate_hash(b"hello"),
    );
    FileSystem::write(&storage_dir.join("f.txt"), b"hello")
        .await
        .unwrap();

    // Corrupt the recorded hash.
    attachment.content_hash = "0".repeat(64);
    let err = store
        .retrieve_file(&attachment, &[], false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Content hash mismatch"));

    // Missing file surfaces an IO error.
    attachment.content_hash = store.calculate_hash(b"hello");
    attachment.storage_path = "gone.txt".to_string();
    assert!(store
        .retrieve_file(&attachment, &[], false, None)
        .await
        .is_err());
}

#[tokio::test]
async fn test_retrieve_encrypted_requires_key_and_valid_length() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let store = BlobStore::new(&storage_dir);
    store.init().await.unwrap();

    let file = small_test_file(temp_dir.path(), "enc.txt", b"top secret");
    let key = [7u8; 32];
    let attachment = store
        .store_file(&file, Uuid::new_v4(), true, Some(&key))
        .await
        .unwrap();
    assert!(attachment.is_encrypted);
    assert!(attachment.encryption_key_id.is_some());

    // Encrypted content cannot be decrypted without a key.
    let err = store
        .retrieve_file(&attachment, &[], true, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Decryption key required"));

    // A wrongly-sized key is rejected before decryption.
    let err = store
        .retrieve_file(&attachment, &[], true, Some(&[1u8; 16]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Invalid decryption key length"));

    // Correct key restores the plaintext.
    let plaintext = store
        .retrieve_file(&attachment, &[], true, Some(&key))
        .await
        .unwrap();
    assert_eq!(plaintext, b"top secret");
}

#[tokio::test]
async fn test_delete_single_file_and_missing_file_noop() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let store = BlobStore::new(&storage_dir);
    store.init().await.unwrap();
    let credential_id = Uuid::new_v4();

    let attachment = Attachment::new(
        credential_id,
        "doomed.txt".to_string(),
        "text/plain".to_string(),
        4,
        "doomed.txt".to_string(),
        store.calculate_hash(b"bye!"),
    );
    FileSystem::write(&storage_dir.join("doomed.txt"), b"bye!")
        .await
        .unwrap();

    store.delete_file(&attachment, &[]).await.unwrap();
    assert!(!FileSystem::exists(&storage_dir.join("doomed.txt")).await);

    // Deleting an already-missing single file is fine.
    store.delete_file(&attachment, &[]).await.unwrap();
}

#[tokio::test]
async fn test_storage_path_traversal_rejected() {
    let temp_dir = tempdir().unwrap();
    let store = BlobStore::new(temp_dir.path().join("storage"));
    store.init().await.unwrap();
    let credential_id = Uuid::new_v4();

    // 根外放一个"诱饵"文件：若逃逸检查失效，retrieve/delete 会摸到它。
    let outside = temp_dir.path().join("outside-secret.txt");
    FileSystem::write(&outside, b"outside").await.unwrap();

    let mut attachment = Attachment::new(
        credential_id,
        "evil.txt".to_string(),
        "text/plain".to_string(),
        7,
        "../outside-secret.txt".to_string(),
        store.calculate_hash(b"outside"),
    );

    // 单文件 retrieve：逃逸路径直接拒绝，不读根外文件。
    let err = store
        .retrieve_file(&attachment, &[], false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("escapes storage root"), "{err}");

    // 单文件 delete：同样拒绝，不删根外文件。
    let err = store.delete_file(&attachment, &[]).await.unwrap_err();
    assert!(err.to_string().contains("escapes storage root"), "{err}");
    assert!(FileSystem::exists(&outside).await);

    // 分块路径同样受检（chunk.storage_path 与 attachment.storage_path 各查各的）。
    let chunk = AttachmentChunk::new(
        attachment.id,
        0,
        7,
        store.calculate_hash(b"outside"),
        "../../outside-secret.txt".to_string(),
    );
    attachment.chunk_count = 2;
    let err = store
        .retrieve_file(&attachment, std::slice::from_ref(&chunk), false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("escapes storage root"), "{err}");
    let err = store
        .delete_file(&attachment, std::slice::from_ref(&chunk))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("escapes storage root"), "{err}");
    assert!(FileSystem::exists(&outside).await);

    // 绝对路径与深层嵌套 `..` 同样拒绝。
    attachment.chunk_count = 1;
    for evil in ["/etc/passwd", "a/../../b.txt", "./here.txt"] {
        attachment.storage_path = evil.to_string();
        assert!(
            store
                .retrieve_file(&attachment, &[], false, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("escapes storage root"),
            "evil={evil}"
        );
    }

    // 合法的嵌套相对路径（uuid/uuid/filename 形态）不受影响。
    let good = temp_dir.path().join("storage");
    let nested = good
        .join(credential_id.to_string())
        .join("att")
        .join("nested.txt");
    FileSystem::create_dir_all(nested.parent().unwrap())
        .await
        .unwrap();
    FileSystem::write(&nested, b"nested ok").await.unwrap();
    attachment.chunk_count = 1;
    attachment.storage_path = format!("{}/att/nested.txt", credential_id);
    attachment.content_hash = store.calculate_hash(b"nested ok");
    let content = store
        .retrieve_file(&attachment, &[], false, None)
        .await
        .unwrap();
    assert_eq!(content, b"nested ok");
}
