use super::*;
use crate::storage::AttachmentRepository;
use tempfile::tempdir;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn test_store_and_retrieve_small_file() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let test_file = temp_dir.path().join("test.txt");

    // Create test file
    let mut file = File::create(&test_file).await.unwrap();
    file.write_all(b"Hello, World!").await.unwrap();
    file.sync_all().await.unwrap();
    drop(file);

    // Create manager
    let db = create_test_db().await;
    let credential_id = seed_identity_and_credential(&db).await;
    let repo = AttachmentRepository::new(db);
    let blob_store = BlobStore::new(&storage_dir);
    let manager = AttachmentManager::new(repo, blob_store);
    manager.init().await.unwrap();

    // Store file
    let attachment_id = manager
        .store(&test_file, credential_id, false, None)
        .await
        .unwrap();

    // Retrieve file
    let content = manager.retrieve(&attachment_id, false, None).await.unwrap();

    assert_eq!(content, b"Hello, World!");
}

#[tokio::test]
async fn test_store_and_retrieve_with_encryption() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let test_file = temp_dir.path().join("secret.txt");

    // Create test file
    let mut file = File::create(&test_file).await.unwrap();
    file.write_all(b"Secret content").await.unwrap();
    file.sync_all().await.unwrap();
    drop(file);

    // Create manager
    let db = create_test_db().await;
    let credential_id = seed_identity_and_credential(&db).await;
    let repo = AttachmentRepository::new(db);
    let blob_store = BlobStore::new(&storage_dir);
    let manager = AttachmentManager::new(repo, blob_store);
    manager.init().await.unwrap();
    let encryption_key = b"0123456789abcdef0123456789abcdef"; // 32 bytes key

    // Store file with encryption
    let attachment_id = manager
        .store(&test_file, credential_id, true, Some(encryption_key))
        .await
        .unwrap();

    // Retrieve file with decryption
    let content = manager
        .retrieve(&attachment_id, true, Some(encryption_key))
        .await
        .unwrap();

    assert_eq!(content, b"Secret content");
}

#[tokio::test]
async fn test_delete_attachment() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let test_file = temp_dir.path().join("test.txt");

    // Create test file
    let mut file = File::create(&test_file).await.unwrap();
    file.write_all(b"Delete me").await.unwrap();
    file.sync_all().await.unwrap();
    drop(file);

    // Create manager
    let db = create_test_db().await;
    let credential_id = seed_identity_and_credential(&db).await;
    let repo = AttachmentRepository::new(db);
    let blob_store = BlobStore::new(&storage_dir);
    let manager = AttachmentManager::new(repo, blob_store);
    manager.init().await.unwrap();

    // Store file
    let attachment_id = manager
        .store(&test_file, credential_id, false, None)
        .await
        .unwrap();

    // Delete attachment
    manager.delete(&attachment_id).await.unwrap();

    // Try to retrieve (should fail)
    let result = manager.retrieve(&attachment_id, false, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_manager_chunked_round_trip_stats_and_list() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let contents = b"chunked-content-0123456789"; // 26 bytes
    let test_file = small_test_file(temp_dir.path(), "chunked.bin", contents);

    let db = create_test_db().await;
    let credential_id = seed_identity_and_credential(&db).await;
    let repo = AttachmentRepository::new(db);
    // Chunk threshold of 8 bytes forces chunking for a 26-byte file.
    let blob_store = BlobStore::with_test_limits(&storage_dir, 8, 8);
    let manager = AttachmentManager::new(repo, blob_store);
    manager.init().await.unwrap();

    let attachment_id = manager
        .store(&test_file, credential_id, false, None)
        .await
        .unwrap();

    // Chunked retrieval reconstructs the original bytes.
    let content = manager.retrieve(&attachment_id, false, None).await.unwrap();
    assert_eq!(content, contents);

    // Stats see one chunked attachment.
    let stats = manager.get_stats().await.unwrap();
    assert_eq!(stats.total_attachments, 1);
    assert_eq!(stats.chunked_count, 1);
    assert_eq!(stats.total_size, contents.len() as u64);

    // Listing by credential finds it.
    assert_eq!(
        manager
            .list_for_credential(&credential_id)
            .await
            .unwrap()
            .len(),
        1
    );

    // Deleting removes metadata and the on-disk chunks.
    manager.delete(&attachment_id).await.unwrap();
    assert!(manager
        .list_for_credential(&credential_id)
        .await
        .unwrap()
        .is_empty());
    assert!(manager.retrieve(&attachment_id, false, None).await.is_err());
}

#[tokio::test]
async fn test_manager_retrieve_and_delete_missing_attachment() {
    let temp_dir = tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");

    let db = create_test_db().await;
    let repo = AttachmentRepository::new(db);
    let blob_store = BlobStore::new(&storage_dir);
    let manager = AttachmentManager::new(repo, blob_store);
    manager.init().await.unwrap();

    let missing = Uuid::new_v4();
    let err = manager.retrieve(&missing, false, None).await.unwrap_err();
    assert!(err.to_string().contains("Attachment not found"));

    let err = manager.delete(&missing).await.unwrap_err();
    assert!(err.to_string().contains("Attachment not found"));
}
