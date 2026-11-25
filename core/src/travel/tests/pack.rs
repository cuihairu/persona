use super::*;

#[test]
fn sidecar_path_sits_next_to_db() {
    assert_eq!(
        sidecar_path(Path::new("/data/persona/identities.db")),
        PathBuf::from("/data/persona/travel.persenc")
    );
    assert_eq!(
        sidecar_path(Path::new("identities.db")),
        PathBuf::from("travel.persenc")
    );
}

/// The "decryptable but content broken" sidecar error branches: a corrupted
/// gzip stream reports decompression failed, and gzipped data that is not
/// TravelPack JSON reports not a valid pack -- neither is confused with a
/// passphrase error.
#[test]
fn open_pack_distinguishes_decompression_from_deserialization_failures() {
    let pw = "travel-pw";

    // gzip magic at the start but corrupted content (CRC/deflate layer failure)
    let mut corrupt = gzip_bytes(b"legit pack bytes".to_vec());
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    let sealed = encrypt_bytes(&corrupt, pw, Some(fast_kdf())).unwrap();
    let err = open_pack(&sealed, pw).unwrap_err();
    assert!(err.to_string().contains("decompression failed"), "{err}");

    let sealed =
        encrypt_bytes(&gzip_bytes(b"{ not a pack".to_vec()), pw, Some(fast_kdf())).unwrap();
    let err = open_pack(&sealed, pw).unwrap_err();
    assert!(err.to_string().contains("not a valid pack"), "{err}");
}

#[tokio::test]
async fn pack_rows_and_round_trips_through_seal_open() {
    let (_dir, db) = seeded_db().await;
    let marked: Vec<String> = IdentityRepository::new(db.clone())
        .find_all()
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.id.to_string())
        .collect();
    let pack = build_pack(db.pool(), None, &marked).await.unwrap();
    assert_eq!(pack.tables.get("identities").unwrap().len(), 2);
    assert_eq!(pack.format_name, FORMAT_NAME);
    assert!(pack.attachment_files.is_empty());

    let sealed = seal_pack(&pack, "travel-pw", Some(fast_kdf())).unwrap();
    assert!(is_persona_encrypted(&sealed));
    let opened = open_pack(&sealed, "travel-pw").unwrap();
    assert_eq!(opened.tables.len(), pack.tables.len());
    assert_eq!(opened.identity_ids, pack.identity_ids);

    let err = open_pack(&sealed, "wrong").unwrap_err();
    assert!(err.to_string().contains("passphrase is wrong"), "{err}");

    // Bad magic: non-PERSENC1 bytes are rejected outright
    let err = open_pack(b"not encrypted at all", "travel-pw").unwrap_err();
    assert!(
        err.to_string().contains("not a Persona encrypted file"),
        "{err}"
    );

    // Format validation (TravelPack fields are all pub, so build a bad
    // format directly)
    let mut bad = build_pack(db.pool(), None, &marked).await.unwrap();
    bad.format_name = "other".into();
    let sealed_bad = seal_pack(&bad, "travel-pw", Some(fast_kdf())).unwrap();
    let err = open_pack(&sealed_bad, "travel-pw").unwrap_err();
    assert!(
        err.to_string()
            .contains("unsupported travel sidecar format"),
        "{err}"
    );
}

#[tokio::test]
async fn write_sidecar_atomic_places_file_with_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("travel.persenc");
    write_sidecar_atomic(&path, b"sealed").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"sealed");

    // Overwrites also go through tmp+rename (no .tmp leftovers)
    write_sidecar_atomic(&path, b"sealed2").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"sealed2");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "tmp files must be renamed away");
}

/// The attachment-collection defense arms of build_pack: empty marked is
/// rejected; storage_path rows with a dirty BLOB type are silently skipped
/// (NOT NULL does not stop BLOBs -- TEXT affinity does not convert BLOBs);
/// a valid row plus its chunk row land in attachment_files as a pair; a
/// missing attachments_root, an on-disk hash mismatch, and a path escape
/// each hit their own error branch.
#[tokio::test]
async fn build_pack_attachment_edges_and_guards() {
    let (dir, db) = seeded_db().await;
    let pool = db.pool();

    let err = build_pack(pool, None, &[]).await.unwrap_err();
    assert!(err.to_string().contains("no marked identities"), "{err}");

    let ident = identity_id_by_name(pool, "A").await;
    let cred = insert_credential(pool, &ident, None).await;

    let root = dir.path().join("attachments");
    let put = |rel: &str, bytes: &[u8]| {
        let full = root.join(rel);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, bytes).unwrap();
    };
    let file_bytes = b"sealed-bytes";
    put("dir/plain.bin", file_bytes);
    put("dir/chunk-0.bin", file_bytes);

    // Dirty row: storage_path stored as BLOB (wrong type); valid row + chunk row
    sqlx::query(
            "INSERT INTO attachments (id, credential_id, filename, mime_type, size, storage_path, content_hash, created_at, updated_at)
             VALUES (?, ?, 'dirty', 'application/octet-stream', 1, X'2F2F', 'whatever', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&cred)
        .execute(pool)
        .await
        .unwrap();
    let plain_hash = sha256_hex(file_bytes);
    let att = uuid::Uuid::new_v4().to_string();
    sqlx::query(
            "INSERT INTO attachments (id, credential_id, filename, mime_type, size, storage_path, content_hash, created_at, updated_at)
             VALUES (?, ?, 'plain', 'application/octet-stream', ?, 'dir/plain.bin', ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(&att)
        .bind(&cred)
        .bind(file_bytes.len() as i64)
        .bind(&plain_hash)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
            "INSERT INTO attachment_chunks (id, attachment_id, chunk_index, size, content_hash, storage_path, created_at)
             VALUES (?, ?, 0, ?, ?, 'dir/chunk-0.bin', '2026-01-01T00:00:00Z')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&att)
        .bind(file_bytes.len() as i64)
        .bind(&plain_hash)
        .execute(pool)
        .await
        .unwrap();

    // Valid row + chunk row make it into the pack; the BLOB dirty row is
    // skipped by filter_map
    let pack = build_pack(pool, Some(&root), std::slice::from_ref(&ident))
        .await
        .unwrap();
    let mut packed_paths: Vec<&str> = pack
        .attachment_files
        .iter()
        .map(|f| f.storage_path.as_str())
        .collect();
    packed_paths.sort_unstable();
    assert_eq!(packed_paths, vec!["dir/chunk-0.bin", "dir/plain.bin"]);

    // Attachment rows but no attachment root from the caller -> configuration
    // error (fail-closed, never silently drop files)
    let err = build_pack(pool, None, std::slice::from_ref(&ident))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("attachment storage is not initialized"),
        "{err}"
    );

    // On-disk bytes do not match the row hash -> refuse to pack (the enter
    // side of relay fidelity)
    sqlx::query("UPDATE attachments SET content_hash = 'deadbeef' WHERE id = ?")
        .bind(&att)
        .execute(pool)
        .await
        .unwrap();
    let err = build_pack(pool, Some(&root), std::slice::from_ref(&ident))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("content hash mismatch"), "{err}");

    // storage_path escapes the attachment root -> refuse (defense against
    // historical dirty data)
    sqlx::query(
        "UPDATE attachments SET storage_path = '../escape.bin', content_hash = ? WHERE id = ?",
    )
    .bind(&plain_hash)
    .bind(&att)
    .execute(pool)
    .await
    .unwrap();
    let err = build_pack(pool, Some(&root), &[ident]).await.unwrap_err();
    assert!(err.to_string().contains("escapes storage root"), "{err}");
}
