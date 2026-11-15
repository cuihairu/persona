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

/// 「能解密但内容坏」的 sidecar 分路报错：gzip 流损坏报
/// decompression failed，gzip 但非 TravelPack JSON 报 not a valid
/// pack——都不与口令错误混淆。
#[test]
fn open_pack_distinguishes_decompression_from_deserialization_failures() {
    let pw = "travel-pw";

    // gzip magic 开头但内容损坏（CRC/deflate 层失败）
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

    // 坏 magic：非 PERSENC1 字节直接拒绝
    let err = open_pack(b"not encrypted at all", "travel-pw").unwrap_err();
    assert!(
        err.to_string().contains("not a Persona encrypted file"),
        "{err}"
    );

    // format 校验（TravelPack 字段全 pub，直接构造坏格式）
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

    // 覆盖写也走 tmp+rename（无 .tmp 残留）
    write_sidecar_atomic(&path, b"sealed2").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"sealed2");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "tmp files must be renamed away");
}

/// build_pack 的附件收集防御臂：空 marked 拒绝；BLOB 脏类型的
/// storage_path 行被静默跳过（NOT NULL 挡不住 BLOB——TEXT 亲和性
/// 不转换 BLOB）；合法行 + chunk 行成对进 attachment_files；缺
/// attachments_root、盘上 hash 不符、路径逃逸分路报错。
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

    // 脏行：storage_path 存 BLOB（类型错）；合法行 + chunk 行
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

    // 合法行 + chunk 行入 pack；BLOB 脏行被 filter_map 跳过
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

    // 有附件行但调用方没传附件根 → 配置错（fail-closed，不静默丢文件）
    let err = build_pack(pool, None, std::slice::from_ref(&ident))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("attachment storage is not initialized"),
        "{err}"
    );

    // 盘上字节与行内 hash 不符 → 拒绝打包（中继保真的 enter 侧一半）
    sqlx::query("UPDATE attachments SET content_hash = 'deadbeef' WHERE id = ?")
        .bind(&att)
        .execute(pool)
        .await
        .unwrap();
    let err = build_pack(pool, Some(&root), std::slice::from_ref(&ident))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("content hash mismatch"), "{err}");

    // storage_path 逃逸出附件根 → 拒绝（历史脏数据防御）
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
