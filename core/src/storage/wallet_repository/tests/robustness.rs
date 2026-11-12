//! 损坏 uuid 行与越界时间戳的错形透传测试（钱包/交易两侧都验）。

use super::*;

#[tokio::test]
async fn corrupt_uuid_rows_surface_invalid_input_errors() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db.clone()));
    let now = chrono::Utc::now().timestamp();

    // A wallet row whose `id` is not a UUID must fail row conversion with
    // an InvalidInput error instead of panicking.
    sqlx::query(
        r#"INSERT INTO crypto_wallets (id, identity_id, name, network, wallet_type,
               encrypted_private_key, watch_only, security_level, created_at, updated_at)
               VALUES ('not-a-uuid', ?, 'Bad Id', '"bitcoin"', '"single_address"',
                       x'00', 0, '"medium"', ?, ?)"#,
    )
    .bind(identity_id.to_string())
    .bind(now)
    .bind(now)
    .execute(db.pool())
    .await
    .unwrap();
    let err = repo.find_all().await.unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
    sqlx::query("DELETE FROM crypto_wallets WHERE id = 'not-a-uuid'")
        .execute(db.pool())
        .await
        .unwrap();

    // Same for a row whose `identity_id` cannot be parsed. The FK keeps
    // such a row out through normal writes, so temporarily disable FK
    // enforcement (pinned to the pool's single connection) to inject it.
    let good_id = Uuid::new_v4();
    {
        let mut conn = db.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO crypto_wallets (id, identity_id, name, network, wallet_type,
                   encrypted_private_key, watch_only, security_level, created_at, updated_at)
                   VALUES (?, 'not-a-uuid', 'Bad Identity', '"bitcoin"', '"single_address"',
                           x'00', 0, '"medium"', ?, ?)"#,
        )
        .bind(good_id.to_string())
        .bind(now)
        .bind(now)
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let err = repo.find_by_id(&good_id).await.unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
    sqlx::query("DELETE FROM crypto_wallets WHERE id = ?")
        .bind(good_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();

    // A transaction request row with an unparseable `id` fails conversion.
    let wallet = make_wallet(identity_id, "Tx Wallet");
    let created = repo.create(&wallet).await.unwrap();
    sqlx::query(
        r#"INSERT INTO transaction_requests (id, wallet_id, network, from_address,
               to_address, amount, fee, required_signatures, created_at)
               VALUES ('not-a-uuid', ?, 'net', 'from', 'to', '1', '0', 1, ?)"#,
    )
    .bind(created.id.to_string())
    .bind(now)
    .execute(db.pool())
    .await
    .unwrap();
    let err = repo.get_pending_requests(&created.id).await.unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));

    // The `wallet_id` column of a request row cannot be unparseable for
    // any query result (they all filter on it) and the FK normally keeps
    // such rows out entirely, so inject one with FK checks disabled and
    // exercise the converter branch through the private converter.
    {
        let mut conn = db.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO transaction_requests (id, wallet_id, network, from_address,
                   to_address, amount, fee, required_signatures, created_at)
                   VALUES (?, 'not-a-uuid', 'net', 'from', 'to', '1', '0', 1, ?)"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(now)
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let row = sqlx::query("SELECT * FROM transaction_requests WHERE wallet_id = 'not-a-uuid'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(matches!(
        repo.transaction_request_from_row(&row),
        Err(PersonaError::InvalidInput(_))
    ));

    // Same for a signed transaction row with an unparseable `id`, reached
    // through the private row converter.
    sqlx::query(
        r#"INSERT INTO signed_transactions (id, wallet_id, request, signatures,
               raw_signed_transaction, transaction_hash, signed_at, created_at)
               VALUES ('not-a-uuid', ?, '{}', '[]', x'00', 'tx-hash', ?, ?)"#,
    )
    .bind(created.id.to_string())
    .bind(now)
    .bind(now)
    .execute(db.pool())
    .await
    .unwrap();
    let row = sqlx::query("SELECT * FROM signed_transactions WHERE id = 'not-a-uuid'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(matches!(
        repo.signed_transaction_from_row(&row),
        Err(PersonaError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn out_of_range_timestamps_surface_database_errors() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db.clone()));
    let wallet = make_wallet(identity_id, "Corrupt Timestamps");
    let created = repo.create(&wallet).await.unwrap();

    // A wallet row whose `created_at` is outside chrono's representable
    // range must fail row conversion with a Database error instead of
    // panicking on the unwrap (DB corruption/manual edits must not
    // break the listing path).
    sqlx::query("UPDATE crypto_wallets SET created_at = ? WHERE id = ?")
        .bind(i64::MAX)
        .bind(created.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    assert!(matches!(
        repo.find_all().await,
        Err(PersonaError::Database(_))
    ));
    assert!(matches!(
        repo.find_by_id(&created.id).await,
        Err(PersonaError::Database(_))
    ));

    // Restoring a sane timestamp puts the row back in service.
    sqlx::query("UPDATE crypto_wallets SET created_at = ? WHERE id = ?")
        .bind(chrono::Utc::now().timestamp())
        .bind(created.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    assert!(repo.find_by_id(&created.id).await.unwrap().is_some());
}
