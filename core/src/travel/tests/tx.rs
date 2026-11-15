use super::*;

#[tokio::test]
async fn enter_exit_round_trip_preserves_rows() {
    let (_dir, db) = seeded_db().await;
    let repo = IdentityRepository::new(db.clone());
    let all = repo.find_all().await.unwrap();
    let marked: Vec<String> = all.iter().map(|i| i.id.to_string()).collect();

    let pack = build_pack(db.pool(), None, &marked).await.unwrap();
    apply_enter_tx(db.pool(), &pack).await.unwrap();
    assert!(
        repo.find_all().await.unwrap().is_empty(),
        "marked identities must be gone after enter"
    );

    apply_exit_tx(db.pool(), &pack).await.unwrap();
    let restored = repo.find_all().await.unwrap();
    assert_eq!(restored.len(), 2);
    let mut restored_ids: Vec<String> = restored.iter().map(|i| i.id.to_string()).collect();
    let mut expected_ids = marked.clone();
    restored_ids.sort();
    expected_ids.sort();
    assert_eq!(restored_ids, expected_ids);
}

#[tokio::test]
async fn enter_exit_clears_and_restores_travel_mode_settings() {
    let (_dir, db) = seeded_db().await;
    let marked: Vec<String> = IdentityRepository::new(db.clone())
        .find_all()
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.id.to_string())
        .collect();
    let pack = build_pack(db.pool(), None, &marked).await.unwrap();

    apply_enter_tx(db.pool(), &pack).await.unwrap();
    let (mode, entered_at): (i64, Option<String>) = sqlx::query_as(
            "SELECT json_extract(settings, '$.travel_mode'), json_extract(settings, '$.travel_entered_at') FROM workspaces LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(mode, 1);
    assert!(entered_at.is_some());

    apply_exit_tx(db.pool(), &pack).await.unwrap();
    let (mode, entered_at): (i64, Option<String>) = sqlx::query_as(
            "SELECT json_extract(settings, '$.travel_mode'), json_extract(settings, '$.travel_entered_at') FROM workspaces LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(mode, 0);
    assert!(entered_at.is_none());
}

/// enter 事务写 settings 前的库内防御：settings 是合法 JSON 但非
/// 对象 → Database；workspace 行缺失 → NotFound（提示 migrate）。
/// 事务中途报错即回滚（identities 未被删）。
#[tokio::test]
async fn enter_tx_rejects_missing_workspace_and_non_object_settings() {
    let (_dir, db) = seeded_db().await;
    let pool = db.pool();
    let pack = minimal_pack(vec![identity_id_by_name(pool, "A").await]);

    sqlx::query("UPDATE workspaces SET settings = '\"junk-string\"'")
        .execute(pool)
        .await
        .unwrap();
    let err = apply_enter_tx(pool, &pack).await.unwrap_err();
    assert!(err.to_string().contains("not an object"), "{err}");

    sqlx::query("DELETE FROM workspaces")
        .execute(pool)
        .await
        .unwrap();
    let err = apply_enter_tx(pool, &pack).await.unwrap_err();
    assert!(err.to_string().contains("persona migrate"), "{err}");

    // 两次失败都回滚：身份行仍在
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identities")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

/// exit 恢复对 pack 缺表宽容：build_pack 恒写满 12 张表，但手改或
/// 旧版 pack 缺键时跳过该表继续恢复其余表（if-let None 臂）。
#[tokio::test]
async fn exit_tx_skips_tables_absent_from_pack() {
    let (_dir, db) = seeded_db().await;
    let repo = IdentityRepository::new(db.clone());
    let marked: Vec<String> = repo
        .find_all()
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.id.to_string())
        .collect();

    let mut pack = build_pack(db.pool(), None, &marked).await.unwrap();
    assert!(pack.tables.remove("passkeys").is_some());
    assert!(pack.tables.remove("change_history").is_some());
    apply_enter_tx(db.pool(), &pack).await.unwrap();
    apply_exit_tx(db.pool(), &pack).await.unwrap();
    assert_eq!(repo.find_all().await.unwrap().len(), 2);
}

/// favicon 清理的 host 集合分支：重复 host 去重（contains 命中不
/// 重推）、不可抓取 URL（非 https）与 NULL url 跳过提取、仅被移除
/// 凭据引用的 host 才删——仍被保留凭据引用的 host 留下。
#[cfg(feature = "favicon")]
#[tokio::test]
async fn favicon_prune_dedups_hosts_and_skips_unfetchable_urls() {
    let (_dir, db) = seeded_db().await;
    let pool = db.pool();
    let id_a = identity_id_by_name(pool, "A").await;
    let id_b = identity_id_by_name(pool, "B").await;

    // 被移除身份：dup.com 两条（去重臂）+ 非 https 一条（提取失败臂）
    // + NULL url 一条（flatten 跳过臂）+ 仅本身份引用的 only-a.com
    insert_credential(pool, &id_a, Some("https://dup.com/one")).await;
    insert_credential(pool, &id_a, Some("https://dup.com/two")).await;
    insert_credential(pool, &id_a, Some("http://plain.invalid/x")).await;
    insert_credential(pool, &id_a, None).await;
    insert_credential(pool, &id_a, Some("https://only-a.com/item")).await;
    // 保留身份：dup.com 仍被引用 → 缓存行必须留下
    insert_credential(pool, &id_b, Some("https://dup.com/kept")).await;

    for host in ["dup.com", "only-a.com"] {
        sqlx::query(
            "INSERT INTO favicon_cache (host, mime_type, data, created_at, updated_at)
                 VALUES (?, 'image/png', X'01', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(host)
        .execute(pool)
        .await
        .unwrap();
    }

    apply_enter_tx(pool, &minimal_pack(vec![id_a]))
        .await
        .unwrap();

    let hosts: Vec<String> = sqlx::query_scalar("SELECT host FROM favicon_cache ORDER BY host")
        .fetch_all(pool)
        .await
        .unwrap();
    assert_eq!(hosts, vec!["dup.com".to_string()]);
}
