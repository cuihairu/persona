use super::*;

/// 行恢复入口的防御面：坏 base64、无 b64 键的对象、不支持的 JSON
/// 类型、非法列名、空行逐类拒绝；Bool 落表为 INTEGER 1/0。
#[tokio::test]
async fn insert_rows_rejects_malformed_cells_and_column_names() {
    let (_dir, db) = seeded_db().await;
    let mut conn = db.pool().acquire().await.unwrap();
    sqlx::query("CREATE TABLE probe (flag INTEGER, blob BLOB, num REAL)")
        .execute(&mut *conn)
        .await
        .unwrap();

    let row_with = |key: &str, value: Value| {
        let mut row = Map::new();
        row.insert(key.to_string(), value);
        vec![row]
    };

    // 标记对象但 base64 非法
    let err = insert_rows(&mut conn, "probe", &row_with("blob", json!({"b64": "!!"})))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("bad base64"), "{err}");

    // 对象缺 b64 键
    let err = insert_rows(&mut conn, "probe", &row_with("blob", json!({"other": 1})))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unexpected object cell"), "{err}");

    // 不支持的 JSON 值（数组）
    let err = insert_rows(&mut conn, "probe", &row_with("blob", json!([1, 2])))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unsupported JSON value"), "{err}");

    // 非法列名（连字符不在白名单）
    let err = insert_rows(&mut conn, "probe", &row_with("bad-name", json!(1)))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("illegal column name"), "{err}");

    // 空行
    let err = insert_rows(&mut conn, "probe", &[Map::new()])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("empty row"), "{err}");

    // Bool 走 Int 通道落表；非整数 float 走 Real 通道保真
    insert_rows(&mut conn, "probe", &row_with("flag", Value::Bool(true)))
        .await
        .unwrap();
    let flag: i64 = sqlx::query_scalar("SELECT flag FROM probe")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(flag, 1);
    insert_rows(&mut conn, "probe", &row_with("num", json!(24.805)))
        .await
        .unwrap();
    let num: f64 = sqlx::query_scalar("SELECT num FROM probe WHERE num IS NOT NULL")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert!((num - 24.805).abs() < 1e-9, "{num}");
}

/// SQLite REAL 可存 Inf（`9e999` 字面量溢出）；JSON 表示不了非有限数，
/// row_to_json 对此 fail-closed 而不是静默丢列或写 null。
#[tokio::test]
async fn row_to_json_rejects_non_finite_float() {
    let (_dir, db) = seeded_db().await;
    sqlx::query("CREATE TABLE probe (v REAL)")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO probe VALUES (9e999)")
        .execute(db.pool())
        .await
        .unwrap();
    let row = sqlx::query("SELECT v FROM probe")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let err = row_to_json(&row).unwrap_err();
    assert!(err.to_string().contains("non-finite float"), "{err}");
}

/// 表名白名单拒绝臂：恢复面只认 12 张打包表（表名来自常量表，此臂
/// 防手改 pack 注入任意表名）。
#[test]
fn table_name_whitelist_rejects_unknown_table() {
    let err = check_table_name("audit_logs").unwrap_err();
    assert!(err.to_string().contains("illegal table name"), "{err}");
    assert!(check_table_name("identities").is_ok());
}
