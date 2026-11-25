use super::*;

/// The defense surface of the row-restore entry point: bad base64, objects
/// without a b64 key, unsupported JSON types, illegal column names, and
/// empty rows are each rejected; Bool lands in the table as INTEGER 1/0.
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

    // Marked object but illegal base64
    let err = insert_rows(&mut conn, "probe", &row_with("blob", json!({"b64": "!!"})))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("bad base64"), "{err}");

    // Object missing the b64 key
    let err = insert_rows(&mut conn, "probe", &row_with("blob", json!({"other": 1})))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unexpected object cell"), "{err}");

    // Unsupported JSON value (array)
    let err = insert_rows(&mut conn, "probe", &row_with("blob", json!([1, 2])))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unsupported JSON value"), "{err}");

    // Illegal column name (hyphen is not in the whitelist)
    let err = insert_rows(&mut conn, "probe", &row_with("bad-name", json!(1)))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("illegal column name"), "{err}");

    // Empty row
    let err = insert_rows(&mut conn, "probe", &[Map::new()])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("empty row"), "{err}");

    // Bool goes through the Int channel into the table; non-integer floats
    // keep fidelity via the Real channel
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

/// SQLite REAL can store Inf (the `9e999` literal overflows); JSON cannot
/// represent non-finite numbers, so row_to_json fails closed on them instead
/// of silently dropping the column or writing null.
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

/// Table-name whitelist rejection arm: the restore surface only accepts the
/// 12 packed tables (table names come from the constant list; this arm
/// blocks hand-edited packs from injecting arbitrary table names).
#[test]
fn table_name_whitelist_rejects_unknown_table() {
    let err = check_table_name("audit_logs").unwrap_err();
    assert!(err.to_string().contains("illegal table name"), "{err}");
    assert!(check_table_name("identities").is_ok());
}
