//! Generic row codec: SQLite row <-> JSON (value-level probing with
//! SQLite dynamic-type fidelity), plus table/column whitelists and the
//! restore write path.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{json, Map, Value};
use sqlx::{AssertSqlSafe, Column, Row};

use super::PACKED_TABLES_IN_INSERT_ORDER;
use crate::{PersonaError, PersonaResult};

/// Row -> JSON map. Probe the actual stored type **value by value** (one
/// SQLite column can hold different kinds of values, so the declared column
/// type is untrustworthy): NULL/TEXT -> i64 -> f64 -> BLOB. Values from
/// INTEGER- and BOOLEAN-declared columns both land in i64 (storage-equivalent,
/// bound back as int).
pub(super) fn row_to_json(row: &sqlx::sqlite::SqliteRow) -> PersonaResult<Map<String, Value>> {
    let mut map = Map::new();
    for col in row.columns() {
        let name = col.name();
        let value = if let Ok(v) = row.try_get::<Option<String>, _>(name) {
            match v {
                Some(s) => Value::String(s),
                None => Value::Null,
            }
        } else if let Ok(v) = row.try_get::<i64, _>(name) {
            Value::Number(v.into())
        } else if let Ok(v) = row.try_get::<f64, _>(name) {
            Value::Number(
                serde_json::Number::from_f64(v)
                    .ok_or_else(|| PersonaError::Database(format!("non-finite float in {name}")))?,
            )
        } else if let Ok(v) = row.try_get::<Vec<u8>, _>(name) {
            json!({ "b64": BASE64.encode(v) })
        } else {
            return Err(PersonaError::Database(format!(
                "column {name}: unsupported value type"
            )));
        };
        map.insert(name.to_string(), value);
    }
    Ok(map)
}

/// JSON value -> bindable cell.
enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

fn value_to_cell(key: &str, value: &Value) -> PersonaResult<Cell> {
    Ok(match value {
        Value::Null => Cell::Null,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Cell::Int(i)
            } else if let Some(f) = n.as_f64() {
                Cell::Real(f)
            } else {
                return Err(PersonaError::Validation(format!(
                    "column {key}: number out of range"
                )));
            }
        }
        Value::String(s) => Cell::Text(s.clone()),
        Value::Object(o) => {
            let Some(b64) = o.get("b64").and_then(Value::as_str) else {
                return Err(PersonaError::Validation(format!(
                    "column {key}: unexpected object cell"
                )));
            };
            Cell::Blob(
                BASE64.decode(b64).map_err(|e| {
                    PersonaError::Validation(format!("column {key}: bad base64: {e}"))
                })?,
            )
        }
        Value::Bool(b) => Cell::Int(*b as i64),
        other => {
            return Err(PersonaError::Validation(format!(
                "column {key}: unsupported JSON value {other}"
            )))
        }
    })
}

/// Column-name whitelist validation (column names come from our own SELECT
/// *; this guards against a dirty pack).
fn check_column_name(key: &str) -> PersonaResult<()> {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(PersonaError::Validation(format!(
            "illegal column name in pack: {key}"
        )));
    }
    Ok(())
}

/// Table-name whitelist validation.
pub(super) fn check_table_name(name: &str) -> PersonaResult<()> {
    if PACKED_TABLES_IN_INSERT_ORDER.contains(&name) {
        Ok(())
    } else {
        Err(PersonaError::Validation(format!(
            "illegal table name in pack: {name}"
        )))
    }
}

pub(super) async fn insert_rows(
    executor: &mut sqlx::SqliteConnection,
    table: &str,
    rows: &[Map<String, Value>],
) -> PersonaResult<()> {
    for row in rows {
        if row.is_empty() {
            return Err(PersonaError::Validation(format!(
                "table {table}: empty row"
            )));
        }
        let mut columns = String::new();
        let mut placeholders = String::new();
        for key in row.keys() {
            check_column_name(key)?;
            if !columns.is_empty() {
                columns.push_str(", ");
                placeholders.push_str(", ");
            }
            // The whitelist limits names to [A-Za-z0-9_]; double quotes only
            // escape SQL keywords (e.g. the "index" column of
            // wallet_addresses).
            columns.push('"');
            columns.push_str(key);
            columns.push('"');
            placeholders.push('?');
        }
        let sql = format!("INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})");
        let mut query = sqlx::query(AssertSqlSafe(sql.as_str()));
        for (key, value) in row {
            query = match value_to_cell(key, value)? {
                Cell::Null => query.bind(None::<String>),
                Cell::Int(i) => query.bind(i),
                Cell::Real(f) => query.bind(f),
                Cell::Text(s) => query.bind(s),
                Cell::Blob(b) => query.bind(b),
            };
        }
        query
            .execute(&mut *executor)
            .await
            .map_err(|e| PersonaError::Database(format!("restoring {table}: {e}")))?;
    }
    Ok(())
}
