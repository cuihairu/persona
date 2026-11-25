use super::*;

// ---- /sync/oplog ----

pub(super) fn validate_op(index: usize, op: &WireOp) -> Vec<ErrorItem> {
    let mut issues = Vec::new();
    let mut check = |field: &str, result: Result<(), String>| {
        if let Err(issue) = result {
            issues.push(ErrorItem::at(index, field, issue));
        }
    };
    check("op_id", parse_uuid(&op.op_id).map(|_| ()));
    check("item_id", parse_uuid(&op.item_id).map(|_| ()));
    check("device_id", parse_uuid(&op.device_id).map(|_| ()));
    // Both ends store lamport in an i64 column: an out-of-range value is truncated to a
    // negative number on insert via `as i64`, and when the client reads it back with
    // `as u64` the inflated value pins the LWW total order and deadlocks the local clock's
    // MAX() anti-regression guard (audit round 2 #6). Values within i64::MAX pass through.
    check(
        "lamport",
        if op.lamport <= i64::MAX as u64 {
            Ok(())
        } else {
            Err(format!("must be <= {}", i64::MAX))
        },
    );
    if op.kind.is_empty() || op.kind.len() > 64 {
        check("kind", Err("must be 1..=64 bytes".to_string()));
    }
    match op.op.as_str() {
        "put" => match &op.payload {
            None => check("payload", Err("required for put".to_string())),
            Some(payload) => {
                for field in ["ciphertext", "wrapped_item_key"] {
                    let raw = match field {
                        "ciphertext" => &payload.ciphertext,
                        _ => &payload.wrapped_item_key,
                    };
                    let decoded = B64.decode(raw).map(|bytes| bytes.len());
                    check(
                        field,
                        decoded
                            .map_err(|_| "malformed base64".to_string())
                            .and_then(|len| {
                                if len > MAX_PAYLOAD_BYTES {
                                    Err(format!("exceeds {MAX_PAYLOAD_BYTES} bytes"))
                                } else {
                                    Ok(())
                                }
                            }),
                    );
                }
            }
        },
        "delete" => {
            if op.payload.is_some() {
                check(
                    "payload",
                    Err("must be null for delete (tombstone)".to_string()),
                );
            }
        }
        _ => check("op", Err("must be \"put\" or \"delete\"".to_string())),
    }
    if let Some(ts) = &op.timestamp {
        check(
            "timestamp",
            chrono::DateTime::parse_from_rfc3339(ts)
                .map(|_| ())
                .map_err(|error| error.to_string()),
        );
    }
    issues
}

fn parse_uuid(raw: &str) -> Result<Uuid, String> {
    Uuid::parse_str(raw).map_err(|_| "must be a UUID".to_string())
}

/// Server-side oplog retention policy (the closeout of E2EE_SYNC_DESIGN §11 open question 3):
/// rolling deletion, by received_at, of relay rows older than the retention window; 0 = no
/// cleanup (the default, preserving the current pure-relay behavior). The window semantics
/// mean giving up the responsibility to re-send history to devices "offline beyond the
/// window": a cursor reset and re-pull returns a shrunken subset (LWW still converges on a
/// subset, and the missing parts are filled from each end's local source of truth plus
/// idempotent re-push — the client's push queue holds the draft, and re-pushing the same
/// op_id rebuilds it verbatim via INSERT OR IGNORE). Cleanup failure only warns: growth
/// governance is not a precondition of relay correctness.
pub(super) async fn enforce_oplog_retention(state: &AppState) {
    let days = state.oplog_retention_days;
    if days == 0 {
        return;
    }
    let cutoff = (Utc::now()
        - chrono::Duration::try_days(i64::from(days)).expect("retention days always fits"))
    .to_rfc3339_opts(SecondsFormat::Millis, true);
    match sqlx::query("DELETE FROM sync_oplog WHERE received_at < ?")
        .bind(&cutoff)
        .execute(&state.pool)
        .await
    {
        Ok(done) => {
            let removed = done.rows_affected();
            if removed > 0 {
                state.metrics.add_sync_ops_pruned(removed);
                tracing::info!(
                    event = "oplog_retention",
                    removed,
                    days,
                    "pruned relayed ops"
                );
            }
        }
        Err(error) => tracing::warn!(%error, "oplog retention skipped"),
    }
}
