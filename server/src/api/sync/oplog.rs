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

/// server 侧 oplog 保留策略（E2EE_SYNC_DESIGN §11 开放问题 3 收口）：
/// 按 received_at 滚动删除超过保留窗口的中继行，0 = 不清理（默认，
/// 保持纯中继现状）。窗口语义 = 放弃向「离线超过窗口」的设备补发历史
/// 的责任：游标重置重拉会拿到缩水子集（LWW 对子集仍收敛，缺失部分靠
/// 各端本地事实源与重推幂等补齐——客户端 push 队列持底稿，重推同 op_id
/// 经 INSERT OR IGNORE 原样重建）。清理失败仅告警：增长治理不是中继
/// 正确性的前置条件。
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
