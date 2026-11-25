use super::*;

#[derive(Debug, serde::Serialize)]
struct StatusResponse {
    head_seq: i64,
}

/// GET /sync/status: the group's operation water level (the "latest group version" from
/// sync-group-mode §II.5.5, used by the settings-page status display). Returns only
/// max(seq) — pure metadata, no ciphertext. The head water level is
/// max(oplog max seq, snapshot seq): after compaction the emptied oplog must not let the
/// group version regress (the §5.5 "monotonic version" hard requirement) — the snapshot
/// point is already the covered position of the facts.
pub async fn status(State(state): State<AppState>) -> Response {
    let head_seq: i64 = match sqlx::query_scalar(
        "SELECT MAX(m) FROM (
         SELECT COALESCE(MAX(seq), 0) AS m FROM sync_oplog
         UNION ALL
         SELECT seq FROM sync_snapshots WHERE id = 1
     )",
    )
    .fetch_one(&state.pool)
    .await
    {
        Ok(seq) => seq,
        Err(error) => return ApiError::internal(error).into_response(),
    };
    (Json(StatusResponse { head_seq })).into_response()
}
