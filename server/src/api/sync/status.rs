use super::*;

#[derive(Debug, serde::Serialize)]
struct StatusResponse {
    head_seq: i64,
}

/// GET /sync/status：组指令流水位（sync-group-mode §二.5.5「组最新版本号」，
/// 设置页状态显示用）。只回 max(seq)——纯元数据，不含密文。头水位按
/// max(oplog max seq, 快照 seq)：压缩后 oplog 清空不能让组版本号回退
/// （§5.5「单调版本号」硬要求）——快照点即已被覆盖的事实位置。
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
