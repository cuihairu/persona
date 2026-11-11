use super::*;

// ---- 库级快照（S2 收口，E2EE_SYNC_DESIGN §5「库级快照与指令压缩」）----
// 单快照：PUT upsert 覆盖（id = 1），事务内删 seq ≤ S 的 ops（与按天
// retention 同向的压缩，「缩水子集也收敛」口径不变）。GET 供空库新设备
// bootstrap——retention 删掉的段对新设备是真丢数据（无本地事实源可补），
// 快照补洞。服务器盲存密文，零知识面不变。

/// 快照包字节上限。整库密文一包（个人凭据库密文 MB 级）；超过说明客户端
/// 打包失控（或滥用），拒绝而非静默存下——与 oplog 512 KiB/条同一防线思路。
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct PutSnapshotRequest {
    /// 覆盖位点：先 pull 到 head 再 push ack 后的 seq——快照声称包含
    /// `seq ≤ S` 的全部效果。
    seq: i64,
    /// 打包设备自报，仅展示（与 oplog 的 device_id 同口径）。
    device_id: String,
    /// base64（STANDARD）——group key 整包加密的 LibrarySnapshotPayload。
    ciphertext: String,
}

#[derive(Debug, Serialize)]
struct PutSnapshotResponse {
    seq: i64,
    /// 本事务内被压缩删除的 oplog 行数（测试与观测用）。
    pruned_ops: u64,
}

#[derive(Debug, Serialize)]
struct SnapshotResponse {
    seq: i64,
    device_id: String,
    ciphertext: String,
    created_at: String,
}

/// PUT /sync/snapshot：上传快照。覆盖语义按水位单调收窄——seq 不小于
/// 现存快照（或尚无快照）才接受（同 seq 重打包幂等覆盖），低于现存水位
/// 的落后端 409 拒绝：否则「快照回退到旧 S2 + 覆盖区间 ops 已删」会留
/// 数据洞（bootstrap 拿旧快照起步，S2..S1 的历史既无快照也无 ops）。
pub async fn put_snapshot(
    State(state): State<AppState>,
    payload: Result<Json<PutSnapshotRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let request = match payload {
        Ok(Json(request)) => request,
        Err(rejection) => {
            return ApiError::rejection(rejection.status(), rejection.body_text()).into_response()
        }
    };
    if request.seq < 0 {
        return ApiError::validation(
            "invalid snapshot",
            vec![ErrorItem::batch("seq", "must be at least 0")],
        )
        .into_response();
    }
    if request.device_id.trim().is_empty() {
        return ApiError::validation(
            "invalid snapshot",
            vec![ErrorItem::batch("device_id", "must not be empty")],
        )
        .into_response();
    }
    let ciphertext = match B64.decode(&request.ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => {
            return ApiError::validation(
                "invalid snapshot",
                vec![ErrorItem::batch("ciphertext", "must be valid base64")],
            )
            .into_response()
        }
    };
    if ciphertext.is_empty() {
        return ApiError::validation(
            "invalid snapshot",
            vec![ErrorItem::batch("ciphertext", "must not be empty")],
        )
        .into_response();
    }
    if ciphertext.len() > MAX_SNAPSHOT_BYTES {
        return ApiError::payload_too_large_with(MAX_SNAPSHOT_BYTES).into_response();
    }

    // 事务：写快照（单行 upsert，seq 单调闸）+ 压缩覆盖区间 ops。分解失败
    // 即整体回滚——不允许「快照已换、旧 ops 还在」的中间态（那会让
    // bootstrap 拿旧快照又重放已进快照的 ops，幂等无害但浪费；真正的危险
    // 是反向：ops 删了快照没写上，覆盖区间既无快照也无 ops = 数据洞）。
    // 单调闸压在 upsert 的 WHERE 上（同一写锁内判定，无检查-写竞态）：
    // 输家 0 行受影响 → 409 回滚，绝不删 ops。
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return ApiError::internal(error).into_response(),
    };
    let upsert = sqlx::query(
        "INSERT INTO sync_snapshots (id, seq, device_id, ciphertext, size)
     VALUES (1, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
        seq = excluded.seq,
        device_id = excluded.device_id,
        ciphertext = excluded.ciphertext,
        size = excluded.size,
        created_at = excluded.created_at
     WHERE excluded.seq >= sync_snapshots.seq",
    )
    .bind(request.seq)
    .bind(request.device_id.trim())
    .bind(&ciphertext)
    .bind(ciphertext.len() as i64)
    .execute(&mut *tx)
    .await;
    let won = match upsert {
        Ok(done) => done.rows_affected() == 1,
        Err(error) => return ApiError::internal(error).into_response(),
    };
    if !won {
        // 落后水位：现存快照更 ahead，本次上传既不能覆盖也不能压缩——
        // fail-visible 409，让落后端先 pull 增量再重打包。
        return ApiError::conflict(
            "snapshot seq is behind the stored snapshot; pull and re-package",
        )
        .into_response();
    }
    let pruned = sqlx::query("DELETE FROM sync_oplog WHERE seq <= ?")
        .bind(request.seq)
        .execute(&mut *tx)
        .await;
    let pruned_ops = match pruned {
        Ok(done) => done.rows_affected(),
        Err(error) => return ApiError::internal(error).into_response(),
    };
    if let Err(error) = tx.commit().await {
        return ApiError::internal(error).into_response();
    }
    (Json(PutSnapshotResponse {
        seq: request.seq,
        pruned_ops,
    }))
    .into_response()
}

/// GET /sync/snapshot：最新快照（bootstrap 起步包）；尚未上传过 404 absent。
pub async fn get_snapshot(State(state): State<AppState>) -> Response {
    let row = sqlx::query(
        "SELECT seq, device_id, ciphertext, created_at FROM sync_snapshots WHERE id = 1",
    )
    .fetch_optional(&state.pool)
    .await;
    match row {
        Ok(Some(row)) => {
            let ciphertext: Vec<u8> = row.get("ciphertext");
            (Json(SnapshotResponse {
                seq: row.get("seq"),
                device_id: row.get("device_id"),
                ciphertext: B64.encode(ciphertext),
                created_at: row.get("created_at"),
            }),)
                .into_response()
        }
        Ok(None) => ApiError::absent("no snapshot uploaded yet").into_response(),
        Err(error) => ApiError::internal(error).into_response(),
    }
}
