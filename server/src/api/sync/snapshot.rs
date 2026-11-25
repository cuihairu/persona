use super::*;

// ---- Library-level snapshots (S2 closeout, E2EE_SYNC_DESIGN §5 "library snapshots and
// operation compaction") ----
// A single snapshot: PUT upserts and overwrites (id = 1), and the transaction deletes the
// ops with seq <= S (compaction running in the same direction as day-based retention, and
// the "a shrunken subset still converges" invariant is unchanged). GET serves bootstrap for
// a new device with an empty store — segments deleted by retention are genuinely lost data
// for a new device (no local source of truth to fill them from), so the snapshot patches
// the holes. The server stores ciphertext blind; the zero-knowledge surface is unchanged.

/// Snapshot package byte limit. One package holds the whole encrypted store (a personal
/// credential store's ciphertext is MB-sized); going over means the client's packaging has
/// run away (or is being abused), so reject rather than silently store it — the same line
/// of defense as the oplog's 512 KiB per entry.
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct PutSnapshotRequest {
    /// Coverage position: pull to head first, then the seq after the pushed acks — the
    /// snapshot claims to contain all effects of `seq <= S`.
    seq: i64,
    /// Self-reported by the packaging device, display only (same convention as the
    /// oplog's device_id).
    device_id: String,
    /// base64 (STANDARD) — a LibrarySnapshotPayload encrypted wholesale with the group key.
    ciphertext: String,
}

#[derive(Debug, Serialize)]
struct PutSnapshotResponse {
    seq: i64,
    /// Number of oplog rows compacted away in this transaction (for tests and observation).
    pruned_ops: u64,
}

#[derive(Debug, Serialize)]
struct SnapshotResponse {
    seq: i64,
    device_id: String,
    ciphertext: String,
    created_at: String,
}

/// PUT /sync/snapshot: upload a snapshot. The overwrite semantics narrow monotonically by
/// water level — accepted only when seq is not below the stored snapshot (or when none is
/// stored yet), so re-packaging the same seq overwrites idempotently, while a lagging end
/// below the stored water level is rejected with 409: otherwise "the snapshot regresses to
/// the older S2 + the ops in the covered range are already deleted" leaves a data hole
/// (bootstrap starts from the old snapshot, and the S2..S1 history has neither snapshot nor
/// ops).
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

    // Transaction: write the snapshot (single-row upsert with a monotonic seq gate) + compact
    // the ops in the covered range. If either step fails, roll the whole thing back — no
    // intermediate state of "the snapshot was replaced but the old ops are still there"
    // (that would make bootstrap take the old snapshot and replay ops already inside it,
    // idempotent and harmless but wasteful; the real danger runs the other way: the ops are
    // deleted but the snapshot was never written, so the covered range has neither snapshot
    // nor ops = a data hole).
    // The monotonic gate sits in the upsert's WHERE clause (decided inside the same write
    // lock, so there is no check-then-write race): the loser has 0 rows affected -> 409
    // rollback, and the ops are never deleted.
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
        // Behind the water level: the stored snapshot is more ahead, so this upload can
        // neither overwrite nor compact — fail-visible 409 so the lagging end pulls the
        // incremental and re-packages first.
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

/// GET /sync/snapshot: the latest snapshot (the bootstrap starter package); 404 absent if
/// none has been uploaded yet.
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
