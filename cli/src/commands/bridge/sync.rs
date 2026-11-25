use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct SyncPushNowRequest {
    #[serde(default)]
    pub(super) user_gesture: bool,
}

/// `sync_push_now_response`: a bridge projection sharing the field names of core
/// `SyncNowReport` (the core type does not implement Serialize, so the bridge mirrors the counts).
#[derive(Debug, Serialize)]
pub(super) struct SyncPushNowPayload {
    pub(super) pulled: usize,
    pub(super) materialized: usize,
    pub(super) conflicts: usize,
    pub(super) pending_identity: usize,
    pub(super) pushed: usize,
    pub(super) backfilled: u64,
}

/// Sync now (M5 batch 3: extension-side additions/edits land in the primary vault via the
/// existing `save_credential`, and this op pushes the backlog + increments up to the cloud).
/// The same core orchestration as the desktop `sync_now` (`SyncSession::open` → backfill →
/// run_cycle), differing in only two points:
/// - the master key comes from the bridge lock state (unlocked via `PERSONA_MASTER_PASSWORD`);
///   while locked it refuses;
/// - **no capture seam is hung** — one request per bridge process, so a seam dying with the
///   process is meaningless; writes made outside this request through the bridge are
///   reconciled idempotently by the next round of `backfill_existing`.
pub(super) async fn run_sync_push_now(db_path: &Path) -> Result<SyncPushNowPayload> {
    let (session, service) = open_bridge_sync_session(db_path).await?;
    let master = service
        .get_master_encryption_service()
        .map_err(|e| anyhow!("locked: master key unavailable: {e}"))?;

    let backfilled = session
        .backfill_existing(master)
        .await
        .map_err(|e| anyhow!("sync_cycle_failed: backfill: {e}"))?;
    let report = session
        .run_cycle(master)
        .await
        .map_err(|e| anyhow!("sync_cycle_failed: {e}"))?;

    Ok(SyncPushNowPayload {
        pulled: report.pulled,
        materialized: report.materialized,
        conflicts: report.conflicts,
        pending_identity: report.pending_identity,
        pushed: report.pushed,
        backfilled,
    })
}

pub(super) type BridgeSyncSession =
    persona_core::sync::runtime::SyncSession<persona_core::sync::remote::HttpSyncRemote>;

/// The session assembly shared by sync_push_now / sync_resolve_conflict: config-section
/// error classification first (cheap errors first, and unlocking is not even needed yet) →
/// keyring identity/token → unlock (bridge lock state) → travel-gate sampling →
/// `SyncSession::open`. Same semantics as the desktop `open_sync_session`; the service is
/// lent out with the return value (master is borrowed from it).
pub(super) async fn open_bridge_sync_session(
    db_path: &Path,
) -> Result<(BridgeSyncSession, PersonaService)> {
    let server_url = read_sync_server_url(db_path).await?;
    let db_key = db_path.to_string_lossy().to_string();
    let token = read_keyring_entry(KEYRING_SERVICE_SYNC_TOKEN, &db_key)?
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| anyhow!("sync_not_configured: sync server token is not set"))?;
    let identity_raw = read_keyring_entry(KEYRING_SERVICE_DEVICE_IDENTITY, &db_key)?
        .ok_or_else(|| anyhow!("sync_not_joined: this vault has not joined sync"))?;
    let identity = persona_core::sync::device::DeviceIdentity::from_stored_json(&identity_raw)
        .map_err(|e| {
            anyhow!("sync_identity_corrupted: stored device identity is unreadable: {e}")
        })?;

    let (service, _) = open_unlocked_service(db_path).await?;
    let db = open_db(db_path).await?;
    db.migrate().await?;
    // The travel gate is sampled once before assembly (same semantics as the desktop open_sync_session)
    let travel_active = service
        .travel_mode_active()
        .await
        .map_err(|e| anyhow!("sync_session_failed: travel mode check failed: {e}"))?;
    let session = persona_core::sync::runtime::SyncSession::open(
        &db,
        &identity,
        &server_url,
        &token,
        Box::new(move || travel_active),
    )
    .await
    .map_err(|e| anyhow!("sync_session_failed: {e}"))?;
    Ok((session, service))
}

#[derive(Debug, Deserialize)]
pub(super) struct SyncResolveConflictRequest {
    pub(super) item_id: String,
    pub(super) adopt_op_id: String,
    #[serde(default)]
    pub(super) user_gesture: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct SyncResolveConflictPayload {
    pub(super) resolved: bool,
}

/// Conflict resolution (aligning with the desktop SyncConflictsModal's "adopt a version"
/// semantics): `adopt_op_id` is the op id of a concurrent replica (same lamport, different
/// device); after adoption the remaining versions are evicted from the view (duplicate
/// resolution/unknown op → NotFound, the same wording as core).
pub(super) async fn run_sync_resolve_conflict(
    db_path: &Path,
    item_id: &str,
    adopt_op_id: &str,
) -> Result<SyncResolveConflictPayload> {
    // UUID parsing happens before session assembly (cheap errors first, and classification can be anchored without the keyring)
    let item_uuid = uuid::Uuid::parse_str(item_id)
        .map_err(|_| anyhow!("invalid_payload: item_id is not a UUID"))?;
    let adopt_uuid = uuid::Uuid::parse_str(adopt_op_id)
        .map_err(|_| anyhow!("invalid_payload: adopt_op_id is not a UUID"))?;
    let (session, service) = open_bridge_sync_session(db_path).await?;
    let master = service
        .get_master_encryption_service()
        .map_err(|e| anyhow!("locked: master key unavailable: {e}"))?;
    session
        .resolve_conflict(master, item_uuid, adopt_uuid)
        .await
        .map_err(|e| anyhow!("sync_resolve_failed: {e}"))?;
    Ok(SyncResolveConflictPayload { resolved: true })
}
