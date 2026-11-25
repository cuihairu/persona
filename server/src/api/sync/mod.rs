//! `/api/v1/sync/*`: the E2EE sync relay (phase 2 batch 3, E2EE_SYNC_DESIGN §5/§6).
//!
//! The server's role = **pure relay + ciphertext custody**: oplog payloads and group key
//! envelopes are all ciphertext bytes; the server stores them blind, appends them in
//! arrival order and forwards them by cursor — it performs **no conflict adjudication and
//! no merging** (DR-4: letting the server arbitrate would hand merge semantics to a
//! component whose honesty we refuse to trust). Authenticity boundary: this phase does
//! not validate that op.device_id corresponds to the authenticated identity (static
//! tokens and SRP tokens are mixed with no unified mapping); write authenticity rests on
//! Bearer authentication plus the long-term "device-private-key-signed oplog" (§11);
//! THREAT_MODEL has registered that "a malicious client cannot be eradicated by the
//! server".
//!
//! Authentication: the whole sub-router is behind `require_bearer` — static tokens and
//! SRP short-term tokens are naturally compatible (the same middleware in auth.rs).
//!
//! Fail-closed authorization semantics: "having an envelope = being authorized". An
//! unauthorized device can fetch someone else's envelope via GET but cannot open it
//! (X25519: no matching private key, so tag verification always fails) — without the group
//! key no entry can be decrypted; this is guaranteed by cryptography rather than by a
//! server-side ACL.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::{decode_cursor, encode_cursor, ApiError, ErrorItem};
use crate::auth::DeviceName;
use crate::AppState;

/// Per-batch push entry limit (following events' convention of 500, design §5).
pub(crate) const MAX_BATCH_OPS: usize = 500;
/// Per-op decoded byte limit for ciphertext / wrapped_item_key. Credential ciphertext is
/// KB-scale; larger payloads (attachments) are a §11 open question and take the v2 channel.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
/// Pull page size: default / maximum entries (following events' cursor-pagination convention).
const PULL_DEFAULT_LIMIT: u32 = 200;
const PULL_MAX_FETCH: u32 = 500;

mod devices;
mod oplog;
mod push_pull;
mod snapshot;
mod status;
mod wire;

pub use devices::{
    delete_device, get_group_keys, list_devices, put_device_remark, put_group_key, register_device,
    rotate_begin,
};
pub use push_pull::{pull, push};
pub use snapshot::{get_snapshot, put_snapshot};
pub use status::status;
use wire::{
    DeviceInfo, DeviceListResponse, GroupKeyEntry, GroupKeysResponse, PullResponse, PushResponse,
    RegisterDeviceResponse, RotateBeginResponse,
};
pub use wire::{
    PullQuery, PushRequest, PutGroupKeyRequest, PutRemarkRequest, RegisterDeviceRequest,
    RotateBeginRequest, WireOp, WirePayload,
};

#[cfg(test)]
mod tests;
