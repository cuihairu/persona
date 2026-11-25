//! HTTP client for the sync remote (feature `remote-auth`): [`super::engine::SyncRemote`]
//! talks to persona-server's `/api/v1/sync/oplog` (oplog send/receive), while [`SyncAdminApi`]
//! talks to `/devices` + `/group-keys` (device registration / group key envelopes, §6 device lifecycle).
//! The authoritative wire contract lives in `server/src/api/sync.rs`: base64 STANDARD and the error
//! envelope `{"error":{"code","message",…}}`.
//!
//! Serde's default for `Vec<u8>` is an array of numbers rather than a base64 string, which does not
//! match the server's wire layer (`WirePayload` carries base64 text) — so this module converts through
//! the [`WireOp`]/[`WirePayload`] intermediate structures by hand instead of serializing `SyncOp` directly.
//!
//! Tolerance policy for per-entry corruption (agreed by the [`SyncRemote`] trait): if parsing one pulled op
//! fails (bad UUID / bad base64 / a put-delete whose payload shape contradicts it) that entry is skipped
//! rather than aborting the whole batch. The oplog is an append-only ciphertext relay, so one corrupt
//! entry must not stall convergence of the rest; skipping affects only that entry and not cursor
//! advancement. The push side carries ciphertext produced locally moments before, so there is no
//! corruption path. An unknown `kind` lands in the store as [`ItemKind::Unknown`] (forward compatible,
//! never skipped).

mod admin;
mod client;
mod cloud;
mod group_key_store;
mod http;
mod wire;

pub use admin::*;
pub use client::*;
pub use cloud::*;
pub use group_key_store::*;

#[cfg(test)]
mod tests;
