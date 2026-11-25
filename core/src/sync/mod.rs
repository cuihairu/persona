//! E2EE sync core (E2EE_SYNC_DESIGN phase 2).
//!
//! Trust root = master password + a private key per device (DR-1); the sync
//! ciphertext is decoupled from the master password——entries are wrapped by a
//! per-item key (the same envelope shape as locally), the item key is wrapped
//! by the group key, and the group key exists on the server only in the form
//! of a "device envelope" ([`envelope`]).
//!
//! - [`capture`]: the sync capture seam on the service write path (trait + a
//!   default implementation in the assembly layer)
//! - [`snapshot`]: the plaintext format of the oplog payload ciphertext
//!   (metadata + CredentialData composite snapshot)
//! - [`keys`]: generation and types of the group key / device keypair
//! - [`device`]: the keyring/file record format of the device identity
//!   (shared for host persistence)
//! - [`envelope`]: sealing and opening of the `persona-dev-env-1` envelope
//! - [`oplog`]: the SyncOp structure + the pure LWW/conflict dual-version
//!   logic (DR-4)
//! - [`engine`]: push/pull cycle orchestration + Lamport clock + travel gate
//! - [`cursor`]: encoding and decoding of the server seq cursor (the format is
//!   shared between server pagination and the local watermark)
//! - [`materialize`]: writing the oplog primary entries into the main DB after
//!   a pull (materializing credential rows)
//! - [`resolve`]: the conflict resolution data plane (displayable versions +
//!   acceptance bookkeeping, phase 3c)
//! - [`runtime`]: assembly of the SyncSession (opening envelopes on open /
//!   backfilling the stock / run_cycle / capture output)——the one-shot entry
//!   point for the host's sync_now
//!
//! This module only holds the pure crypto layer and data structures; local
//! persistence lives in [`crate::storage::sync_repository`]. Persisting the
//! device private key (OS keyring `persona-device` / 0600 file fallback) is
//! the host's responsibility——core does not depend on keyring. The HTTP wire
//! layer is in [`remote`] (cfg remote-auth).
//!
//! Dynamic password pairing (cross-device sync S1, `docs/sync-group-mode.md`)
//! lives in [`pairing`]: joining a group with no account, the short code goes
//! through an Argon2id domain separator and then into SRP-6a PAKE, and the
//! group key is wrapped with pairing-key AEAD and delivered via the relay,
//! which stays zero-knowledge.

pub mod capture;
pub mod cursor;
pub mod device;
pub mod engine;
pub mod envelope;
pub mod keys;
pub mod materialize;
pub mod oplog;
pub mod pairing;
#[cfg(feature = "remote-auth")]
pub mod remote;
pub mod resolve;
pub mod runtime;
pub mod snapshot;
