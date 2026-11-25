//! Travel Mode: move all data of the marked identities off this device in
//! one piece and restore it unchanged on exit (1Password's
//! "remove vaults from devices" semantics).
//!
//! # Data flow
//!
//! enter: read every row of the marked identities (12 tables) + the
//! attachment blob file bytes (sealed on disk, never decrypted) ->
//! serialize a `TravelPack` -> gzip -> PERSENC1 encryption (a travel
//! passphrase independent of the master password) -> write the sidecar
//! `<db dir>/travel.persenc` -> delete from the main database in one
//! transaction (audit_logs FK references stripped first). The main database
//! is left with zero trace (not even a name); the master password cannot
//! open the sidecar.
//!
//! exit: read the sidecar -> decrypt and unpack (verifying the format) ->
//! restore with a single `INSERT OR REPLACE` transaction (parent tables
//! first) + reset settings -> rewrite the blob files -> delete the sidecar.
//! Row ids and the encrypted form (`wrapped_item_key` / `encrypted_data`
//! bytes) are unchanged -- per-item keys are wrapped by the master key, so
//! as long as the master password is unchanged they stay decryptable after
//! restore; that is why changing the master password is refused while travel
//! mode is active (see the check in `PersonaService::change_master_password`).
//!
//! # Crash-window semantics
//!
//! | Crash point | State | Recovery |
//! |---|---|---|
//! | sidecar written, transaction not committed | sidecar present, `travel_mode=false`, rows untouched | enter refuses (sidecar already exists); delete the leftover sidecar or just exit to restore |
//! | transaction committed, blob files not removed | rows deleted, files left behind | exit overwrites the files at their original storage_path, self-healing |
//! | user deleted the sidecar by hand | `travel_mode=true` with the sidecar missing | `travel_status().inconsistent = true` -- the data lived only in the sidecar and is gone (reported honestly rather than faking recoverability) |
//!
//! # Known limitations
//!
//! - A forgotten travel passphrase = unreadable sidecar = the data can only
//!   come back from a full-database backup taken before enter (a backup is a
//!   point-in-time snapshot that still contains the marked identities).
//! - A local attacker can delete or replace the sidecar (denial of service);
//!   without the travel passphrase a replacer cannot build ciphertext that
//!   passes GCM authentication, so injection is not feasible.
//! - audit_logs do not travel (they hold ids only, no plaintext, and are
//!   kept as evidence); change_history snapshots contain plaintext metadata
//!   and do travel.
//!
//! # Module layout
//!
//! - `model`: pack / status / counts types and format constants
//! - `codec`: value-level SQLite row <-> JSON codec plus whitelist validation
//! - `pack`: cross-database read aggregation (`build_pack`)
//! - `sidecar`: sidecar path and encrypted wrapping (seal / open / atomic write)
//! - `tx`: the enter / exit transactions (including favicon cache pruning and the settings flags)
//! - `blob`: attachment file I/O and path-escape defense

use sha2::{Digest, Sha256};

mod blob;
mod codec;
mod model;
mod pack;
mod sidecar;
mod tx;

pub(crate) use blob::{delete_blob_files, write_blob_files};
pub use model::{TravelBlobFile, TravelCounts, TravelPack, TravelStatus};
pub(crate) use pack::build_pack;
pub use sidecar::sidecar_path;
pub(crate) use sidecar::{open_pack, seal_pack, write_sidecar_atomic};
pub(crate) use tx::{apply_enter_tx, apply_exit_tx};

/// Sidecar file name (placed next to the database file).
pub const SIDECAR_FILENAME: &str = "travel.persenc";

/// Format name (checked by `open_pack`).
pub const FORMAT_NAME: &str = "persona-travel-1";

/// Format version.
pub const FORMAT_VERSION: u32 = 1;

/// Tables packed on enter (restored in this order, parent tables first --
/// FK dependency order).
const PACKED_TABLES_IN_INSERT_ORDER: &[&str] = &[
    "identities",
    "credentials",
    "attachments",
    "attachment_chunks",
    "passkeys",
    "crypto_wallets",
    "wallet_addresses",
    "wallet_metadata",
    "transaction_requests",
    "signed_transactions",
    "workspace_members",
    "change_history",
];

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
use blob::write_blob_file;
#[cfg(test)]
use codec::{check_table_name, insert_rows, row_to_json};

#[cfg(test)]
mod tests;
