//! Data model for the travel pack: pack payload, attachment files, count
//! report, and status snapshot.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Attachment blob file (raw bytes from disk, kept in sealed form -- on
/// restore the rows are re-inserted verbatim, so the files must go back
/// verbatim too; any decrypt/re-encrypt would break their pairing with the
/// rows).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TravelBlobFile {
    pub storage_path: String,
    /// Hex sha256 of the content (from the content_hash column of the
    /// attachments/attachment_chunks rows, re-verified on read).
    pub sha256: String,
    pub data_b64: String,
}

/// The packed data (plaintext JSON, before gzip).
#[derive(Debug, Serialize, Deserialize)]
pub struct TravelPack {
    pub format_name: String,
    pub format_version: u32,
    pub created_at: String,
    pub app_version: String,
    /// Original workspace active pointer when it referenced a removed identity
    /// at enter time (restored on exit; None otherwise).
    pub active_identity_id: Option<String>,
    /// Redundant index: the set of removed identity ids.
    pub identity_ids: Vec<String>,
    /// Table name -> raw rows (BLOB cells as `{"b64": "..."}`).
    pub tables: std::collections::BTreeMap<String, Vec<Map<String, Value>>>,
    pub attachment_files: Vec<TravelBlobFile>,
}

/// Count report for enter/exit (audit metadata and UI feedback).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TravelCounts {
    pub identities: u32,
    pub credentials: u32,
    pub attachments: u32,
    pub passkeys: u32,
    pub wallets: u32,
    pub history_rows: u32,
    pub files: u32,
}

impl TravelCounts {
    pub(crate) fn from_pack(pack: &TravelPack) -> Self {
        let table = |name: &str| pack.tables.get(name).map(Vec::len).unwrap_or(0);
        Self {
            identities: table("identities") as u32,
            credentials: table("credentials") as u32,
            attachments: table("attachments") as u32,
            passkeys: table("passkeys") as u32,
            wallets: table("crypto_wallets") as u32,
            history_rows: table("change_history") as u32,
            files: pack.attachment_files.len() as u32,
        }
    }
}

/// Travel mode status (reading it requires no travel passphrase; used for
/// UI/CLI display).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TravelStatus {
    /// The travel_mode flag in settings.
    pub active: bool,
    /// When travel mode was entered (RFC3339; written by enter, cleared by
    /// exit).
    pub entered_at: Option<String>,
    /// Whether the sidecar file exists at `<db dir>/travel.persenc`.
    pub sidecar_exists: bool,
    /// `active && !sidecar_exists`: the flag claims travel mode is on, but the
    /// data container is gone (hand-deleted or corrupted) -- the data is lost;
    /// report it honestly instead of pretending it is recoverable.
    pub inconsistent: bool,
}
