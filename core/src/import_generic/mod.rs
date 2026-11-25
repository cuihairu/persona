//! Generic-format import (FEATURE_GAP_ANALYSIS #20): parsing of CSV + Bitwarden
//! JSON exports and planning the import.
//!
//! Covers the mainstream plaintext export shapes:
//! - **CSV** (column roles sniffed from the headers): Bitwarden CSV (with
//!   `type`-column branching), Chrome,
//!   Firefox, 1Password CSV, KeePass 1.x/2.x CSV;
//! - **Bitwarden JSON** (plaintext exports with `encrypted: false`;
//!   password-protected exports are explicitly
//!   rejected with guidance).
//!
//! Same design line as [`crate::import_1pux`]: parse → a pure function plans an
//! [`ImportPlan`], which the CLI/desktop preview before confirming and writing
//! to the store. A CSV export has no notion of containers,
//! so the whole file lands in a single identity (`identity_name` is supplied by
//! the caller, usually the filename stem);
//! Bitwarden's folder maps to a persona tag rather than an identity (a folder
//! is a lightweight grouping inside the vault,
//! not a container like a 1Password vault). KeePass goes through its CSV export
//! (KeePass →
//! Export → CSV) and never reads the KDBX encrypted container directly — the
//! same plaintext-container
//! policy as 1PUX/maFile, avoiding the heavy keepass-rs dependency.

use anyhow::Result;

use crate::import_1pux::ImportPlan;

mod bitwarden;
mod csv;
mod plan;
#[cfg(test)]
mod tests;

use bitwarden::{parse_bitwarden_json, plan_bitwarden};
pub use bitwarden::{BitwardenFolder, BitwardenItem};
use csv::{parse_csv, plan_csv};

/// The single container key for generic imports: one identity per whole file,
/// with credentials linked back through it.
pub const GENERIC_VAULT_KEY: &str = "generic-import";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericExportFormat {
    /// A password manager CSV export (column roles sniffed from headers; see
    /// `map_roles` in csv.rs for the mapping)
    Csv,
    /// A Bitwarden plaintext JSON export (`encrypted: false`)
    BitwardenJson,
}

/// The product of parsing: a CSV record set or a Bitwarden JSON export.
#[derive(Debug, Clone)]
pub enum GenericExport {
    Csv(CsvExport),
    BitwardenJson(BitwardenExport),
}

/// A CSV export: headers + data rows (columns align with the headers
/// positionally; short rows are tolerated via `flexible`).
#[derive(Debug, Clone)]
pub struct CsvExport {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// A Bitwarden plaintext JSON export.
#[derive(Debug, Clone)]
pub struct BitwardenExport {
    pub folders: Vec<BitwardenFolder>,
    pub items: Vec<BitwardenItem>,
}

/// Sniff the format automatically: after stripping a UTF-8 BOM, a leading
/// `{`/`[` means JSON, anything else is treated as CSV.
/// The extension is not trustworthy (users often rename files), so judge by
/// content.
pub fn detect_format(bytes: &[u8]) -> GenericExportFormat {
    let head = String::from_utf8_lossy(strip_utf8_bom(bytes));
    match head.trim_start().starts_with('{') || head.trim_start().starts_with('[') {
        true => GenericExportFormat::BitwardenJson,
        false => GenericExportFormat::Csv,
    }
}

/// Parse a generic export file. Pass `None` for `format` to sniff automatically.
pub fn parse_generic(bytes: &[u8], format: Option<GenericExportFormat>) -> Result<GenericExport> {
    match format.unwrap_or_else(|| detect_format(bytes)) {
        GenericExportFormat::Csv => parse_csv(bytes).map(GenericExport::Csv),
        GenericExportFormat::BitwardenJson => {
            parse_bitwarden_json(bytes).map(GenericExport::BitwardenJson)
        }
    }
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_prefix([0xEF, 0xBB, 0xBF].as_slice())
        .unwrap_or(bytes)
}

/// Map a generic export into an [`ImportPlan`]: the whole file lands in one
/// identity (`identity_name`,
/// with `source_label` recorded in the description for traceability). A pure
/// function with no IO.
pub fn plan_generic_import(
    export: &GenericExport,
    identity_name: &str,
    source_label: &str,
) -> ImportPlan {
    match export {
        GenericExport::Csv(csv) => plan_csv(csv, identity_name, source_label),
        GenericExport::BitwardenJson(bw) => plan_bitwarden(bw, identity_name, source_label),
    }
}
