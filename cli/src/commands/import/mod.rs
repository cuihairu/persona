//! Plain JSON / YAML / CSV import command: file validation → decryption →
//! parsing → preview → conflict check → execution (backup, dry-run, and
//! merge/replace/skip modes).
//!
//! # Module layout
//!
//! The types (`ImportArgs` and the three import data structures) stay in this hub —
//! their private fields are read and written by flow / display / formats and by the
//! tests; flow orchestration, format parsing, and result display each live in their
//! own submodule.

use std::path::PathBuf;

use clap::Args;

mod display;
mod flow;
mod formats;

pub use flow::execute;

#[cfg(test)]
mod tests;

#[derive(Args, Clone)]
pub struct ImportArgs {
    /// Import file path
    file: PathBuf,

    /// Import mode (merge, replace, skip)
    #[arg(short, long, default_value = "merge")]
    mode: String,

    /// Dry run - show what would be imported without making changes
    #[arg(long)]
    dry_run: bool,

    /// Force import without confirmation
    #[arg(short, long)]
    force: bool,

    /// Backup existing data before import
    #[arg(short, long)]
    backup: bool,

    /// Decrypt imported data
    #[arg(long)]
    decrypt: bool,

    /// Interactive selection of identities to import
    #[arg(short, long)]
    interactive: bool,
}

#[derive(Debug, Clone)]
struct ImportData {
    version: String,
    created: String,
    identities: Vec<ImportIdentity>,
}

#[derive(Debug, Clone)]
struct ImportIdentity {
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug)]
struct ImportConflict {
    name: String,
    conflict_type: String,
    existing_data: String,
    new_data: String,
}
