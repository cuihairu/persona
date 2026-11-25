//! Whole-database encrypted backup (phase one, client side).
//!
//! Backup chain = VACUUM INTO physical snapshot → gzip → PERSENC1 encryption:
//! - a physical snapshot loses nothing (the users verification subtree,
//!   wrapped_item_key, passkey private keys, change_history and audit rows are
//!   all captured) and needs no passphrase unlock — it is a file-level op;
//! - the byte stream is always gzipped before encryption (ciphertext is
//!   incompressible);
//! - PERSENC1 is byte-level interchangeable with the CLI `--encrypt` export
//!   format (see [`file_crypto`]).
//!
//! The server (persona-server `/api/v1/backups`) only ever sees ciphertext and
//! metadata; attachment blobs are not part of v1 backups (after a restore the
//! attachment metadata is present but the file bodies are missing).

pub mod client;
pub mod file_crypto;
pub mod snapshot;

pub use client::{BackupClient, BackupMeta, BackupPage, DownloadedBackup, PushResult};
pub use file_crypto::{decrypt_bytes, encrypt_bytes, is_persona_encrypted, KdfParams};
pub use snapshot::{create_backup_bytes, restore_backup_bytes, BackupBlob};
