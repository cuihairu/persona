//! Backup chain: VACUUM INTO physical snapshot → gzip → PERSENC1 encryption;
//! restore runs it in reverse.
//!
//! Restore = decrypt → magic-adaptive decompression → SQLite header check →
//! write the target path. No logical import code to write: a restored physical
//! snapshot is already the complete database (schema migrations run normally on
//! first open by the restoring side).

use super::file_crypto::{decrypt_bytes, encrypt_bytes, KdfParams};
use anyhow::{anyhow, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, SqlitePool};
use std::io::{Read, Write};
use std::path::Path;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// An encrypted backup (in-memory bytes + metadata).
pub struct BackupBlob {
    pub bytes: Vec<u8>,
    pub size_bytes: u64,
    /// Hex digest of the ciphertext (the server's dedupe key and the download
    /// re-verification key).
    pub sha256: String,
}

/// Snapshot the database into `dest` (VACUUM INTO: the target must not exist;
/// the output is self-contained with no WAL dependency).
///
/// Prefer a bound parameter; if the driver rejects it, fall back to a
/// single-quote-escaped literal (the path-injection surface is closed by the
/// `''` escaping). Cannot run inside a transaction (a VACUUM restriction), so
/// callers must not wrap it in one.
///
/// Known pitfall (measured 2026-09): sqlx 0.8 returns Ok for VACUUM INTO on a
/// `sqlite::memory:` connection pool without ever writing anything to disk
/// (both SQLite itself and file-database paths behave normally) — in-memory
/// databases are unsuitable for the backup chain, and the production path
/// identities.db is always a file database. The output-existence check at the
/// end exists precisely to keep such silent failures from leaking an empty
/// backup.
pub async fn vault_snapshot(pool: &SqlitePool, dest: &Path) -> Result<()> {
    let dest_str = dest
        .to_str()
        .ok_or_else(|| anyhow!("snapshot path must be valid UTF-8"))?;
    if let Err(bind_error) = sqlx::query("VACUUM INTO ?1")
        .bind(dest_str)
        .execute(pool)
        .await
    {
        // Fallback: escaped literal (in a SQLite string literal only ' needs
        // escaping to ''); the path first goes through the ?1 bound attempt and
        // only reaches here once that has failed, the literal is escaped per
        // SQLite rules
        let escaped = dest_str.replace('\'', "''");
        sqlx::query(AssertSqlSafe(format!("VACUUM INTO '{escaped}'")))
            .execute(pool)
            .await
            .map_err(|error| {
                anyhow!("VACUUM INTO failed: {error} (bound-param attempt: {bind_error})")
            })?;
    }
    if !dest.exists() {
        anyhow::bail!("VACUUM INTO reported success but {dest_str} does not exist");
    }
    Ok(())
}

/// gzip compression (default level). The `io::Error` of an in-memory `Vec`
/// writer is not actually reachable.
pub fn gzip_bytes(data: Vec<u8>) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::with_capacity(data.len() / 2), Compression::default());
    encoder
        .write_all(&data)
        .and_then(|()| encoder.finish())
        .expect("in-memory gzip cannot fail")
}

/// Magic-adaptive decompression: decompress when the bytes start with `1f 8b`
/// (gzip), otherwise return them unchanged (tolerates uncompressed raw SQLite
/// bytes — e.g. old manually encrypted export files).
pub fn maybe_gunzip(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let mut decoder = GzDecoder::new(data);
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .map_err(|error| anyhow!("gunzip failed: {error}"))?;
        Ok(out)
    } else {
        Ok(data.to_vec())
    }
}

/// Create an encrypted backup: snapshot → gzip → encrypt → sha256 (one chain).
pub async fn create_backup_bytes(
    pool: &SqlitePool,
    passphrase: &str,
    kdf: Option<KdfParams>,
) -> Result<BackupBlob> {
    let dir = tempfile::tempdir()?;
    let snapshot_path = dir.path().join("snapshot.db");
    vault_snapshot(pool, &snapshot_path).await?;
    let raw = std::fs::read(&snapshot_path)
        .map_err(|error| anyhow!("failed to read snapshot: {error}"))?;
    drop(dir); // clean up the snapshot temp file as early as possible

    let gz = gzip_bytes(raw);
    let bytes = encrypt_bytes(&gz, passphrase, kdf)?;
    let size_bytes = bytes.len() as u64;
    let sha256 = hex_lower(&Sha256::digest(&bytes));
    Ok(BackupBlob {
        bytes,
        size_bytes,
        sha256,
    })
}

/// Restore from an encrypted backup: decrypt → adaptive decompression →
/// SQLite header check → write `dest`.
///
/// Only produces the file; does not open the database or run migrations —
/// sequencing the swap/reopen is the caller's job (the CLI keeps a .bak before
/// swapping the file; the desktop side has connection-draining constraints, see
/// each implementation).
pub fn restore_backup_bytes(data: &[u8], passphrase: &str, dest: &Path) -> Result<()> {
    let decrypted = decrypt_bytes(data, passphrase)?;
    let plain = maybe_gunzip(&decrypted)?;
    if plain.len() < SQLITE_HEADER.len() || &plain[..SQLITE_HEADER.len()] != SQLITE_HEADER {
        anyhow::bail!("restored payload is not a SQLite database (header mismatch)");
    }
    std::fs::write(dest, plain)
        .map_err(|error| anyhow!("failed to write restored database: {error}"))?;
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Identity, IdentityType};
    use crate::storage::repository::{IdentityRepository, Repository};
    use crate::storage::Database;

    fn fast_kdf() -> KdfParams {
        KdfParams {
            mem_kib: 8 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    #[test]
    fn gzip_round_trips_and_magic_detection() {
        let raw = b"SQLite format 3\0 some database bytes".to_vec();
        let gz = gzip_bytes(raw.clone());
        assert_eq!(&gz[..2], &[0x1f, 0x8b]);
        assert_eq!(maybe_gunzip(&gz).unwrap(), raw);
        // non-gzip bytes are returned as-is
        assert_eq!(maybe_gunzip(&raw).unwrap(), raw);
    }

    #[test]
    fn maybe_gunzip_reports_corrupt_stream() {
        let mut gz = gzip_bytes(b"payload".to_vec());
        gz.truncate(gz.len() - 4); // truncation corrupts the CRC/length
        assert!(maybe_gunzip(&gz).is_err());
    }

    #[tokio::test]
    async fn snapshot_preserves_rows_across_vacuum_into() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::from_file(dir.path().join("source.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        let identity = Identity::new("Backup Source".to_owned(), IdentityType::Personal);
        let created = repo.create(&identity).await.unwrap();

        let snapshot_path = dir.path().join("snapshot.db");
        vault_snapshot(db.pool(), &snapshot_path).await.unwrap();
        assert!(snapshot_path.exists());

        // The snapshot is self-contained SQLite: the rows survive a reopen
        let reopened = Database::from_file(&snapshot_path).await.unwrap();
        let repo2 = IdentityRepository::new(reopened.clone());
        let fetched = repo2.find_by_id(&created.id).await.unwrap();
        assert!(fetched.is_some(), "snapshot must preserve rows");

        // VACUUM INTO refuses to overwrite an existing target
        assert!(vault_snapshot(db.pool(), &snapshot_path).await.is_err());
    }

    #[tokio::test]
    async fn create_then_restore_round_trips_a_working_database() {
        // from_file rather than in_memory: VACUUM INTO on an in-memory
        // database silently has no effect with sqlx (see the vault_snapshot
        // comment); the backup chain only works with file databases
        let dir = tempfile::tempdir().unwrap();
        let db = Database::from_file(dir.path().join("source.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        let identity = Identity::new("Roundtrip".to_owned(), IdentityType::Personal);
        let created = repo.create(&identity).await.unwrap();

        let blob = create_backup_bytes(db.pool(), "backup-pass", Some(fast_kdf()))
            .await
            .unwrap();
        assert_eq!(blob.size_bytes, blob.bytes.len() as u64);
        assert_eq!(blob.sha256.len(), 64);
        // No plaintext trace survives in the ciphertext (the name itself is
        // not separately encrypted, but the whole snapshot is encrypted+gzip)
        assert!(!blob
            .bytes
            .windows(b"Roundtrip".len())
            .any(|w| w == b"Roundtrip"));

        let restored_dir = tempfile::tempdir().unwrap();
        let restored_path = restored_dir.path().join("restored.db");
        restore_backup_bytes(&blob.bytes, "backup-pass", &restored_path).unwrap();

        let restored = Database::from_file(&restored_path).await.unwrap();
        let repo2 = IdentityRepository::new(restored.clone());
        let fetched = repo2.find_by_id(&created.id).await.unwrap();
        assert!(
            fetched.is_some(),
            "restored database must contain the identity"
        );
    }

    /// sqlx returns Ok for VACUUM INTO on a `:memory:` pool without ever
    /// writing anything to disk — the output check must turn that kind of
    /// silent failure into an explicit error (this behavior is borrowed as
    /// a natural fault injection).
    #[tokio::test]
    async fn snapshot_surfaces_silent_vacuum_failure() {
        let db = Database::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("silent.db");
        let err = vault_snapshot(db.pool(), &dest).await.unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn restore_rejects_wrong_passphrase_and_non_sqlite_payload() {
        // Hand-build a backup that "decrypts fine but is not SQLite inside"
        // (an encrypted plaintext)
        let encrypted = encrypt_bytes(b"not a database", "pw", Some(fast_kdf())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.db");
        let err = restore_backup_bytes(&encrypted, "pw", &dest).unwrap_err();
        assert!(err.to_string().contains("not a SQLite database"));
        assert!(
            !dest.exists(),
            "failed restore must not leave a partial file"
        );

        let err = restore_backup_bytes(&encrypted, "wrong", &dest).unwrap_err();
        assert!(err.to_string().contains("Decryption failed"));
    }
}
