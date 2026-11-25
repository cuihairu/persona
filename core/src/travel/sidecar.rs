//! Sidecar path, encrypted wrapping, and atomic write: gzip + PERSENC1
//! (an independent travel passphrase, unrelated to the master password),
//! written crash-safely.

use crate::backup::file_crypto::{decrypt_bytes, encrypt_bytes, is_persona_encrypted, KdfParams};
use crate::backup::snapshot::{gzip_bytes, maybe_gunzip};
use crate::{PersonaError, PersonaResult};
use std::path::{Path, PathBuf};

use super::model::TravelPack;
use super::{FORMAT_NAME, FORMAT_VERSION, SIDECAR_FILENAME};

/// `<db dir>/travel.persenc`。
pub fn sidecar_path(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(SIDECAR_FILENAME)
}

/// Serialize -> gzip -> PERSENC1 (default 64 MiB Argon2id; the same
/// parameters as the backup chain, but an independent passphrase -- a
/// forgotten travel passphrase does not affect the main database and vice
/// versa). The plaintext JSON exists briefly in memory (the same exposure
/// as the backup chain's snapshot plaintext; see the limitations section of
/// the module docs).
pub(crate) fn seal_pack(
    pack: &TravelPack,
    passphrase: &str,
    kdf: Option<KdfParams>,
) -> PersonaResult<Vec<u8>> {
    let plaintext = serde_json::to_vec(pack)
        .map_err(|e| PersonaError::Validation(format!("pack serialization failed: {e}")))?;
    let gz = gzip_bytes(plaintext);
    encrypt_bytes(&gz, passphrase, kdf)
        .map_err(|e| PersonaError::CryptographicError(format!("travel pack encryption: {e}")))
}

/// Decrypt, unpack, and verify the format. A wrong passphrase (GCM
/// authentication failure) and a format mismatch are reported through
/// separate error branches.
pub(crate) fn open_pack(bytes: &[u8], passphrase: &str) -> PersonaResult<TravelPack> {
    if !is_persona_encrypted(bytes) {
        return Err(PersonaError::Validation(
            "travel sidecar is not a Persona encrypted file".to_string(),
        ));
    }
    let gz = decrypt_bytes(bytes, passphrase).map_err(|e| {
        PersonaError::AuthenticationFailed(format!(
            "travel passphrase is wrong or the sidecar is corrupted: {e}"
        ))
    })?;
    let plaintext = maybe_gunzip(&gz).map_err(|e| {
        PersonaError::Validation(format!("travel sidecar decompression failed: {e}"))
    })?;
    let pack: TravelPack = serde_json::from_slice(&plaintext).map_err(|e| {
        PersonaError::Validation(format!("travel sidecar is not a valid pack: {e}"))
    })?;
    if pack.format_name != FORMAT_NAME || pack.format_version != FORMAT_VERSION {
        return Err(PersonaError::Validation(format!(
            "unsupported travel sidecar format {} v{} (expected {FORMAT_NAME} v{FORMAT_VERSION})",
            pack.format_name, pack.format_version
        )));
    }
    Ok(pack)
}

/// Atomic sidecar write: write a `.tmp` file in the same directory, fsync,
/// then rename (crash-safe); mode 0600 on Unix (the most sensitive file at
/// the level of the main database).
pub(crate) fn write_sidecar_atomic(path: &Path, bytes: &[u8]) -> PersonaResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| PersonaError::ConfigurationError("sidecar path has no parent".into()))?;
    let tmp = parent.join(format!(".{}.tmp.{}", SIDECAR_FILENAME, std::process::id()));
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| PersonaError::Io(format!("failed to create sidecar tmp: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| PersonaError::Io(format!("failed to chmod sidecar: {e}")))?;
        }
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| PersonaError::Io(format!("failed to write sidecar: {e}")))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| PersonaError::Io(format!("failed to place sidecar: {e}")))?;
    Ok(())
}
