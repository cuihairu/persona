//! Attachment blob file protection: storage_path escape defense, sealed
//! raw-byte read/write, and sha256 integrity checks.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::path::{Component, Path};

use super::model::TravelBlobFile;
use super::sha256_hex;
use crate::{PersonaError, PersonaResult};

/// Read an attachment file (sealed raw bytes). Guards against storage_path
/// escapes (defense against historical dirty data).
pub(super) fn read_blob_file(root: &Path, storage_path: &str) -> PersonaResult<Vec<u8>> {
    let relative = Path::new(storage_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(PersonaError::Validation(format!(
            "attachment storage_path escapes storage root: {storage_path}"
        )));
    }
    std::fs::read(root.join(relative))
        .map_err(|e| PersonaError::Io(format!("failed to read attachment {storage_path}: {e}")))
}

/// Write an attachment file (sealed raw bytes; the parent directory is
/// created on demand during exit).
pub(super) fn write_blob_file(root: &Path, storage_path: &str, bytes: &[u8]) -> PersonaResult<()> {
    let relative = Path::new(storage_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(PersonaError::Validation(format!(
            "attachment storage_path escapes storage root: {storage_path}"
        )));
    }
    let target = root.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            PersonaError::Io(format!(
                "failed to create attachment dir {}: {e}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(&target, bytes).map_err(|e| {
        PersonaError::Io(format!(
            "failed to write attachment {}: {e}",
            target.display()
        ))
    })
}

/// Delete the attachment blob files of the removed identities (best-effort
/// after the enter transaction commits: failures are logged as warnings and
/// returned in the list -- exit self-heals by overwriting via storage_path).
pub(crate) fn delete_blob_files(root: &Path, files: &[TravelBlobFile]) -> Vec<String> {
    let mut failures = Vec::new();
    for file in files {
        let relative = Path::new(&file.storage_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            failures.push(format!("{} (path escapes root)", file.storage_path));
            continue;
        }
        match std::fs::remove_file(root.join(relative)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    "travel enter: failed to remove attachment {}: {e}",
                    file.storage_path
                );
                failures.push(file.storage_path.clone());
            }
        }
    }
    failures
}

/// Rewrite the attachment blob files (after the exit transaction commits;
/// the rows are restored by then, so a failure here can simply retry the
/// whole thing -- both INSERT OR REPLACE and the file overwrite are
/// idempotent). The path-escape check runs before the content check: a bad
/// path is rejected outright without wasting decode and hashing work.
pub(crate) fn write_blob_files(root: &Path, files: &[TravelBlobFile]) -> PersonaResult<()> {
    for file in files {
        let relative = Path::new(&file.storage_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(PersonaError::Validation(format!(
                "attachment storage_path escapes storage root: {}",
                file.storage_path
            )));
        }
        let bytes = BASE64.decode(&file.data_b64).map_err(|e| {
            PersonaError::Validation(format!("attachment {}: bad base64: {e}", file.storage_path))
        })?;
        let actual = sha256_hex(&bytes);
        if actual != file.sha256 {
            return Err(PersonaError::Validation(format!(
                "attachment {}: integrity check failed (expected {}, got {})",
                file.storage_path, file.sha256, actual
            )));
        }
        write_blob_file(root, &file.storage_path, &bytes)?;
    }
    Ok(())
}
