//! sidecar 的路径、加密封装与原子落盘：gzip + PERSENC1（travel 独立
//! 口令，与主密码无关），crash-safe 写入。

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

/// 序列化 → gzip → PERSENC1（默认 64 MiB Argon2id；与备份链同款参数，
/// 但口令独立——travel 口令忘了不影响主库，反之亦然）。明文 JSON 在
/// 内存短暂存在（与备份链的快照明文同等暴露面，见模块注释限制节）。
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

/// 解密解包并校验 format。口令错（GCM 认证失败）与格式不符分路报错。
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

/// 原子写 sidecar：同目录 `.tmp` 写完 fsync 后 rename（crash-safe），
/// Unix 下 0600（主库同级的最高敏度文件）。
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
