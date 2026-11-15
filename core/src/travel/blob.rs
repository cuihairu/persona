//! 附件 blob 文件保护：storage_path 路径逃逸防御、密封态原字节读写
//! 与 sha256 完整性校验。

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::path::{Component, Path};

use super::model::TravelBlobFile;
use super::sha256_hex;
use crate::{PersonaError, PersonaResult};

/// 读附件文件（密封态原字节）。storage_path 防逃逸（历史脏数据防御）。
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

/// 写附件文件（密封态原字节；exit 时父目录按需创建）。
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

/// 删除被移除身份的附件 blob 文件（enter 事务提交后 best-effort：
/// 失败项 warn 并计入返回清单——exit 会按 storage_path 覆写自愈）。
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

/// 重写附件 blob 文件（exit 事务提交后；行已恢复，此步失败可整条重试，
/// INSERT OR REPLACE 与文件覆写均幂等）。路径逃逸校验先于内容校验：
/// 坏路径直接拒绝，不浪费解码与哈希。
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
