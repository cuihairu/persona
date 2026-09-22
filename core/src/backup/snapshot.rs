//! 备份链：VACUUM INTO 物理快照 → gzip → PERSENC1 加密；恢复反向。
//!
//! 恢复 = 解密 → 魔数自适应解压 → SQLite 头校验 → 写目标路径。免写
//! 逻辑导入代码：物理快照恢复即完整库（schema 迁移由恢复端首次打开时
//! 正常执行）。

use super::file_crypto::{decrypt_bytes, encrypt_bytes, KdfParams};
use anyhow::{anyhow, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::io::{Read, Write};
use std::path::Path;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// 一份加密备份（内存字节 + 元数据）。
pub struct BackupBlob {
    pub bytes: Vec<u8>,
    pub size_bytes: u64,
    /// 密文 hex 摘要（服务器去重键与下载复验键）。
    pub sha256: String,
}

/// 把库快照到 `dest`（VACUUM INTO：目标须不存在；产物自洽、无 WAL 依赖）。
///
/// 绑定参数优先；驱动拒绝时退回单引号转义的字面量（路径注入面靠
/// `''` 转义闭合）。不能在事务内执行（VACUUM 限制），调用方勿包事务。
///
/// 已知坑（2026-09 实测）：sqlx 0.8 对 `sqlite::memory:` 连接池上的
/// VACUUM INTO 返回 Ok 却不落盘（SQLite 本身与文件库路径均正常）——
/// 内存库不适用于备份链，生产路径 identities.db 恒为文件库；末尾的
/// 产物存在性校验就是防这类静默失败流出空备份。
pub async fn vault_snapshot(pool: &SqlitePool, dest: &Path) -> Result<()> {
    let dest_str = dest
        .to_str()
        .ok_or_else(|| anyhow!("snapshot path must be valid UTF-8"))?;
    if let Err(bind_error) = sqlx::query("VACUUM INTO ?1")
        .bind(dest_str)
        .execute(pool)
        .await
    {
        // 退路：转义字面量（SQLite 字符串字面量仅 ' 需转义为 ''）
        let escaped = dest_str.replace('\'', "''");
        sqlx::query(&format!("VACUUM INTO '{escaped}'"))
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

/// gzip 压缩（默认等级）。内存 `Vec` writer 的 `io::Error` 实际不可达。
pub fn gzip_bytes(data: Vec<u8>) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::with_capacity(data.len() / 2), Compression::default());
    encoder
        .write_all(&data)
        .and_then(|()| encoder.finish())
        .expect("in-memory gzip cannot fail")
}

/// 魔数自适应解压：`1f 8b`（gzip）则解压，否则原样返回（容忍未压缩
/// 的纯 SQLite 字节——如手工加密的旧导出文件）。
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

/// 创建加密备份：快照 → gzip → 加密 → sha256（一条链）。
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
    drop(dir); // 快照临时文件尽早清理

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

/// 从加密备份恢复：解密 → 自适应解压 → SQLite 头校验 → 写 `dest`。
///
/// 只产出文件、不打开库、不跑迁移——换库/重开的顺序编排归调用方
/// （CLI 先留 .bak 再换文件；桌面端有连接排空约束，见各自实现）。
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
        // 非 gzip 原样返回
        assert_eq!(maybe_gunzip(&raw).unwrap(), raw);
    }

    #[test]
    fn maybe_gunzip_reports_corrupt_stream() {
        let mut gz = gzip_bytes(b"payload".to_vec());
        gz.truncate(gz.len() - 4); // 截断破坏 CRC/长度
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

        // 快照是自洽 SQLite：重开后行还在
        let reopened = Database::from_file(&snapshot_path).await.unwrap();
        let repo2 = IdentityRepository::new(reopened.clone());
        let fetched = repo2.find_by_id(&created.id).await.unwrap();
        assert!(fetched.is_some(), "snapshot must preserve rows");

        // VACUUM INTO 不允许覆盖已存在的目标
        assert!(vault_snapshot(db.pool(), &snapshot_path).await.is_err());
    }

    #[tokio::test]
    async fn create_then_restore_round_trips_a_working_database() {
        // from_file 而非 in_memory：sqlx 对内存库的 VACUUM INTO 会静默
        // 无效果（见 vault_snapshot 注释），备份链只对文件库成立
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
        // 密文中找不到明文痕迹（名字不做加密，但整个快照是加密+gzip 的）
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

    /// sqlx 对 `:memory:` 池的 VACUUM INTO 会返回 Ok 但不落盘——产物
    /// 校验必须把这类静默失败转成显式错误（借该行为当天然故障注入）。
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
        // 手工构造一个"解密成功但内容不是 SQLite"的备份（加密纯文本）
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
