//! 整库加密备份（同步第一阶段客户端侧）。
//!
//! 备份链 = VACUUM INTO 物理快照 → gzip → PERSENC1 加密：
//! - 物理快照零信息丢失（users 验证子、wrapped_item_key、passkeys 私钥、
//!   change_history、审计全在），无需解锁主密码——文件级操作；
//! - 字节流恒先 gzip 后加密（密文不可压）；
//! - PERSENC1 与 CLI `--encrypt` 导出格式字节级互解（见 [`file_crypto`]）。
//!
//! 服务器（persona-server `/api/v1/backups`）只见密文与元数据；附件
//! blob 不在 v1 备份内（恢复后附件元数据在、文件体缺失）。

pub mod client;
pub mod file_crypto;
pub mod snapshot;

pub use client::{BackupClient, BackupMeta, BackupPage, DownloadedBackup, PushResult};
pub use file_crypto::{decrypt_bytes, encrypt_bytes, is_persona_encrypted, KdfParams};
pub use snapshot::{create_backup_bytes, restore_backup_bytes, BackupBlob};
