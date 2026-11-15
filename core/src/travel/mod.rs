//! Travel Mode（旅行模式）：把被标记身份的数据整包移出本设备，退出时
//! 原样恢复（1Password「remove vaults from devices」语义）。
//!
//! # 数据流
//!
//! enter：读被标记身份的全部行（12 张表）+ 附件 blob 文件字节（磁盘密封
//! 态，不解密）→ `TravelPack` 序列化 → gzip → PERSENC1 加密（独立 travel
//! 口令，与主密码无关）→ 写 sidecar `<db dir>/travel.persenc` → 单事务
//! 从主库删除（先剥离 audit_logs 的 FK 引用）。主库零痕迹（连名字都没有）；
//! 主密码打不开 sidecar。
//!
//! exit：读 sidecar → 解密解包（校验 format）→ 单事务 `INSERT OR REPLACE`
//! 恢复（父表在前）+ settings 复位 → 重写 blob 文件 → 删 sidecar。
//! 行 id、加密形态（`wrapped_item_key`/`encrypted_data` 字节）不变——
//! per-item key 由主密钥包裹，主密码未变则恢复后可解；也因此旅行模式
//! 期间拒绝改主密码（见 `PersonaService::change_master_password` 拦截）。
//!
//! # 崩溃窗口语义
//!
//! | 崩溃点 | 状态 | 恢复方式 |
//! |---|---|---|
//! | sidecar 已写、事务未提交 | sidecar 存在、`travel_mode=false`、行未删 | enter 拒绝（sidecar 已存在），提示删残留 sidecar 或直接 exit 恢复 |
//! | 事务已提交、blob 文件未删 | 行已删、文件残留 | exit 时按 storage_path 原路径覆写文件，自愈 |
//! | 用户手删 sidecar | `travel_mode=true` 且 sidecar 缺失 | `travel_status().inconsistent = true`——数据仅存于 sidecar，已丢失（诚实呈现，不假装可恢复） |
//!
//! # 已知限制
//!
//! - travel 口令忘了 = sidecar 不可解 = 数据只能靠 enter 之前的整库备份
//!   （备份是时间点快照，含当时仍在库内的被标记身份）。
//! - 本机攻击者可删除/替换 sidecar（拒绝服务）；替换者没有 travel 口令
//!   就构造不出能通过 GCM 认证的密文，注入不可行。
//! - audit_logs 不随行（只记 id 无明文，留作存证）；change_history 快照
//!   含明文元数据，随行。
//!
//! # 模块布局
//!
//! - `model`：pack / status / counts 类型与格式常量
//! - `codec`：SQLite 行 ↔ JSON 的值级编解码与白名单校验
//! - `pack`：跨库读取聚合（build_pack）
//! - `sidecar`：sidecar 路径与加密封装（seal / open / 原子落盘）
//! - `tx`：enter / exit 单事务（含 favicon 缓存清理与 settings 旗标）
//! - `blob`：附件文件的读写与路径逃逸防御

use sha2::{Digest, Sha256};

mod blob;
mod codec;
mod model;
mod pack;
mod sidecar;
mod tx;

pub(crate) use blob::{delete_blob_files, write_blob_files};
pub use model::{TravelBlobFile, TravelCounts, TravelPack, TravelStatus};
pub(crate) use pack::build_pack;
pub use sidecar::sidecar_path;
pub(crate) use sidecar::{open_pack, seal_pack, write_sidecar_atomic};
pub(crate) use tx::{apply_enter_tx, apply_exit_tx};

/// sidecar 文件名（放在库文件同目录）。
pub const SIDECAR_FILENAME: &str = "travel.persenc";

/// 格式名（open_pack 校验）。
pub const FORMAT_NAME: &str = "persona-travel-1";

/// 格式版本。
pub const FORMAT_VERSION: u32 = 1;

/// enter 时打包的表（恢复时按此顺序插回，父表在前——FK 依赖序）。
const PACKED_TABLES_IN_INSERT_ORDER: &[&str] = &[
    "identities",
    "credentials",
    "attachments",
    "attachment_chunks",
    "passkeys",
    "crypto_wallets",
    "wallet_addresses",
    "wallet_metadata",
    "transaction_requests",
    "signed_transactions",
    "workspace_members",
    "change_history",
];

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
use blob::write_blob_file;
#[cfg(test)]
use codec::{check_table_name, insert_rows, row_to_json};

#[cfg(test)]
mod tests;
