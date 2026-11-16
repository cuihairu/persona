//! 通用格式导入（FEATURE_GAP_ANALYSIS #20）：CSV + Bitwarden JSON 导出解析
//! 与导入规划。
//!
//! 覆盖主流明文导出形：
//! - **CSV**（按表头嗅探列角色）：Bitwarden CSV（含 `type` 列分流）、Chrome、
//!   Firefox、1Password CSV、KeePass 1.x/2.x CSV；
//! - **Bitwarden JSON**（`encrypted: false` 的明文导出；密码保护导出明确
//!   拒绝并指路）。
//!
//! 与 [`crate::import_1pux`] 同一条设计线：解析 → 纯函数规划出
//! [`ImportPlan`]，CLI/桌面先预览再确认后落库。CSV 导出没有容器概念，
//! 整个文件落进一个身份（`identity_name` 由调用方给定，通常是文件名 stem）；
//! Bitwarden 的 folder 映射为 persona 标签而非身份（folder 是库内轻量分组，
//! 不是 1Password vault 那种容器）。KeePass 走其 CSV 导出（KeePass →
//! Export → CSV），不直读 KDBX 加密容器——与 1PUX/maFile 一致的明文容器
//! 策略，避免引入 keepass-rs 重依赖。

use anyhow::Result;

use crate::import_1pux::ImportPlan;

mod bitwarden;
mod csv;
mod plan;
#[cfg(test)]
mod tests;

use bitwarden::{parse_bitwarden_json, plan_bitwarden};
pub use bitwarden::{BitwardenFolder, BitwardenItem};
use csv::{parse_csv, plan_csv};

/// 通用导入的唯一容器键：整个文件一个身份，凭据经它回链。
pub const GENERIC_VAULT_KEY: &str = "generic-import";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericExportFormat {
    /// 密码管理器 CSV 导出（表头嗅探列角色，映射见 csv.rs `map_roles`）
    Csv,
    /// Bitwarden 明文 JSON 导出（`encrypted: false`）
    BitwardenJson,
}

/// 解析产物：CSV 记录集或 Bitwarden JSON 导出。
#[derive(Debug, Clone)]
pub enum GenericExport {
    Csv(CsvExport),
    BitwardenJson(BitwardenExport),
}

/// CSV 导出：表头 + 数据行（列与表头按位对齐，缺列由 `flexible` 容忍）。
#[derive(Debug, Clone)]
pub struct CsvExport {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// Bitwarden 明文 JSON 导出。
#[derive(Debug, Clone)]
pub struct BitwardenExport {
    pub folders: Vec<BitwardenFolder>,
    pub items: Vec<BitwardenItem>,
}

/// 自动嗅探格式：剥掉 UTF-8 BOM 后，`{`/`[` 开头当 JSON，否则当 CSV。
/// 扩展名不可靠（用户常改名），按内容判断。
pub fn detect_format(bytes: &[u8]) -> GenericExportFormat {
    let head = String::from_utf8_lossy(strip_utf8_bom(bytes));
    match head.trim_start().starts_with('{') || head.trim_start().starts_with('[') {
        true => GenericExportFormat::BitwardenJson,
        false => GenericExportFormat::Csv,
    }
}

/// 解析通用导出文件。`format` 传 `None` 时自动嗅探。
pub fn parse_generic(bytes: &[u8], format: Option<GenericExportFormat>) -> Result<GenericExport> {
    match format.unwrap_or_else(|| detect_format(bytes)) {
        GenericExportFormat::Csv => parse_csv(bytes).map(GenericExport::Csv),
        GenericExportFormat::BitwardenJson => {
            parse_bitwarden_json(bytes).map(GenericExport::BitwardenJson)
        }
    }
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_prefix([0xEF, 0xBB, 0xBF].as_slice())
        .unwrap_or(bytes)
}

/// 把通用导出映射成 [`ImportPlan`]：整个文件落进一个身份（`identity_name`，
/// 描述里记录 `source_label` 便于溯源）。纯函数、无 IO。
pub fn plan_generic_import(
    export: &GenericExport,
    identity_name: &str,
    source_label: &str,
) -> ImportPlan {
    match export {
        GenericExport::Csv(csv) => plan_csv(csv, identity_name, source_label),
        GenericExport::BitwardenJson(bw) => plan_bitwarden(bw, identity_name, source_label),
    }
}
