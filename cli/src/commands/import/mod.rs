//! Plain JSON / YAML / CSV 导入命令：文件校验 → 解密 → 解析 → 预览 →
//! 冲突检查 → 执行（备份、dry-run、merge/replace/skip 模式）。
//!
//! # 模块布局
//!
//! 类型（`ImportArgs` 与三个导入数据结构）留枢纽——私有字段被 flow /
//! display / formats 与测试共同读写；流程编排、格式解析、结果展示分居子模块。

use std::path::PathBuf;

use clap::Args;

mod display;
mod flow;
mod formats;

pub use flow::execute;

#[cfg(test)]
mod tests;

#[derive(Args, Clone)]
pub struct ImportArgs {
    /// Import file path
    file: PathBuf,

    /// Import mode (merge, replace, skip)
    #[arg(short, long, default_value = "merge")]
    mode: String,

    /// Dry run - show what would be imported without making changes
    #[arg(long)]
    dry_run: bool,

    /// Force import without confirmation
    #[arg(short, long)]
    force: bool,

    /// Backup existing data before import
    #[arg(short, long)]
    backup: bool,

    /// Decrypt imported data
    #[arg(long)]
    decrypt: bool,

    /// Interactive selection of identities to import
    #[arg(short, long)]
    interactive: bool,
}

#[derive(Debug, Clone)]
struct ImportData {
    version: String,
    created: String,
    identities: Vec<ImportIdentity>,
}

#[derive(Debug, Clone)]
struct ImportIdentity {
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug)]
struct ImportConflict {
    name: String,
    conflict_type: String,
    existing_data: String,
    new_data: String,
}
