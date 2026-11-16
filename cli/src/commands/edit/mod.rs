//! 身份编辑命令：加载 → 展示现值 → 交互/单字段/参数三种编辑路径 →
//! 校验 → 确认 → 保存。
//!
//! # 模块布局
//!
//! 类型（`EditArgs` 与编辑快照 `Identity`）留枢纽——私有字段被所有子模块
//! 与测试共同读写；流程编排、字段编辑、自定义属性、展示、持久化分居子模块。

use clap::Args;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

mod attributes;
mod display;
mod fields;
mod flow;
mod persist;

pub use flow::execute;

#[cfg(test)]
mod tests;

#[derive(Args)]
pub struct EditArgs {
    /// Identity name to edit
    name: String,

    /// New identity type
    #[arg(long)]
    identity_type: Option<String>,

    /// New description
    #[arg(long)]
    description: Option<String>,

    /// New email address
    #[arg(long)]
    email: Option<String>,

    /// New phone number
    #[arg(long)]
    phone: Option<String>,

    /// Interactive editing mode
    #[arg(short, long)]
    interactive: bool,

    /// Edit specific field only
    #[arg(long)]
    field: Option<String>,

    /// New value for the field
    #[arg(long)]
    value: Option<String>,
}

#[derive(Debug, Clone)]
struct Identity {
    id: Option<Uuid>,
    name: String,
    identity_type: String,
    description: String,
    email: Option<String>,
    phone: Option<String>,
    tags: Vec<String>,
    attributes: HashMap<String, Value>,
    modified: String,
}
