//! Tauri wire 类型（LAY-020 拆分）：`AppState`、同步、账号、命令、审批与
//! `Serializable*` 序列化域各占一个子模块。
//!
//! 外部路径零改动：`crate::types::{...}`、`crate::types::X` 均经
//! `pub use` 保持原路径（lib.rs `pub mod types` 不变）。

pub mod account;
pub mod approvals;
pub mod commands;
pub mod serializers;
pub mod state;
pub mod sync;

pub use account::*;
pub use approvals::*;
pub use commands::*;
pub use serializers::*;
pub use state::*;
pub use sync::*;
