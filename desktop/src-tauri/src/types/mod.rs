//! Tauri wire types (LAY-020 split): `AppState`, sync, account, commands,
//! approvals and the `Serializable*` serialization domain each live in their
//! own submodule.
//!
//! External paths are untouched: `crate::types::{...}` and `crate::types::X`
//! keep their original paths via `pub use` (lib.rs `pub mod types` unchanged).

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
