//! 钱包加密：私钥/助记词封装（`model.rs`）与 Web3 Secret Storage v3
//! keystore 导入导出（`keystore.rs`）。

mod keystore;
mod model;

pub use keystore::*;
pub use model::*;

#[cfg(test)]
mod tests;
