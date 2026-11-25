//! Wallet encryption: private key / mnemonic wrapping (`model.rs`) and
//! Web3 Secret Storage v3 keystore import/export (`keystore.rs`).

mod keystore;
mod model;

pub use keystore::*;
pub use model::*;

#[cfg(test)]
mod tests;
