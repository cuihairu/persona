//!
//! 拆分（LAY-022）：钱包查询见 `query.rs`，写入见 `write.rs`，
//! 地址维护见 `address.rs`，交易域见 `transaction.rs`；测试按域分在 `tests/`。
use crate::models::wallet::{
    BlockchainNetwork, CryptoWallet, SignedTransaction, TransactionRequest, WalletAddress,
    WalletMetadata, WalletSecurityLevel,
};
use crate::storage::Database;
use crate::{PersonaError, PersonaResult};
use chrono::{DateTime, TimeZone, Utc};
use serde_json;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

/// Convert a stored Unix timestamp to DateTime<Utc>. Out-of-range values
/// (corrupt or truncated DB rows) surface as a Database error instead of
/// panicking the caller's recovery path — the same tolerance passkey rows
/// already have.
fn timestamp_to_datetime(ts: i64) -> PersonaResult<DateTime<Utc>> {
    Utc.timestamp_opt(ts, 0)
        .single()
        .ok_or_else(|| PersonaError::Database(format!("invalid stored timestamp: {ts}")))
}

/// Repository for managing crypto wallets
pub struct CryptoWalletRepository {
    db: Arc<Database>,
}

/// Wallet transaction statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletTransactionStats {
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub total_amount_sent: f64,
}
impl CryptoWalletRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

mod address;
mod query;
#[cfg(test)]
mod tests;
mod transaction;
mod write;
