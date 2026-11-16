//! 交易模型：构建请求、签名交易/签名与方案、广播状态。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::network::BlockchainNetwork;

/// Transaction request for wallet signing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionRequest {
    /// Transaction ID
    pub id: Uuid,

    /// Wallet ID
    pub wallet_id: Uuid,

    /// Network
    pub network: BlockchainNetwork,

    /// From address
    pub from_address: String,

    /// To address
    pub to_address: String,

    /// Amount (in smallest unit - satoshis, wei, etc.)
    pub amount: String,

    /// Fee (in smallest unit)
    pub fee: String,

    /// Gas price or fee rate
    pub gas_price: Option<String>,

    /// Gas limit (for EVM chains)
    pub gas_limit: Option<u64>,

    /// Nonce (for EVM chains)
    pub nonce: Option<u64>,

    /// Memo or note
    pub memo: Option<String>,

    /// Raw transaction data
    pub raw_transaction_data: Option<Vec<u8>>,

    /// Required signatures
    pub required_signatures: usize,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Expiration timestamp
    pub expires_at: Option<DateTime<Utc>>,

    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Signed transaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedTransaction {
    /// Transaction ID
    pub id: Uuid,

    /// Original request
    pub request: TransactionRequest,

    /// Signature(s)
    pub signatures: Vec<TransactionSignature>,

    /// Raw signed transaction
    pub raw_signed_transaction: Vec<u8>,

    /// Transaction hash
    pub transaction_hash: String,

    /// Signed timestamp
    pub signed_at: DateTime<Utc>,

    /// Broadcasting status
    pub broadcast_status: BroadcastStatus,
}

/// Transaction signature
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionSignature {
    /// Signer address
    pub signer_address: String,

    /// Signature data
    pub signature: Vec<u8>,

    /// Public key
    pub public_key: Vec<u8>,

    /// Signature scheme
    pub signature_scheme: SignatureScheme,

    /// Signed timestamp
    pub signed_at: DateTime<Utc>,
}

/// Signature schemes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureScheme {
    /// ECDSA (secp256k1) - Bitcoin, Ethereum
    ECDSA,
    /// EdDSA (ed25519) - Solana, Ed25519
    EdDSA,
    /// Schnorr - Bitcoin Taproot
    Schnorr,
    /// BLS - Ethereum 2.0
    BLS,
}

/// Transaction broadcast status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BroadcastStatus {
    /// Not yet broadcast
    NotBroadcast,
    /// Broadcasting
    Broadcasting,
    /// Broadcast successful
    BroadcastSuccess {
        /// Transaction hash
        hash: String,
        /// Block height (if confirmed)
        block_height: Option<u64>,
        /// Confirmations count
        confirmations: u64,
        /// Confirmed timestamp
        confirmed_at: Option<DateTime<Utc>>,
    },
    /// Broadcast failed
    BroadcastFailed {
        /// Error message
        error: String,
        /// Retry count
        retry_count: u32,
    },
}
