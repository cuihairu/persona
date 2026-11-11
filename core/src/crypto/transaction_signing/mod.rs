// Multi-chain transaction signing module.
//
// Protocol-level serialization, signing hashes and address parsing are
// delegated to the audited `alloy` (Ethereum) and `rust-bitcoin` (Bitcoin)
// crates; k256/ed25519-dalek remain the signing primitives.
//
// Implemented chains:
// - Ethereum & EVM L2s: legacy EIP-155 and typed EIP-1559 transactions
//   (`alloy_consensus`), producing broadcastable raw signed transactions.
// - Bitcoin: BIP-143 P2WPKH signing and segwit (BIP-141) transaction
//   assembly (`SighashCache` + consensus serialization) from
//   caller-provided UTXO `inputs` metadata; without them only an audit
//   signature over the request fields is recorded.
// - Solana: Ed25519 signing over a serialized message (e.g. the output of
//   `Transaction::serialize_message()`), producing a wire-format signed
//   transaction with a single signature.

use crate::crypto::wallet_crypto::Ed25519Key;
use crate::models::wallet::{
    BlockchainNetwork, SignatureScheme, TransactionRequest, TransactionSignature,
};
use crate::{PersonaError, PersonaResult};
use chrono::Utc;
use k256::ecdsa::SigningKey;
use sha2::Digest;
use sha3::Keccak256;

mod btc;
mod ethereum;
mod solana;
mod verify;

pub use btc::build_bitcoin_raw_transaction;
use btc::sign_bitcoin_transaction;
pub(crate) use btc::{build_p2wpkh_transaction, p2wpkh_output_script};
pub use ethereum::{build_eip1559_raw_transaction, build_eip155_raw_transaction};
use ethereum::{evm_tx_type, sign_ethereum_transaction, EvmTxType};
use solana::{sign_solana_transaction, solana_message};
pub use verify::{
    verify_ethereum_transaction, verify_solana_transaction, verify_transaction_signature,
};

// Add conversion from k256::ecdsa::Error to PersonaError
impl From<k256::ecdsa::Error> for PersonaError {
    fn from(err: k256::ecdsa::Error) -> Self {
        PersonaError::CryptographicError(err.to_string())
    }
}

/// The signing key material for a wallet, matched to the chain's curve.
#[derive(Clone)]
pub enum WalletSigningKey {
    /// secp256k1 key (Bitcoin, Ethereum and other EVM chains)
    Secp256k1(SigningKey),
    /// Ed25519 key (Solana)
    Ed25519(Ed25519Key),
}

/// Compressed 33-byte secp256k1 public key of a signing key.
pub(super) fn secp_compressed_pubkey(signing_key: &SigningKey) -> [u8; 33] {
    let encoded = signing_key.verifying_key().to_sec1_point(true);
    encoded
        .as_bytes()
        .try_into()
        .expect("33-byte compressed key")
}

/// A fully built, broadcastable transaction.
#[derive(Debug, Clone)]
pub struct RawSignedTransaction {
    /// Wire-format signed transaction, ready for broadcast.
    pub raw: Vec<u8>,
    /// Transaction hash/identifier as displayed by explorers.
    pub hash: String,
}

/// Sign a transaction using the scheme required by the network.
pub fn sign_transaction(
    request: &TransactionRequest,
    key: &WalletSigningKey,
) -> PersonaResult<TransactionSignature> {
    let signer_address = request.from_address.clone();
    let signed_at = Utc::now();

    match (&request.network, key) {
        (BlockchainNetwork::Bitcoin, WalletSigningKey::Secp256k1(k)) => {
            let (signature, scheme) = sign_bitcoin_transaction(request, k)?;
            Ok(signature_for(
                &signer_address,
                signature,
                secp_compressed_pubkey(k).to_vec(),
                scheme,
                signed_at,
            ))
        }
        (
            BlockchainNetwork::Ethereum
            | BlockchainNetwork::Polygon
            | BlockchainNetwork::Arbitrum
            | BlockchainNetwork::Optimism
            | BlockchainNetwork::BinanceSmartChain,
            WalletSigningKey::Secp256k1(k),
        ) => {
            let (signature, scheme) = sign_ethereum_transaction(request, k)?;
            Ok(signature_for(
                &signer_address,
                signature,
                secp_compressed_pubkey(k).to_vec(),
                scheme,
                signed_at,
            ))
        }
        (BlockchainNetwork::Solana, WalletSigningKey::Ed25519(k)) => {
            let (signature, scheme) = sign_solana_transaction(request, k)?;
            Ok(signature_for(
                &signer_address,
                signature,
                k.public_bytes().to_vec(),
                scheme,
                signed_at,
            ))
        }
        (network, _) => Err(PersonaError::InvalidInput(format!(
            "No matching signing key curve for {:?} (or network is unsupported)",
            network
        ))),
    }
}

fn signature_for(
    signer_address: &str,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    signature_scheme: SignatureScheme,
    signed_at: chrono::DateTime<Utc>,
) -> TransactionSignature {
    TransactionSignature {
        signer_address: signer_address.to_string(),
        signature,
        public_key,
        signature_scheme,
        signed_at,
    }
}

/// Sign the transaction and build the chain-specific raw transaction.
pub fn build_raw_transaction(
    request: &TransactionRequest,
    key: &WalletSigningKey,
) -> PersonaResult<RawSignedTransaction> {
    match &request.network {
        BlockchainNetwork::Bitcoin => {
            let WalletSigningKey::Secp256k1(k) = key else {
                return Err(PersonaError::InvalidInput(
                    "Bitcoin requires a secp256k1 key".to_string(),
                ));
            };
            build_bitcoin_raw_transaction(request, k)
        }
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => {
            let WalletSigningKey::Secp256k1(k) = key else {
                return Err(PersonaError::InvalidInput(
                    "Ethereum requires a secp256k1 key".to_string(),
                ));
            };
            let raw = match evm_tx_type(request) {
                EvmTxType::Legacy => build_eip155_raw_transaction(request, k)?,
                EvmTxType::Eip1559 => build_eip1559_raw_transaction(request, k)?,
            };
            let hash = Keccak256::digest(&raw);
            Ok(RawSignedTransaction {
                raw,
                hash: format!("0x{}", hex::encode(hash)),
            })
        }
        BlockchainNetwork::Solana => {
            let WalletSigningKey::Ed25519(k) = key else {
                return Err(PersonaError::InvalidInput(
                    "Solana requires an Ed25519 key".to_string(),
                ));
            };
            let message = solana_message(request)?;
            let signature = k.sign(&message);
            // Solana wire format: compact-u16 signature count, then the
            // signatures, then the message.
            let mut raw = Vec::with_capacity(1 + 64 + message.len());
            raw.push(1); // one signature
            raw.extend_from_slice(&signature);
            raw.extend_from_slice(&message);
            Ok(RawSignedTransaction {
                raw,
                hash: bs58::encode(signature).into_string(),
            })
        }
        network => Err(PersonaError::InvalidInput(format!(
            "Raw transaction assembly is not supported for {:?}",
            network
        ))),
    }
}

#[cfg(test)]
mod tests;
