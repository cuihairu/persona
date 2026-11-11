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
use crate::models::wallet::{SignatureScheme, TransactionRequest};
use crate::{PersonaError, PersonaResult};

/// Sign Solana transaction
pub(super) fn sign_solana_transaction(
    request: &TransactionRequest,
    private_key: &Ed25519Key,
) -> PersonaResult<(Vec<u8>, SignatureScheme)> {
    let message = solana_message(request)?;
    Ok((private_key.sign(&message).to_vec(), SignatureScheme::EdDSA))
}

/// The message that gets signed for Solana.
///
/// Solana transaction structure (recent blockhash, account order, compiled
/// instructions) must be assembled by the caller; Persona signs the exact
/// serialized message supplied via `raw_transaction_data`.
pub(super) fn solana_message(request: &TransactionRequest) -> PersonaResult<Vec<u8>> {
    request.raw_transaction_data.clone().ok_or_else(|| {
        PersonaError::InvalidInput(
            "Solana signing requires the serialized message in raw_transaction_data \
             (e.g. Transaction::serialize_message())"
                .to_string(),
        )
    })
}
