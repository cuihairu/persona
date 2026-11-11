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

use super::ethereum::{chain_id, eip1559_tx, evm_tx_type, legacy_tx, EvmTxType};
use crate::models::wallet::{SignatureScheme, TransactionRequest, TransactionSignature};
use crate::{PersonaError, PersonaResult};
use alloy_consensus::SignableTransaction;
use alloy_primitives::B256;
use k256::ecdsa::{signature::DigestVerifier, RecoveryId, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Verify a transaction signature (Bitcoin audit signatures and generic
/// message signatures; Ethereum/Solana have dedicated verifiers).
pub fn verify_transaction_signature(
    signature: &TransactionSignature,
    message: &[u8],
) -> PersonaResult<bool> {
    match signature.signature_scheme {
        SignatureScheme::ECDSA => {
            verify_ecdsa_signature(&signature.public_key, &signature.signature, message)
        }
        SignatureScheme::EdDSA => {
            verify_ed25519_signature(&signature.public_key, &signature.signature, message)
        }
        _ => Err(PersonaError::InvalidInput(
            "Signature verification for this scheme".to_string(),
        )),
    }
}

/// Recompute the signing hash for `request` (legacy or typed) and check that
/// the signature recovers `signer_address`.
pub fn verify_ethereum_transaction(
    request: &TransactionRequest,
    signature: &TransactionSignature,
) -> PersonaResult<bool> {
    match evm_tx_type(request) {
        EvmTxType::Legacy => verify_ethereum_legacy(request, signature),
        EvmTxType::Eip1559 => verify_ethereum_typed(request, signature),
    }
}

pub(super) fn verify_ethereum_legacy(
    request: &TransactionRequest,
    signature: &TransactionSignature,
) -> PersonaResult<bool> {
    let chain = chain_id(request)?;
    let prehash: B256 = legacy_tx(request)?.signature_hash();
    if signature.signature.len() < 65 {
        return Ok(false);
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&signature.signature[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature.signature[32..64]);
    // EIP-155 v encodes the chain id and parity
    let v = decode_varuint(&signature.signature[64..])
        .ok_or_else(|| PersonaError::InvalidInput("Invalid Ethereum signature v".to_string()))?;
    if v < 35 || (v - 35) < 2 * chain {
        return Ok(false);
    }
    let y_odd = ((v - 35 - 2 * chain) & 1) == 1;

    let sig = Signature::from_scalars(r, s)
        .map_err(|_| PersonaError::InvalidInput("Invalid r/s in Ethereum signature".to_string()))?;
    let recovered =
        VerifyingKey::recover_from_prehash(&prehash.0, &sig, RecoveryId::new(y_odd, false))
            .map_err(|e| PersonaError::CryptographicError(e.to_string()))?;

    let recovered_address = address_from_verifying_key(&recovered)?;
    Ok(recovered_address == signature.signer_address.to_lowercase())
}

/// Typed-transaction verify: signature is `r || s || y_parity` (1 byte).
pub(super) fn verify_ethereum_typed(
    request: &TransactionRequest,
    signature: &TransactionSignature,
) -> PersonaResult<bool> {
    let prehash: B256 = eip1559_tx(request)?.signature_hash();
    if signature.signature.len() != 65 {
        return Ok(false);
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&signature.signature[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature.signature[32..64]);
    let y_odd = signature.signature[64] == 1;

    let sig = Signature::from_scalars(r, s)
        .map_err(|_| PersonaError::InvalidInput("Invalid r/s in Ethereum signature".to_string()))?;
    let recovered =
        VerifyingKey::recover_from_prehash(&prehash.0, &sig, RecoveryId::new(y_odd, false))
            .map_err(|e| PersonaError::CryptographicError(e.to_string()))?;

    let recovered_address = address_from_verifying_key(&recovered)?;
    Ok(recovered_address == signature.signer_address.to_lowercase())
}

/// Verify the Ed25519 signature over the Solana message.
pub fn verify_solana_transaction(
    signature: &TransactionSignature,
    message: &[u8],
) -> PersonaResult<bool> {
    verify_ed25519_signature(&signature.public_key, &signature.signature, message)
}

pub(super) fn address_from_verifying_key(key: &VerifyingKey) -> PersonaResult<String> {
    let encoded = key.to_sec1_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

/// Verify ECDSA (secp256k1) signature
pub(super) fn verify_ecdsa_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> PersonaResult<bool> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| PersonaError::CryptographicError(format!("Invalid public key: {}", e)))?;
    let signature = Signature::from_der(signature)
        .map_err(|e| PersonaError::CryptographicError(format!("Invalid signature: {}", e)))?;

    match verifying_key.verify_digest(
        |d: &mut Sha256| {
            d.update(message);
            Ok(())
        },
        &signature,
    ) {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::debug!(error = %e, "ECDSA signature verification failed");
            Ok(false)
        }
    }
}

/// Verify Ed25519 signature
pub(super) fn verify_ed25519_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> PersonaResult<bool> {
    use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey as Ed25519VerifyingKey};

    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        PersonaError::InvalidInput("Ed25519 public key must be 32 bytes".to_string())
    })?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_key)
        .map_err(|e| PersonaError::CryptographicError(format!("Invalid public key: {}", e)))?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| {
        PersonaError::InvalidInput("Ed25519 signature must be 64 bytes".to_string())
    })?;
    let signature = Ed25519Sig::from_bytes(&signature);

    match verifying_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub(super) fn decode_varuint(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut value: u64 = 0;
    for &b in bytes {
        value = (value << 8) | u64::from(b);
    }
    Some(value)
}
