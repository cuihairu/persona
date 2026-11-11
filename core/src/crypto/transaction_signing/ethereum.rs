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

use crate::models::wallet::{BlockchainNetwork, SignatureScheme, TransactionRequest};
use crate::{PersonaError, PersonaResult};
use alloy_consensus::{SignableTransaction, Signed, TxEip1559, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    Address as EvmAddress, Signature as EvmSignature, TxKind, B256, U256 as EvmU256,
};
use k256::ecdsa::{
    signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey, VerifyingKey,
};

/// Sign an Ethereum transaction (EIP-155 legacy or EIP-1559 dynamic fee).
///
/// Legacy returns `r || s || v` with `v = 35 + 2*chain_id + recovery_id`;
/// typed (1559) transactions return `r || s || y_parity`.
pub(super) fn sign_ethereum_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<(Vec<u8>, SignatureScheme)> {
    let mut eth_signature = Vec::with_capacity(65);
    match evm_tx_type(request) {
        EvmTxType::Legacy => {
            let (r, s, v) = sign_eip155(request, signing_key)?;
            eth_signature.extend_from_slice(&r);
            eth_signature.extend_from_slice(&s);
            eth_signature.extend_from_slice(&minimal_be_bytes(v));
        }
        EvmTxType::Eip1559 => {
            let signing_hash: B256 = eip1559_tx(request)?.signature_hash();
            let signature: Signature = signing_key.sign_prehash(&signing_hash.0)?;
            let y_parity = recovery_id_for(signing_key, &signing_hash.0, &signature)?;
            eth_signature.extend_from_slice(&signature.r().to_bytes());
            eth_signature.extend_from_slice(&signature.s().to_bytes());
            eth_signature.push(y_parity);
        }
    }
    Ok((eth_signature, SignatureScheme::ECDSA))
}

/// Minimal big-endian encoding of an unsigned integer (0 -> empty),
/// used for the EIP-155 `v` byte in stored audit signatures.
pub(super) fn minimal_be_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let be = value.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[first..].to_vec()
}

/// EVM transaction type selected from request metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EvmTxType {
    /// EIP-155 legacy (`gas_price`), type prefix absent.
    Legacy,
    /// EIP-1559 dynamic fee (`max_fee_per_gas` / `max_priority_fee_per_gas`),
    /// serialized with the `0x02` type byte.
    Eip1559,
}

/// Decide the EVM transaction type from metadata. A transaction specifying
/// 1559 fee fields (or an explicit `tx_type`) is treated as 1559; everything
/// else stays legacy.
pub(super) fn evm_tx_type(request: &TransactionRequest) -> EvmTxType {
    let meta = &request.metadata;
    let explicit = meta
        .get("tx_type")
        .map(|t| t.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if explicit == "eip1559" || explicit == "2" || explicit == "type2" {
        return EvmTxType::Eip1559;
    }
    if meta.contains_key("max_fee_per_gas") || meta.contains_key("max_priority_fee_per_gas") {
        return EvmTxType::Eip1559;
    }
    EvmTxType::Legacy
}

pub(super) fn metadata_u128(
    request: &TransactionRequest,
    key: &str,
) -> PersonaResult<Option<u128>> {
    match request.metadata.get(key) {
        None => Ok(None),
        Some(v) => v.trim().parse::<u128>().map(Some).map_err(|_| {
            PersonaError::InvalidInput(format!("metadata '{key}' must be a decimal integer"))
        }),
    }
}

/// Access list is accepted as empty; a non-empty `access_list` in metadata is
/// rejected so callers never get a signature over semantics Persona ignored.
pub(super) fn access_list_guard(request: &TransactionRequest) -> PersonaResult<()> {
    match request.metadata.get("access_list") {
        None => Ok(()),
        Some(v) if v.trim().is_empty() || v.trim() == "[]" => Ok(()),
        Some(_) => Err(PersonaError::InvalidInput(
            "Non-empty access lists are not supported yet".to_string(),
        )),
    }
}

pub(super) fn evm_to_address(request: &TransactionRequest) -> PersonaResult<EvmAddress> {
    request
        .to_address
        .parse::<EvmAddress>()
        .map_err(|_| PersonaError::InvalidInput("Invalid Ethereum to_address".to_string()))
}

/// Full-range wei value (no longer capped at u128).
pub(super) fn evm_value(request: &TransactionRequest) -> PersonaResult<EvmU256> {
    EvmU256::from_str_radix(request.amount.trim(), 10)
        .map_err(|_| PersonaError::InvalidInput(format!("Invalid wei amount '{}'", request.amount)))
}

pub(super) fn evm_input(request: &TransactionRequest) -> PersonaResult<alloy_primitives::Bytes> {
    match request.metadata.get("data") {
        Some(hex_data) => hex::decode(hex_data.trim_start_matches("0x"))
            .map(Into::into)
            .map_err(|_| PersonaError::InvalidInput("metadata 'data' must be hex".to_string())),
        None => Ok(Default::default()),
    }
}

/// EIP-155 legacy transaction fields, built by `alloy_consensus`.
pub(super) fn legacy_tx(request: &TransactionRequest) -> PersonaResult<TxLegacy> {
    let nonce = request.nonce.ok_or_else(|| {
        PersonaError::InvalidInput("Ethereum transactions require a nonce".to_string())
    })?;
    let gas_price = request
        .gas_price
        .as_deref()
        .and_then(|g| g.parse::<u128>().ok())
        .ok_or_else(|| {
            PersonaError::InvalidInput(
                "Ethereum transactions require a numeric gas_price".to_string(),
            )
        })?;
    let gas_limit = request.gas_limit.ok_or_else(|| {
        PersonaError::InvalidInput("Ethereum transactions require a gas_limit".to_string())
    })?;
    Ok(TxLegacy {
        chain_id: Some(chain_id(request)?),
        nonce,
        gas_price,
        gas_limit,
        to: TxKind::Call(evm_to_address(request)?),
        value: evm_value(request)?,
        input: evm_input(request)?,
    })
}

/// EIP-1559 typed transaction fields, built by `alloy_consensus`.
pub(super) fn eip1559_tx(request: &TransactionRequest) -> PersonaResult<TxEip1559> {
    let nonce = request.nonce.ok_or_else(|| {
        PersonaError::InvalidInput("Ethereum transactions require a nonce".to_string())
    })?;
    let gas_limit = request.gas_limit.ok_or_else(|| {
        PersonaError::InvalidInput("Ethereum transactions require a gas_limit".to_string())
    })?;
    let max_priority = metadata_u128(request, "max_priority_fee_per_gas")?.unwrap_or(0);
    let max_fee = metadata_u128(request, "max_fee_per_gas")?.unwrap_or(0);
    if max_fee == 0 {
        return Err(PersonaError::InvalidInput(
            "EIP-1559 transactions require metadata 'max_fee_per_gas'".to_string(),
        ));
    }
    if max_priority > max_fee {
        return Err(PersonaError::InvalidInput(
            "max_priority_fee_per_gas must not exceed max_fee_per_gas".to_string(),
        ));
    }
    Ok(TxEip1559 {
        chain_id: chain_id(request)?,
        nonce,
        gas_limit,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: max_priority,
        to: TxKind::Call(evm_to_address(request)?),
        value: evm_value(request)?,
        access_list: Default::default(),
        input: evm_input(request)?,
    })
}

/// Build the full broadcastable EIP-1559 transaction:
/// `0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data,
/// accessList, yParity, r, s])`.
pub fn build_eip1559_raw_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<Vec<u8>> {
    access_list_guard(request)?;
    let tx = eip1559_tx(request)?;
    let signed = sign_alloy_transaction(tx, signing_key)?;
    Ok(signed.encoded_2718())
}

/// Sign a transaction's signing hash with k256 and wrap the resulting
/// (r, s, y-parity) into alloy's signature for encoding.
pub(super) fn sign_alloy_transaction<T>(
    tx: T,
    signing_key: &SigningKey,
) -> PersonaResult<Signed<T, EvmSignature>>
where
    T: SignableTransaction<EvmSignature>,
{
    let signing_hash: B256 = tx.signature_hash();
    let signature: Signature = signing_key.sign_prehash(&signing_hash.0)?;
    let y_parity = recovery_id_for(signing_key, &signing_hash.0, &signature)?;

    let mut r = [0u8; 32];
    r.copy_from_slice(&signature.r().to_bytes());
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature.s().to_bytes());
    let evm_signature = EvmSignature::new(
        EvmU256::from_be_bytes(r),
        EvmU256::from_be_bytes(s),
        y_parity == 1,
    );

    Ok(tx.into_signed(evm_signature))
}

/// EIP-155 chain id for the network.
pub(super) fn chain_id(request: &TransactionRequest) -> PersonaResult<u64> {
    match &request.network {
        BlockchainNetwork::Ethereum => Ok(1),
        BlockchainNetwork::Optimism => Ok(10),
        BlockchainNetwork::Polygon => Ok(137),
        BlockchainNetwork::Arbitrum => Ok(42161),
        BlockchainNetwork::BinanceSmartChain => Ok(56),
        BlockchainNetwork::Custom(_) => request
            .metadata
            .get("chain_id")
            .and_then(|id| id.parse::<u64>().ok())
            .ok_or_else(|| {
                PersonaError::InvalidInput(
                    "Custom EVM networks require a chain_id in metadata".to_string(),
                )
            }),
        network => Err(PersonaError::InvalidInput(format!(
            "{:?} is not an EVM network",
            network
        ))),
    }
}

/// Sign the EIP-155 signing hash, returning `(r, s, v)` with the EIP-155 `v`.
pub(super) fn sign_eip155(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<([u8; 32], [u8; 32], u64)> {
    let chain = chain_id(request)?;
    let signing_hash: B256 = legacy_tx(request)?.signature_hash();

    // Per EIP-155 the message to sign is the keccak hash of the RLP payload;
    // sign it directly rather than hashing again.
    let signature: Signature = signing_key.sign_prehash(&signing_hash.0)?;

    // k256 normalizes to low-s; recover the parity bit that reproduces our
    // public key so the signature validates against from_address.
    let recovery_id = recovery_id_for(signing_key, &signing_hash.0, &signature)?;

    let mut r = [0u8; 32];
    r.copy_from_slice(&signature.r().to_bytes());
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature.s().to_bytes());
    let v = 35 + 2 * chain + u64::from(recovery_id);

    Ok((r, s, v))
}

/// Build the full broadcastable EIP-155 transaction:
/// `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`.
pub fn build_eip155_raw_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<Vec<u8>> {
    build_eip155_raw_transaction_with(request, signing_key)
}

pub(super) fn build_eip155_raw_transaction_with(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<Vec<u8>> {
    let tx = legacy_tx(request)?;
    let (r, s, v) = sign_eip155(request, signing_key)?;
    let chain = chain_id(request)?;
    let y_odd = ((v - 35 - 2 * chain) & 1) == 1;

    let signed = tx.into_signed(EvmSignature::new(
        EvmU256::from_be_bytes(r),
        EvmU256::from_be_bytes(s),
        y_odd,
    ));
    Ok(signed.encoded_2718())
}

/// Recover the y-parity bit of the signature that reproduces the signer.
pub(super) fn recovery_id_for(
    signing_key: &SigningKey,
    prehash: &[u8; 32],
    signature: &Signature,
) -> PersonaResult<u8> {
    let expected = signing_key.verifying_key();
    for y_odd in [false, true] {
        if let Ok(recovered) =
            VerifyingKey::recover_from_prehash(prehash, signature, RecoveryId::new(y_odd, false))
        {
            if recovered == *expected {
                return Ok(u8::from(y_odd));
            }
        }
    }
    Err(PersonaError::CryptographicError(
        "Failed to recover signer from Ethereum signature".to_string(),
    ))
}
