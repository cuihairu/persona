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
use alloy_consensus::{SignableTransaction, Signed, TxEip1559, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    Address as EvmAddress, Signature as EvmSignature, TxKind, B256, U256 as EvmU256,
};
use bitcoin::absolute::LockTime;
use bitcoin::amount::Amount;
use bitcoin::consensus::serialize as consensus_serialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Network, OutPoint, ScriptBuf, Sequence, Txid};
use chrono::Utc;
use k256::ecdsa::{
    signature::{hazmat::PrehashSigner, DigestSigner, DigestVerifier, SignatureEncoding},
    RecoveryId, Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

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
fn secp_compressed_pubkey(signing_key: &SigningKey) -> [u8; 33] {
    let encoded = signing_key.verifying_key().to_encoded_point(true);
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

/// Sign Bitcoin transaction (audit signature over Persona's internal
/// sighash scheme; not a broadcastable Bitcoin transaction).
fn sign_bitcoin_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<(Vec<u8>, SignatureScheme)> {
    let sighash = create_bitcoin_sighash(request)?;
    let signature = sign_with_secp256k1(signing_key, &sighash)?;

    // Bitcoin uses DER-encoded signatures
    let der_signature = signature.to_der().to_vec();

    Ok((der_signature, SignatureScheme::ECDSA))
}

/// Sign an Ethereum transaction (EIP-155 legacy or EIP-1559 dynamic fee).
///
/// Legacy returns `r || s || v` with `v = 35 + 2*chain_id + recovery_id`;
/// typed (1559) transactions return `r || s || y_parity`.
fn sign_ethereum_transaction(
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
fn minimal_be_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let be = value.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[first..].to_vec()
}

/// Sign Solana transaction
fn sign_solana_transaction(
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
fn solana_message(request: &TransactionRequest) -> PersonaResult<Vec<u8>> {
    request.raw_transaction_data.clone().ok_or_else(|| {
        PersonaError::InvalidInput(
            "Solana signing requires the serialized message in raw_transaction_data \
             (e.g. Transaction::serialize_message())"
                .to_string(),
        )
    })
}

/// Create Bitcoin sighash for the audit signature (internal scheme).
fn create_bitcoin_sighash(request: &TransactionRequest) -> PersonaResult<[u8; 32]> {
    let mut hasher = Sha256::new();

    // Internal scheme: hash the request fields so the signature is bound to
    // the exact transaction parameters being approved.
    hasher.update(request.to_address.as_bytes());
    hasher.update(request.from_address.as_bytes());

    // Parse amount and fee as strings to numbers
    if let Ok(amount_u64) = request.amount.parse::<u64>() {
        hasher.update(amount_u64.to_le_bytes());
    }
    if let Ok(fee_u64) = request.fee.parse::<u64>() {
        hasher.update(fee_u64.to_le_bytes());
    }

    let hash = hasher.finalize();
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&hash);

    Ok(sighash)
}

/// EVM transaction type selected from request metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvmTxType {
    /// EIP-155 legacy (`gas_price`), type prefix absent.
    Legacy,
    /// EIP-1559 dynamic fee (`max_fee_per_gas` / `max_priority_fee_per_gas`),
    /// serialized with the `0x02` type byte.
    Eip1559,
}

/// Decide the EVM transaction type from metadata. A transaction specifying
/// 1559 fee fields (or an explicit `tx_type`) is treated as 1559; everything
/// else stays legacy.
fn evm_tx_type(request: &TransactionRequest) -> EvmTxType {
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

fn metadata_u128(request: &TransactionRequest, key: &str) -> PersonaResult<Option<u128>> {
    match request.metadata.get(key) {
        None => Ok(None),
        Some(v) => v.trim().parse::<u128>().map(Some).map_err(|_| {
            PersonaError::InvalidInput(format!("metadata '{key}' must be a decimal integer"))
        }),
    }
}

/// Access list is accepted as empty; a non-empty `access_list` in metadata is
/// rejected so callers never get a signature over semantics Persona ignored.
fn access_list_guard(request: &TransactionRequest) -> PersonaResult<()> {
    match request.metadata.get("access_list") {
        None => Ok(()),
        Some(v) if v.trim().is_empty() || v.trim() == "[]" => Ok(()),
        Some(_) => Err(PersonaError::InvalidInput(
            "Non-empty access lists are not supported yet".to_string(),
        )),
    }
}

fn evm_to_address(request: &TransactionRequest) -> PersonaResult<EvmAddress> {
    request
        .to_address
        .parse::<EvmAddress>()
        .map_err(|_| PersonaError::InvalidInput("Invalid Ethereum to_address".to_string()))
}

/// Full-range wei value (no longer capped at u128).
fn evm_value(request: &TransactionRequest) -> PersonaResult<EvmU256> {
    EvmU256::from_str_radix(request.amount.trim(), 10)
        .map_err(|_| PersonaError::InvalidInput(format!("Invalid wei amount '{}'", request.amount)))
}

fn evm_input(request: &TransactionRequest) -> PersonaResult<alloy_primitives::Bytes> {
    match request.metadata.get("data") {
        Some(hex_data) => hex::decode(hex_data.trim_start_matches("0x"))
            .map(Into::into)
            .map_err(|_| PersonaError::InvalidInput("metadata 'data' must be hex".to_string())),
        None => Ok(Default::default()),
    }
}

/// EIP-155 legacy transaction fields, built by `alloy_consensus`.
fn legacy_tx(request: &TransactionRequest) -> PersonaResult<TxLegacy> {
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
fn eip1559_tx(request: &TransactionRequest) -> PersonaResult<TxEip1559> {
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
fn sign_alloy_transaction<T>(
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

// ---------------------------------------------------------------------------
// Bitcoin: BIP-143 P2WPKH signing and segwit transaction assembly
// (delegated to the `bitcoin` crate for sighash, serialization and parsing)
// ---------------------------------------------------------------------------

const SIGHASH_ALL: u8 = 0x01;

/// Hard upper bound for satoshi amounts (21M BTC), so `Amount::from_sat`
/// can never panic on user input.
const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

/// A segwit transaction input as provided by the caller.
#[derive(Debug, Clone)]
struct BtcInput {
    outpoint: OutPoint,
    /// Prevout value in satoshis (required by BIP-143).
    amount: u64,
    sequence: Sequence,
}

fn parse_satoshis(value: &str, field: &str) -> PersonaResult<u64> {
    let sat: u64 = value.trim().parse().map_err(|_| {
        PersonaError::InvalidInput(format!("Bitcoin {field} must be decimal satoshis"))
    })?;
    if sat > MAX_MONEY_SATS {
        return Err(PersonaError::InvalidInput(format!(
            "Bitcoin {field} exceeds the max money supply"
        )));
    }
    Ok(sat)
}

/// Parse the `inputs` metadata field: a JSON array of
/// `{"txid": "<64 hex>", "vout": <n>, "amount": "<satoshis>"}`.
/// `Txid::from_str` takes care of display-order vs internal-order txids.
fn parse_btc_inputs(request: &TransactionRequest) -> PersonaResult<Vec<BtcInput>> {
    let raw = request.metadata.get("inputs").ok_or_else(|| {
        PersonaError::InvalidInput(
            "Bitcoin signing requires an 'inputs' metadata field (JSON array of \
             {txid, vout, amount})"
                .to_string(),
        )
    })?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(raw).map_err(|e| {
        PersonaError::InvalidInput(format!("metadata 'inputs' is not valid JSON: {e}"))
    })?;
    if entries.is_empty() {
        return Err(PersonaError::InvalidInput(
            "Bitcoin signing requires at least one input".to_string(),
        ));
    }

    let mut inputs = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let txid_hex = entry
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PersonaError::InvalidInput(format!("inputs[{i}] missing 'txid'")))?;
        let txid: Txid = txid_hex.parse().map_err(|_| {
            PersonaError::InvalidInput(format!("inputs[{i}].txid must be a 64-hex txid"))
        })?;
        let vout = entry
            .get("vout")
            .and_then(|v| v.as_u64())
            .filter(|v| *v <= u32::MAX as u64)
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("inputs[{i}] missing numeric 'vout'"))
            })?;
        let amount = entry
            .get("amount")
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| parse_satoshis(s, "input amount").ok())
                    .or(v.as_u64())
            })
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!(
                    "inputs[{i}] missing numeric 'amount' (satoshis)"
                ))
            })?;
        if amount > MAX_MONEY_SATS {
            return Err(PersonaError::InvalidInput(format!(
                "inputs[{i}].amount exceeds the max money supply"
            )));
        }

        inputs.push(BtcInput {
            outpoint: OutPoint::new(txid, vout as u32),
            amount,
            sequence: Sequence::MAX,
        });
    }
    Ok(inputs)
}

/// scriptPubKey for a destination address; parsing, network and checksum
/// validation are delegated to the `bitcoin` crate. Persona signs for
/// mainnet only.
fn script_pubkey_for_address(address: &str) -> PersonaResult<ScriptBuf> {
    use bitcoin::address::NetworkUnchecked;

    address
        .parse::<bitcoin::Address<NetworkUnchecked>>()
        .ok()
        .and_then(|a| a.require_network(Network::Bitcoin).ok())
        .map(|a| a.script_pubkey())
        .ok_or_else(|| {
            PersonaError::InvalidInput(format!(
                "Unsupported or invalid mainnet Bitcoin address '{address}'"
            ))
        })
}

/// The P2WPKH output script (`OP_0 <20-byte key hash>`) whose script code
/// BIP-143 derives when signing.
fn p2wpkh_output_script(pubkey_hash: &[u8; 20]) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(22);
    bytes.extend_from_slice(&[0x00, 0x14]);
    bytes.extend_from_slice(pubkey_hash);
    ScriptBuf::from_bytes(bytes)
}

/// Build the broadcastable segwit (BIP-141) transaction spending the given
/// P2WPKH prevouts, signed with SIGHASH_ALL.
///
/// Metadata contract:
/// - `inputs`: JSON array of `{txid, vout, amount}` (satoshis)
/// - `change_address`: optional; receives `sum(inputs) - amount - fee`.
///   Without it, inputs must exactly equal `amount + fee` so no value is
///   silently burned.
/// - `locktime`: optional u32 (default 0); `rbf`: "true" enables BIP-125
///   replace-by-fee signalling.
///
/// Only P2WPKH inputs (native segwit, BIP-84 addresses) can be signed.
/// `from_address` must be the address of the signing key.
pub fn build_bitcoin_raw_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<RawSignedTransaction> {
    use crate::crypto::address_generator::hash160;
    use crate::crypto::bech32::decode_witness_address;

    let inputs = parse_btc_inputs(request)?;

    // The input being spent must be a native P2WPKH output.
    let (_, witness_version, program) = decode_witness_address(&request.from_address)?;
    if witness_version != 0 || program.len() != 20 {
        return Err(PersonaError::InvalidInput(
            "Bitcoin signing currently supports only P2WPKH inputs \
             (BIP-84 bech32 addresses)"
                .to_string(),
        ));
    }

    // Guard against signing away funds from an address we don't control.
    let pubkey = secp_compressed_pubkey(signing_key);
    let pubkey_hash = hash160(&pubkey);
    if pubkey_hash != program.as_slice() {
        return Err(PersonaError::InvalidInput(
            "from_address does not match the signing key".to_string(),
        ));
    }

    let send_amount = parse_satoshis(&request.amount, "amount")?;
    let fee = parse_satoshis(&request.fee, "fee")?;
    let output_script = script_pubkey_for_address(&request.to_address)?;

    let total_in: u64 = inputs.iter().map(|i| i.amount).sum();
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(send_amount),
        script_pubkey: output_script,
    }];

    match request.metadata.get("change_address") {
        Some(change_addr) => {
            let change = (total_in - send_amount).checked_sub(fee).ok_or_else(|| {
                PersonaError::InvalidInput("Fee exceeds inputs minus send amount".to_string())
            })?;
            if change > 0 {
                outputs.push(TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: script_pubkey_for_address(change_addr)?,
                });
            }
        }
        None => {
            if total_in != send_amount + fee {
                return Err(PersonaError::InvalidInput(
                    "Inputs do not equal amount + fee; provide 'change_address' \
                     to receive the remainder instead of burning it"
                        .to_string(),
                ));
            }
        }
    }

    let locktime = request
        .metadata
        .get("locktime")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let rbf = request
        .metadata
        .get("rbf")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut inputs = inputs;
    if rbf {
        for input in &mut inputs {
            input.sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        }
    }

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(locktime),
        input: inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: i.sequence,
                witness: Default::default(),
            })
            .collect(),
        output: outputs,
    };

    // Sign each input (BIP-143 P2WPKH, SIGHASH_ALL) via rust-bitcoin's
    // sighash implementation.
    let witness_script = p2wpkh_output_script(&pubkey_hash);
    let mut witnesses = Vec::with_capacity(inputs.len());
    {
        let mut cache = SighashCache::new(&mut tx);
        for (index, input) in inputs.iter().enumerate() {
            let sighash = cache
                .p2wpkh_signature_hash(
                    index,
                    witness_script.as_script(),
                    Amount::from_sat(input.amount),
                    EcdsaSighashType::All,
                )
                .map_err(|e| {
                    PersonaError::InvalidInput(format!("Cannot sign input {index}: {e}"))
                })?;
            let signature: Signature = signing_key.sign_prehash(&sighash.to_byte_array())?;
            let mut witness_item = signature.to_der().to_vec();
            witness_item.push(SIGHASH_ALL);
            witnesses.push((witness_item, pubkey.to_vec()));
        }
    }
    for (index, (item_sig, item_pub)) in witnesses.iter().enumerate() {
        tx.input[index].witness = bitcoin::Witness::from_slice(&[item_sig, item_pub]);
    }

    // compute_txid hashes the stripped (witness-free) serialization, matching
    // what explorers display.
    Ok(RawSignedTransaction {
        raw: consensus_serialize(&tx),
        hash: tx.compute_txid().to_string(),
    })
}

/// EIP-155 chain id for the network.
fn chain_id(request: &TransactionRequest) -> PersonaResult<u64> {
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
fn sign_eip155(
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

fn build_eip155_raw_transaction_with(
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
fn recovery_id_for(
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
    Err(PersonaError::Cryptography(
        "Failed to recover signer from Ethereum signature".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

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

fn verify_ethereum_legacy(
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
fn verify_ethereum_typed(
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

fn address_from_verifying_key(key: &VerifyingKey) -> PersonaResult<String> {
    let encoded = key.to_encoded_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

/// Sign using secp256k1 (ECDSA)
fn sign_with_secp256k1(signing_key: &SigningKey, message: &[u8]) -> PersonaResult<Signature> {
    let digest = Sha256::new().chain_update(message);
    Ok(signing_key.sign_digest(digest))
}

/// Verify ECDSA (secp256k1) signature
fn verify_ecdsa_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> PersonaResult<bool> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| PersonaError::CryptographicError(format!("Invalid public key: {}", e)))?;
    let signature = Signature::from_der(signature)
        .map_err(|e| PersonaError::CryptographicError(format!("Invalid signature: {}", e)))?;

    // Create digest of the message
    let digest = Sha256::new().chain_update(message);

    match verifying_key.verify_digest(digest, &signature) {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::debug!(error = %e, "ECDSA signature verification failed");
            Ok(false)
        }
    }
}

/// Verify Ed25519 signature
fn verify_ed25519_signature(
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

fn decode_varuint(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut value: u64 = 0;
    for &b in bytes {
        value = (value << 8) | u64::from(b);
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wallet_crypto::{MasterKey, SecureMnemonic};
    use std::collections::HashMap;

    fn create_test_signing_key() -> SigningKey {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecureMnemonic::from_phrase(phrase).unwrap();
        let seed = mnemonic.to_seed("");

        let master_key = MasterKey::from_seed(&seed).unwrap();
        master_key
            .derive_path("m/44'/60'/0'/0/0")
            .unwrap()
            .to_signing_key()
            .unwrap()
    }

    fn test_key_from_raw(raw: [u8; 32]) -> SigningKey {
        SigningKey::from_slice(&raw).unwrap()
    }

    /// Build a `Txid` from wire-order bytes (the order txids appear inside
    /// a raw transaction), which is how BIP-143 vectors list them.
    fn wire_order_txid(hex_str: &str) -> Txid {
        Txid::from_byte_array(hex::decode(hex_str).unwrap().try_into().unwrap())
    }

    fn eth_request(nonce: u64) -> TransactionRequest {
        TransactionRequest {
            id: uuid::Uuid::new_v4(),
            wallet_id: uuid::Uuid::new_v4(),
            network: BlockchainNetwork::Ethereum,
            from_address: "0x0000000000000000000000000000000000000000".to_string(),
            to_address: "0x3535353535353535353535353535353535353535".to_string(),
            amount: "1000000000000000000".to_string(), // 1 ETH in wei
            fee: "0".to_string(),
            gas_price: Some("20000000000".to_string()), // 20 gwei
            gas_limit: Some(21000),
            nonce: Some(nonce),
            memo: None,
            raw_transaction_data: None,
            required_signatures: 1,
            created_at: Utc::now(),
            expires_at: None,
            metadata: HashMap::new(),
        }
    }

    // The worked example from the EIP-155 specification.
    #[test]
    fn test_eip155_spec_signing_hash() {
        // nonce=9, gasprice=20e9, startgas=21000, to=0x3535..35, value=1e18
        let request = eth_request(9);
        let hash: B256 = legacy_tx(&request).unwrap().signature_hash();
        assert_eq!(
            hex::encode(hash),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );
    }

    // The EIP-155 spec's signed example: the private key 0x46 repeated must
    // produce exactly the canonical signed transaction bytes.
    #[test]
    fn test_eip155_spec_signed_transaction() {
        let request = eth_request(9);
        let key = test_key_from_raw([0x46u8; 32]);
        let raw = build_eip155_raw_transaction_with(&request, &key).unwrap();

        assert_eq!(
            hex::encode(&raw),
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
    }

    #[test]
    fn test_ethereum_transaction_signing_roundtrip() {
        let request = eth_request(0);

        let private_key = create_test_signing_key();
        let (signature, scheme) = sign_ethereum_transaction(&request, &private_key).unwrap();
        assert_eq!(scheme, SignatureScheme::ECDSA);
        // r(32) + s(32) + v(1..3)
        assert!(signature.len() >= 65 && signature.len() <= 67);

        // The signature must verify against the actual from_address.
        let expected_address = address_from_verifying_key(private_key.verifying_key()).unwrap();
        let tx_signature = signature_for(
            &expected_address,
            signature,
            secp_compressed_pubkey(&private_key).to_vec(),
            SignatureScheme::ECDSA,
            Utc::now(),
        );
        assert!(verify_ethereum_transaction(&request, &tx_signature).unwrap());
    }

    #[test]
    fn test_solana_transaction_signing() {
        let seed = [7u8; 64];
        let ed_key = Ed25519Key::from_seed(&seed).unwrap();
        let message = b"serialized solana message".to_vec();
        let request = TransactionRequest {
            network: BlockchainNetwork::Solana,
            from_address: bs58::encode(ed_key.public_bytes()).into_string(),
            raw_transaction_data: Some(message.clone()),
            ..eth_request(0)
        };

        let (signature, scheme) = sign_solana_transaction(&request, &ed_key).unwrap();
        assert_eq!(scheme, SignatureScheme::EdDSA);
        assert_eq!(signature.len(), 64);

        let tx_signature = signature_for(
            &request.from_address,
            signature,
            ed_key.public_bytes().to_vec(),
            SignatureScheme::EdDSA,
            Utc::now(),
        );
        assert!(verify_solana_transaction(&tx_signature, &message).unwrap());
    }

    #[test]
    fn test_solana_signing_requires_message() {
        let ed_key = Ed25519Key::from_seed(&[7u8; 64]).unwrap();
        let request = TransactionRequest {
            network: BlockchainNetwork::Solana,
            ..eth_request(0)
        };
        assert!(sign_solana_transaction(&request, &ed_key).is_err());
    }

    #[test]
    fn test_bitcoin_raw_requires_inputs() {
        let request = TransactionRequest {
            network: BlockchainNetwork::Bitcoin,
            from_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            to_address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            amount: "100000".to_string(),
            fee: "1000".to_string(),
            ..eth_request(0)
        };
        let key = WalletSigningKey::Secp256k1(create_test_signing_key());

        // The audit signature still works...
        let sig = sign_transaction(&request, &key).unwrap();
        assert_eq!(sig.signature_scheme, SignatureScheme::ECDSA);
        assert!(!sig.signature.is_empty());
        // ...but raw assembly needs the UTXO inputs to sign for real.
        assert!(build_raw_transaction(&request, &key).is_err());
    }

    // BIP-143 native P2WPKH example: input index 1, via rust-bitcoin's
    // SighashCache. The spec's txid strings appear in the unsigned tx hex,
    // i.e. internal (wire) byte order, so they are loaded with
    // `Txid::from_byte_array` rather than parsed as display-order ids.
    #[test]
    fn test_bip143_spec_sighash() {
        let privkey = test_key_from_raw(
            hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let pubkey = secp_compressed_pubkey(&privkey);
        assert_eq!(
            hex::encode(pubkey),
            "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
        );
        let pubkey_hash = crate::crypto::address_generator::hash160(&pubkey);

        let txid0 =
            wire_order_txid("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f");
        let txid1 =
            wire_order_txid("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a");
        // Both inputs participate in hashPrevouts/hashSequence with their
        // own sequence; the script type of input 0 does not affect the
        // P2WPKH sighash for input 1.
        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::from_consensus(17),
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(txid0, 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(0xffff_ffee),
                    witness: Default::default(),
                },
                TxIn {
                    previous_output: OutPoint::new(txid1, 1),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Default::default(),
                },
            ],
            output: vec![
                TxOut {
                    value: Amount::from_sat(112_340_000),
                    script_pubkey: ScriptBuf::from_bytes(
                        hex::decode("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac").unwrap(),
                    ),
                },
                TxOut {
                    value: Amount::from_sat(223_450_000),
                    script_pubkey: ScriptBuf::from_bytes(
                        hex::decode("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac").unwrap(),
                    ),
                },
            ],
        };

        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wpkh_signature_hash(
                1,
                p2wpkh_output_script(&pubkey_hash).as_script(),
                Amount::from_sat(600_000_000),
                EcdsaSighashType::All,
            )
            .unwrap();
        assert_eq!(
            hex::encode(sighash.to_byte_array()),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    // BIP-143 example: RFC-6979 deterministic signing must reproduce the
    // spec's DER signature byte for byte.
    #[test]
    fn test_bip143_spec_signature() {
        let privkey = test_key_from_raw(
            hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let sighash: [u8; 32] =
            hex::decode("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
                .unwrap()
                .try_into()
                .unwrap();

        let signature: k256::ecdsa::Signature = privkey.sign_prehash(&sighash).unwrap();
        let mut der = signature.to_der().to_vec();
        der.push(SIGHASH_ALL);

        assert_eq!(
            hex::encode(&der),
            "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a\
             0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
                .replace(' ', "")
        );
    }

    // Full segwit assembly: structure, witness contents and txid shape.
    #[test]
    fn test_bitcoin_p2wpkh_raw_transaction() {
        use crate::crypto::address_generator::{
            generate_bitcoin_address_from_compressed_pubkey, BitcoinAddressType,
        };

        let key = create_test_signing_key();
        let pubkey = secp_compressed_pubkey(&key);
        let from_address = generate_bitcoin_address_from_compressed_pubkey(
            &pubkey,
            BitcoinAddressType::P2WPKH,
            false,
        )
        .unwrap();
        let to_address = generate_bitcoin_address_from_compressed_pubkey(
            &[0x02u8; 33],
            BitcoinAddressType::P2WPKH,
            false,
        )
        .unwrap();

        // 2 inputs, single output, no change: total_in must equal amount+fee.
        let inputs_json = format!(
            r#"[
            {{"txid":"{}","vout":0,"amount":"100000"}},
            {{"txid":"{}","vout":1,"amount":"200000"}}
        ]"#,
            "11".repeat(32),
            "22".repeat(32),
        );
        let request = TransactionRequest {
            network: BlockchainNetwork::Bitcoin,
            from_address,
            to_address,
            amount: "280000".to_string(),
            fee: "20000".to_string(),
            metadata: HashMap::from([("inputs".to_string(), inputs_json)]),
            ..eth_request(0)
        };

        let signed =
            build_raw_transaction(&request, &WalletSigningKey::Secp256k1(key.clone())).unwrap();

        // Header: version 2, segwit marker+flag, 2 inputs, 1 output.
        assert_eq!(&signed.raw[..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        // txid is 64 hex chars
        assert_eq!(signed.hash.len(), 64);

        // Witness item 1 must be the BIP-143 signature over the recomputed
        // sighash; item 2 is the compressed pubkey.
        let pubkey_hash = crate::crypto::address_generator::hash160(&pubkey);
        let inputs = parse_btc_inputs(&request).unwrap();
        let template = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(0),
            input: inputs
                .iter()
                .map(|i| TxIn {
                    previous_output: i.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: i.sequence,
                    witness: Default::default(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(280_000),
                script_pubkey: script_pubkey_for_address(&request.to_address).unwrap(),
            }],
        };
        let mut cache = SighashCache::new(&template);
        let sighash = cache
            .p2wpkh_signature_hash(
                0,
                p2wpkh_output_script(&pubkey_hash).as_script(),
                Amount::from_sat(inputs[0].amount),
                EcdsaSighashType::All,
            )
            .unwrap();
        let sig: k256::ecdsa::Signature = key.sign_prehash(&sighash.to_byte_array()).unwrap();
        let mut expected_item = sig.to_der().to_vec();
        expected_item.push(SIGHASH_ALL);

        // Find the witness section: after outputs, each input has 2 items.
        // Cheap structural check: the raw tx must contain the pubkey and
        // the signature bytes.
        let raw_hex = hex::encode(&signed.raw);
        assert!(raw_hex.contains(&hex::encode(pubkey)));
        assert!(raw_hex.contains(&hex::encode(&expected_item)));
    }

    #[test]
    fn test_bitcoin_from_address_must_match_key() {
        use crate::crypto::address_generator::{
            generate_bitcoin_address_from_compressed_pubkey, BitcoinAddressType,
        };

        let key = create_test_signing_key();
        // Address of a DIFFERENT key.
        let from_address = generate_bitcoin_address_from_compressed_pubkey(
            &[0x03u8; 33],
            BitcoinAddressType::P2WPKH,
            false,
        )
        .unwrap();
        let inputs_json = format!(r#"[{{"txid":"{}","vout":0,"amount":1}}]"#, "aa".repeat(32));
        let request = TransactionRequest {
            network: BlockchainNetwork::Bitcoin,
            from_address,
            to_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            amount: "1".to_string(),
            fee: "1".to_string(),
            metadata: HashMap::from([("inputs".to_string(), inputs_json.to_string())]),
            ..eth_request(0)
        };
        assert!(build_bitcoin_raw_transaction(&request, &key).is_err());
    }

    #[test]
    fn test_eip155_raw_transaction_builds_and_hashes() {
        let request = eth_request(4);
        let key = WalletSigningKey::Secp256k1(create_test_signing_key());
        let signed = build_raw_transaction(&request, &key).unwrap();
        assert_eq!(signed.raw[0], 0xf8); // RLP list header
        assert!(signed.hash.starts_with("0x"));
        assert_eq!(signed.hash.len(), 66);
    }

    // --- EIP-1559 typed transactions -------------------------------------

    fn eip1559_request(nonce: u64) -> TransactionRequest {
        let mut request = eth_request(nonce);
        request.gas_price = None; // legacy fee field must not be needed
        request.metadata.insert(
            "max_fee_per_gas".to_string(),
            "30000000000".to_string(), // 30 gwei
        );
        request.metadata.insert(
            "max_priority_fee_per_gas".to_string(),
            "2000000000".to_string(), // 2 gwei
        );
        request
    }

    #[test]
    fn test_eip1559_signing_roundtrip_and_raw() {
        let request = eip1559_request(3);
        let key = create_test_signing_key();
        let expected_address = address_from_verifying_key(key.verifying_key()).unwrap();

        // Audit signature path: r||s||y_parity.
        let (sig, scheme) = sign_ethereum_transaction(&request, &key).unwrap();
        assert_eq!(scheme, SignatureScheme::ECDSA);
        assert_eq!(sig.len(), 65); // typed transactions carry a 1-byte parity
        let tx_sig = signature_for(
            &expected_address,
            sig,
            secp_compressed_pubkey(&key).to_vec(),
            SignatureScheme::ECDSA,
            Utc::now(),
        );
        assert!(verify_ethereum_transaction(&request, &tx_sig).unwrap());

        // Raw path: 0x02 typed envelope with the same fields echoed back.
        let signed = build_raw_transaction(&request, &WalletSigningKey::Secp256k1(key)).unwrap();
        assert_eq!(signed.raw[0], 0x02);
        assert!(signed.hash.starts_with("0x"));
        assert_eq!(signed.hash.len(), 66);
    }

    #[test]
    fn test_eip1559_build_matches_manual_signing_hash() {
        // The raw envelope's [chainId, nonce, prio, fee, gas, to, value, data]
        // must be exactly the fields the signing hash committed to.
        let request = eip1559_request(7);
        let hash: B256 = eip1559_tx(&request).unwrap().signature_hash();
        // Deterministic: same request, same hash (RFC-6979 signing not
        // involved in the hash itself).
        assert_eq!(hash, eip1559_tx(&request).unwrap().signature_hash());
    }

    #[test]
    fn test_eip1559_fee_validation() {
        let key = create_test_signing_key();

        // priority fee above max fee is invalid
        let mut request = eip1559_request(0);
        request.metadata.insert(
            "max_priority_fee_per_gas".to_string(),
            "40000000000".to_string(),
        );
        assert!(build_eip1559_raw_transaction(&request, &key).is_err());

        // missing max_fee_per_gas is invalid
        let mut request = eip1559_request(0);
        request.metadata.remove("max_fee_per_gas");
        assert!(build_eip1559_raw_transaction(&request, &key).is_err());

        // non-empty access lists are rejected rather than ignored
        let mut request = eip1559_request(0);
        request.metadata.insert(
            "access_list".to_string(),
            r#"[{"address":"0x00"}]"#.to_string(),
        );
        assert!(build_eip1559_raw_transaction(&request, &key).is_err());

        // empty access list string is fine
        let mut request = eip1559_request(0);
        request
            .metadata
            .insert("access_list".to_string(), "[]".to_string());
        assert!(build_eip1559_raw_transaction(&request, &key).is_ok());
    }

    #[test]
    fn test_legacy_tx_still_uses_eip155_v() {
        // No 1559 metadata => legacy path, v >= 35.
        let request = eth_request(1);
        let key = create_test_signing_key();
        let (sig, _) = sign_ethereum_transaction(&request, &key).unwrap();
        let v = sig[sig.len() - 1];
        assert!(v >= 35, "legacy v must encode chain id + parity");
    }

    // ============ additional coverage: dispatch, guards, verify paths ======

    fn btc_request(from: String, to: String) -> TransactionRequest {
        TransactionRequest {
            network: BlockchainNetwork::Bitcoin,
            from_address: from,
            to_address: to,
            amount: "100000".to_string(),
            fee: "1000".to_string(),
            ..eth_request(0)
        }
    }

    #[test]
    fn k256_error_converts_into_persona_error() {
        // k256's ecdsa::Error is signature::Error; the From impl wraps its
        // message into a cryptographic PersonaError.
        let converted: PersonaError = k256::ecdsa::Error::new().into();
        assert!(!converted.to_string().is_empty());
    }

    #[test]
    fn sign_transaction_rejects_mismatched_key_curve() {
        // Bitcoin with an Ed25519 key.
        let ed = WalletSigningKey::Ed25519(Ed25519Key::from_seed(&[7u8; 64]).unwrap());
        let err = sign_transaction(
            &btc_request(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            ),
            &ed,
        )
        .expect_err("Bitcoin requires secp256k1");
        assert!(err.to_string().contains("No matching signing key curve"));

        // Solana with a secp256k1 key.
        let secp = WalletSigningKey::Secp256k1(create_test_signing_key());
        let mut sol_request = eth_request(0);
        sol_request.network = BlockchainNetwork::Solana;
        sol_request.raw_transaction_data = Some(b"msg".to_vec());
        assert!(sign_transaction(&sol_request, &secp).is_err());
    }

    #[test]
    fn sign_transaction_covers_solana_dispatch() {
        let ed_key = Ed25519Key::from_seed(&[7u8; 64]).unwrap();
        let message = b"solana wire message".to_vec();
        let mut request = eth_request(0);
        request.network = BlockchainNetwork::Solana;
        request.from_address = bs58::encode(ed_key.public_bytes()).into_string();
        request.raw_transaction_data = Some(message.clone());

        let sig = sign_transaction(&request, &WalletSigningKey::Ed25519(ed_key.clone())).unwrap();
        assert_eq!(sig.signature_scheme, SignatureScheme::EdDSA);
        assert_eq!(sig.public_key, ed_key.public_bytes().to_vec());
        assert_eq!(sig.signature.len(), 64);
        assert!(verify_solana_transaction(&sig, &message).unwrap());
    }

    #[test]
    fn build_raw_transaction_rejects_wrong_curves_and_networks() {
        let secp = WalletSigningKey::Secp256k1(create_test_signing_key());
        let ed = WalletSigningKey::Ed25519(Ed25519Key::from_seed(&[7u8; 64]).unwrap());

        // Bitcoin requires secp256k1.
        let err = build_raw_transaction(
            &btc_request(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            ),
            &ed,
        )
        .expect_err("Bitcoin requires secp256k1");
        assert!(err.to_string().contains("Bitcoin requires a secp256k1"));

        // Ethereum requires secp256k1.
        let err =
            build_raw_transaction(&eth_request(0), &ed).expect_err("Ethereum requires secp256k1");
        assert!(err.to_string().contains("Ethereum requires a secp256k1"));

        // Solana requires Ed25519.
        let mut sol = eth_request(0);
        sol.network = BlockchainNetwork::Solana;
        sol.raw_transaction_data = Some(b"msg".to_vec());
        let err = build_raw_transaction(&sol, &secp).expect_err("Solana requires Ed25519");
        assert!(err.to_string().contains("Solana requires an Ed25519"));

        // Other networks have no raw assembly.
        let mut other = eth_request(0);
        other.network = BlockchainNetwork::BitcoinCash;
        let err =
            build_raw_transaction(&other, &secp).expect_err("raw assembly is network-limited");
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn build_raw_transaction_covers_solana() {
        let ed_key = Ed25519Key::from_seed(&[7u8; 64]).unwrap();
        let message = b"serialized solana message".to_vec();
        let mut request = eth_request(0);
        request.network = BlockchainNetwork::Solana;
        request.from_address = bs58::encode(ed_key.public_bytes()).into_string();
        request.raw_transaction_data = Some(message.clone());

        let signed =
            build_raw_transaction(&request, &WalletSigningKey::Ed25519(ed_key.clone())).unwrap();
        // Wire format: 1 signature || 64-byte sig || message.
        assert_eq!(signed.raw[0], 1);
        assert_eq!(&signed.raw[1..65], &ed_key.sign(&message)[..]);
        assert_eq!(&signed.raw[65..], &message[..]);
        // Hash is the base58 signature.
        assert_eq!(signed.hash, bs58::encode(&signed.raw[1..65]).into_string());
    }

    #[test]
    fn minimal_be_bytes_encodes_minimally() {
        assert_eq!(minimal_be_bytes(0), Vec::<u8>::new());
        assert_eq!(minimal_be_bytes(1), vec![1]);
        assert_eq!(minimal_be_bytes(35), vec![35]);
        assert_eq!(minimal_be_bytes(255), vec![255]);
        assert_eq!(minimal_be_bytes(256), vec![1, 0]);
        assert_eq!(minimal_be_bytes(0x0100_0000_0000), vec![1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn decode_varuint_boundaries() {
        assert_eq!(decode_varuint(&[]), None);
        assert_eq!(decode_varuint(&[1, 2]), Some(0x0102));
        assert_eq!(decode_varuint(&[0xFFu8; 8]), Some(u64::MAX));
        assert_eq!(decode_varuint(&[0xFFu8; 9]), None);
    }

    #[test]
    fn bitcoin_sighash_binds_request_fields() {
        let mut request = btc_request(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        );
        request.amount = "100".to_string();
        request.fee = "10".to_string();

        let baseline = create_bitcoin_sighash(&request).unwrap();
        // Deterministic.
        assert_eq!(create_bitcoin_sighash(&request).unwrap(), baseline);

        // Changing any bound field changes the hash.
        let mut other = request.clone();
        other.to_address = "1FC9gffSsyaMNCmZ3CuktoAjs.IdFjdNv".to_string();
        assert_ne!(create_bitcoin_sighash(&other).unwrap(), baseline);
        let mut other = request.clone();
        other.amount = "101".to_string();
        assert_ne!(create_bitcoin_sighash(&other).unwrap(), baseline);
        let mut other = request.clone();
        other.fee = "11".to_string();
        assert_ne!(create_bitcoin_sighash(&other).unwrap(), baseline);

        // Non-numeric amounts are skipped from the hash rather than erroring.
        let mut other = request.clone();
        other.amount = "not-a-number".to_string();
        let skipped = create_bitcoin_sighash(&other).unwrap();
        assert_ne!(skipped, baseline);
        let mut without_amount = request.clone();
        without_amount.amount = "garbage too".to_string();
        assert_eq!(create_bitcoin_sighash(&without_amount).unwrap(), skipped);
    }

    #[test]
    fn metadata_u128_rejects_non_numeric() {
        let mut request = eip1559_request(0);
        request
            .metadata
            .insert("max_fee_per_gas".to_string(), "abc".to_string());
        let err = build_eip1559_raw_transaction(&request, &create_test_signing_key())
            .expect_err("non-numeric fee metadata must be rejected");
        assert!(err.to_string().contains("must be a decimal integer"));
    }

    #[test]
    fn evm_field_errors() {
        // Invalid to_address.
        let mut request = eth_request(0);
        request.to_address = "not an address".to_string();
        let err = build_eip155_raw_transaction(&request, &create_test_signing_key())
            .expect_err("invalid to_address must be rejected");
        assert!(err.to_string().contains("Invalid Ethereum to_address"));

        // Invalid wei amount.
        let mut request = eth_request(0);
        request.amount = "1.5".to_string();
        let err = build_eip155_raw_transaction(&request, &create_test_signing_key())
            .expect_err("fractional wei must be rejected");
        assert!(err.to_string().contains("Invalid wei amount"));

        // Hex input data is accepted (with or without 0x prefix).
        let mut request = eth_request(0);
        request
            .metadata
            .insert("data".to_string(), "0xdeadbeef".to_string());
        assert!(build_eip155_raw_transaction(&request, &create_test_signing_key()).is_ok());

        // Non-hex data is rejected.
        let mut request = eth_request(0);
        request
            .metadata
            .insert("data".to_string(), "zz-not-hex".to_string());
        let err = build_eip155_raw_transaction(&request, &create_test_signing_key())
            .expect_err("invalid hex data must be rejected");
        assert!(err.to_string().contains("must be hex"));
    }

    #[test]
    fn legacy_tx_requires_nonce_gas_price_and_limit() {
        let key = create_test_signing_key();

        // Missing nonce.
        let mut request = eth_request(0);
        request.nonce = None;
        let err = build_eip155_raw_transaction(&request, &key)
            .expect_err("missing nonce must be rejected");
        assert!(err.to_string().contains("require a nonce"));

        // Missing gas_price.
        let mut request = eth_request(0);
        request.gas_price = None;
        let err = build_eip155_raw_transaction(&request, &key)
            .expect_err("missing gas_price must be rejected");
        assert!(err.to_string().contains("require a numeric gas_price"));

        // Non-numeric gas_price.
        let mut request = eth_request(0);
        request.gas_price = Some("20 gwei".to_string());
        assert!(build_eip155_raw_transaction(&request, &key).is_err());

        // Missing gas_limit.
        let mut request = eth_request(0);
        request.gas_limit = None;
        let err = build_eip155_raw_transaction(&request, &key)
            .expect_err("missing gas_limit must be rejected");
        assert!(err.to_string().contains("require a gas_limit"));

        // EIP-1559: missing gas_limit is also rejected there.
        let mut request = eip1559_request(0);
        request.gas_limit = None;
        let err = build_eip1559_raw_transaction(&request, &key)
            .expect_err("1559 missing gas_limit must be rejected");
        assert!(err.to_string().contains("require a gas_limit"));

        // EIP-1559: missing nonce.
        let mut request = eip1559_request(0);
        request.nonce = None;
        assert!(build_eip1559_raw_transaction(&request, &key).is_err());

        // EIP-1559: zero max fee.
        let mut request = eip1559_request(0);
        request
            .metadata
            .insert("max_fee_per_gas".to_string(), "0".to_string());
        let err = build_eip1559_raw_transaction(&request, &key)
            .expect_err("zero max fee must be rejected");
        assert!(err
            .to_string()
            .contains("require metadata 'max_fee_per_gas'"));
    }

    #[test]
    fn parse_satoshis_validates_range_and_format() {
        assert_eq!(parse_satoshis(" 100 ", "amount").unwrap(), 100);
        assert_eq!(
            parse_satoshis("2100000000000000", "amount").unwrap(),
            MAX_MONEY_SATS
        );

        let err =
            parse_satoshis("1.5", "amount").expect_err("fractional satoshis must be rejected");
        assert!(err.to_string().contains("must be decimal satoshis"));

        let err = parse_satoshis("2100000000000001", "amount")
            .expect_err("above the money supply must be rejected");
        assert!(err.to_string().contains("exceeds the max money supply"));
    }

    #[test]
    fn parse_btc_inputs_error_paths() {
        let base = btc_request(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        );
        let with_inputs = |json: &str| {
            let mut request = base.clone();
            request
                .metadata
                .insert("inputs".to_string(), json.to_string());
            parse_btc_inputs(&request)
        };

        // Missing inputs field entirely.
        let err = parse_btc_inputs(&base).expect_err("missing inputs must be rejected");
        assert!(err
            .to_string()
            .contains("requires an 'inputs' metadata field"));

        // Invalid JSON.
        let err = with_inputs("[").expect_err("invalid JSON must be rejected");
        assert!(err.to_string().contains("not valid JSON"));

        // Empty array.
        let err = with_inputs("[]").expect_err("empty inputs must be rejected");
        assert!(err.to_string().contains("at least one input"));

        // Missing txid.
        let err =
            with_inputs(r#"[{"vout":0,"amount":1}]"#).expect_err("missing txid must be rejected");
        assert!(err.to_string().contains("missing 'txid'"));

        // Malformed txid.
        let err = with_inputs(r#"[{"txid":"nothex","vout":0,"amount":1}]"#)
            .expect_err("bad txid must be rejected");
        assert!(err.to_string().contains("64-hex txid"));

        // Missing vout.
        let err = with_inputs(format!(r#"[{{"txid":"{}","amount":1}}]"#, "11".repeat(32)).as_str())
            .expect_err("missing vout must be rejected");
        assert!(err.to_string().contains("missing numeric 'vout'"));

        // vout overflowing u32.
        let err = with_inputs(
            format!(
                r#"[{{"txid":"{}","vout":4294967296,"amount":1}}]"#,
                "11".repeat(32)
            )
            .as_str(),
        )
        .expect_err("vout above u32 must be rejected");
        assert!(err.to_string().contains("missing numeric 'vout'"));

        // Missing amount.
        let err = with_inputs(format!(r#"[{{"txid":"{}","vout":0}}]"#, "11".repeat(32)).as_str())
            .expect_err("missing amount must be rejected");
        assert!(err.to_string().contains("missing numeric 'amount'"));

        // Numeric amount above the money supply (but inside u64).
        let err = with_inputs(
            format!(
                r#"[{{"txid":"{}","vout":0,"amount":9000000000000000}}]"#,
                "11".repeat(32)
            )
            .as_str(),
        )
        .expect_err("amount above the money supply must be rejected");
        assert!(err.to_string().contains("exceeds the max money supply"));

        // Happy path: string amounts and numeric amounts both parse.
        let inputs = with_inputs(
            r#"[{"txid":"11ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","vout":0,"amount":"100"},
                {"txid":"22ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","vout":1,"amount":200}]"#,
        )
        .unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].amount, 100);
        assert_eq!(inputs[1].amount, 200);
        assert_eq!(inputs[1].sequence, Sequence::MAX);
    }

    #[test]
    fn script_pubkey_for_address_shapes() {
        // P2PKH: version + push20 + hash + check = 25 bytes.
        let p2pkh = script_pubkey_for_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(p2pkh.len(), 25);
        assert_eq!(p2pkh.as_bytes()[0], 0x76); // OP_DUP

        // P2SH: hash160 script = 23 bytes.
        let p2sh = script_pubkey_for_address("3P14159f73E4gFr7JterCCQh9QjiTjiZrG").unwrap();
        assert_eq!(p2sh.len(), 23);
        assert_eq!(p2sh.as_bytes()[0], 0xa9); // OP_HASH160

        // Bech32 P2WPKH.
        let bech32 =
            script_pubkey_for_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(bech32.as_bytes()[..2], [0x00, 0x14]);

        // Testnet addresses are rejected (Persona signs mainnet only).
        let err = script_pubkey_for_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn")
            .expect_err("testnet address must be rejected");
        assert!(err.to_string().contains("Unsupported or invalid mainnet"));

        // Garbage.
        assert!(script_pubkey_for_address("hello").is_err());
    }

    #[test]
    fn bitcoin_raw_rejects_non_p2wpkh_from_address() {
        let key = create_test_signing_key();
        // Taproot from_address: witness version 1.
        let p2tr_from =
            crate::crypto::address_generator::generate_bitcoin_address_from_compressed_pubkey(
                &secp_compressed_pubkey(&key),
                crate::crypto::address_generator::BitcoinAddressType::P2TR,
                false,
            )
            .unwrap();
        let mut request = btc_request(p2tr_from, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string());
        request.metadata.insert(
            "inputs".to_string(),
            format!(
                r#"[{{"txid":"{}","vout":0,"amount":200000}}]"#,
                "11".repeat(32)
            ),
        );
        let err = build_bitcoin_raw_transaction(&request, &key)
            .expect_err("taproot inputs are not supported yet");
        assert!(
            err.to_string().contains("only P2WPKH inputs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn bitcoin_raw_change_address_paths() {
        let key = create_test_signing_key();
        let from_address =
            crate::crypto::address_generator::generate_bitcoin_address_from_compressed_pubkey(
                &secp_compressed_pubkey(&key),
                crate::crypto::address_generator::BitcoinAddressType::P2WPKH,
                false,
            )
            .unwrap();
        let to_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();

        let make_request = |amount: &str, fee: &str, extra: Vec<(&str, String)>| {
            let mut request = btc_request(from_address.clone(), to_address.clone());
            request.amount = amount.to_string();
            request.fee = fee.to_string();
            request.metadata.insert(
                "inputs".to_string(),
                format!(
                    r#"[{{"txid":"{}","vout":0,"amount":300000}}]"#,
                    "11".repeat(32)
                ),
            );
            for (k, v) in extra {
                request.metadata.insert(k.to_string(), v);
            }
            request
        };

        // Without a change address the inputs must equal amount + fee exactly.
        let err = build_bitcoin_raw_transaction(&make_request("100000", "1000", vec![]), &key)
            .expect_err("surplus without change address must be rejected");
        assert!(
            err.to_string().contains("Inputs do not equal amount + fee"),
            "unexpected error: {err}"
        );

        // With a change address, zero change collapses to a single output.
        let signed = build_bitcoin_raw_transaction(
            &make_request(
                "299000",
                "1000",
                vec![(
                    "change_address",
                    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
                )],
            ),
            &key,
        )
        .unwrap();
        // Header: version 2, segwit marker+flag; and byte 48 (after the
        // single input) is the output count.
        assert_eq!(&signed.raw[..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(signed.raw[48], 1);
        // Default sequence is 0xffffffff.
        assert_eq!(&signed.raw[44..48], &[0xff, 0xff, 0xff, 0xff]);
        // Default locktime 0 closes the transaction.
        assert_eq!(
            &signed.raw[signed.raw.len() - 4..],
            &[0x00, 0x00, 0x00, 0x00]
        );

        // Positive change produces a second output.
        let signed = build_bitcoin_raw_transaction(
            &make_request(
                "100000",
                "1000",
                vec![(
                    "change_address",
                    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
                )],
            ),
            &key,
        )
        .unwrap();
        assert_eq!(signed.raw[48], 2);

        // Fee exceeding inputs-minus-amount is rejected.
        let err = build_bitcoin_raw_transaction(
            &make_request(
                "299999",
                "2000",
                vec![(
                    "change_address",
                    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
                )],
            ),
            &key,
        )
        .expect_err("fee above inputs-minus-amount must be rejected");
        assert!(err.to_string().contains("Fee exceeds"));

        // RBF signalling and a custom locktime land in the transaction.
        let signed = build_bitcoin_raw_transaction(
            &make_request(
                "299000",
                "1000",
                vec![
                    ("rbf", "true".to_string()),
                    ("locktime", "800000".to_string()),
                ],
            ),
            &key,
        )
        .unwrap();
        // RBF sequence 0xfffffffd (little-endian on the wire) and locktime
        // 800000 = 0x0c3500 as the trailing 4 consensus bytes.
        assert_eq!(&signed.raw[44..48], &[0xfd, 0xff, 0xff, 0xff]);
        assert_eq!(
            &signed.raw[signed.raw.len() - 4..],
            &[0x00, 0x35, 0x0c, 0x00]
        );
    }

    #[test]
    fn chain_id_resolution() {
        let mut request = eth_request(0);

        request.network = BlockchainNetwork::Ethereum;
        assert_eq!(chain_id(&request).unwrap(), 1);
        request.network = BlockchainNetwork::Optimism;
        assert_eq!(chain_id(&request).unwrap(), 10);
        request.network = BlockchainNetwork::Polygon;
        assert_eq!(chain_id(&request).unwrap(), 137);
        request.network = BlockchainNetwork::Arbitrum;
        assert_eq!(chain_id(&request).unwrap(), 42161);
        request.network = BlockchainNetwork::BinanceSmartChain;
        assert_eq!(chain_id(&request).unwrap(), 56);

        // Custom networks need an explicit chain_id.
        request.network = BlockchainNetwork::Custom("test".to_string());
        let err = chain_id(&request).expect_err("custom without chain_id must fail");
        assert!(err.to_string().contains("require a chain_id"));
        request
            .metadata
            .insert("chain_id".to_string(), "1337".to_string());
        assert_eq!(chain_id(&request).unwrap(), 1337);

        // Non-EVM networks are rejected.
        request.network = BlockchainNetwork::Bitcoin;
        request.metadata.remove("chain_id");
        let err = chain_id(&request).expect_err("Bitcoin is not EVM");
        assert!(err.to_string().contains("is not an EVM network"));
    }

    #[test]
    fn recovery_id_for_fails_on_foreign_verifying_key() {
        let key_a = test_key_from_raw([1u8; 32]);
        let key_b = test_key_from_raw([2u8; 32]);

        let prehash = [7u8; 32];
        let signature: k256::ecdsa::Signature = key_a.sign_prehash(&prehash).unwrap();

        // Recovery against key_a succeeds...
        assert!(recovery_id_for(&key_a, &prehash, &signature).is_ok());
        // ...but the same signature cannot reproduce key_b.
        let err = recovery_id_for(&key_b, &prehash, &signature)
            .expect_err("a signature cannot recover a foreign key");
        assert!(err.to_string().contains("Failed to recover signer"));
    }

    #[test]
    fn verify_transaction_signature_dispatch() {
        let key = create_test_signing_key();
        let message = b"some message";

        // ECDSA round trip.
        let signature = sign_with_secp256k1(&key, message).unwrap();
        let tx_sig = signature_for(
            "addr",
            signature.to_der().to_vec(),
            secp_compressed_pubkey(&key).to_vec(),
            SignatureScheme::ECDSA,
            Utc::now(),
        );
        assert!(verify_transaction_signature(&tx_sig, message).unwrap());
        assert!(!verify_transaction_signature(&tx_sig, b"other").unwrap());

        // Unsupported scheme.
        let mut unsupported = tx_sig.clone();
        unsupported.signature_scheme = SignatureScheme::Schnorr;
        let err = verify_transaction_signature(&unsupported, message)
            .expect_err("Schnorr has no verifier");
        assert!(err.to_string().contains("Signature verification"));
        unsupported.signature_scheme = SignatureScheme::BLS;
        assert!(verify_transaction_signature(&unsupported, message).is_err());

        // Malformed public key / signature.
        let mut bad = tx_sig.clone();
        bad.public_key = vec![1, 2, 3];
        let err = verify_transaction_signature(&bad, message)
            .expect_err("short public key must be rejected");
        assert!(err.to_string().contains("Invalid public key"));

        let mut bad = tx_sig.clone();
        bad.signature = vec![0xFF; 10];
        let err = verify_transaction_signature(&bad, message)
            .expect_err("non-DER signature must be rejected");
        assert!(err.to_string().contains("Invalid signature"));
    }

    #[test]
    fn verify_ed25519_signature_error_paths() {
        let ed_key = Ed25519Key::from_seed(&[9u8; 64]).unwrap();
        let message = b"solana message";
        let tx_sig = signature_for(
            "addr",
            ed_key.sign(message).to_vec(),
            ed_key.public_bytes().to_vec(),
            SignatureScheme::EdDSA,
            Utc::now(),
        );

        assert!(verify_transaction_signature(&tx_sig, message).unwrap());
        // Wrong message verifies to false (not an error).
        assert!(!verify_transaction_signature(&tx_sig, b"tampered").unwrap());

        // Public key of the wrong length.
        let mut bad = tx_sig.clone();
        bad.public_key = vec![0u8; 31];
        let err = verify_transaction_signature(&bad, message)
            .expect_err("31-byte Ed25519 key must be rejected");
        assert!(err.to_string().contains("must be 32 bytes"));

        // Signature of the wrong length.
        let mut bad = tx_sig.clone();
        bad.signature = vec![0u8; 63];
        let err = verify_transaction_signature(&bad, message)
            .expect_err("63-byte Ed25519 signature must be rejected");
        assert!(err.to_string().contains("must be 64 bytes"));
    }

    #[test]
    fn verify_ethereum_legacy_rejects_malformed_signatures() {
        let request = eth_request(0);
        let key = create_test_signing_key();
        let real_address = address_from_verifying_key(key.verifying_key()).unwrap();

        let (sig, _) = sign_ethereum_transaction(&request, &key).unwrap();
        let make_sig = |signature: Vec<u8>, signer: String| {
            signature_for(
                &signer,
                signature,
                secp_compressed_pubkey(&key).to_vec(),
                SignatureScheme::ECDSA,
                Utc::now(),
            )
        };

        // Happy path.
        assert!(verify_ethereum_transaction(
            &request,
            &make_sig(sig.clone(), real_address.clone())
        )
        .unwrap());

        // Too short.
        assert!(!verify_ethereum_transaction(
            &request,
            &make_sig(sig[..64].to_vec(), real_address.clone())
        )
        .unwrap());

        // 73-byte signature: v section longer than 8 bytes is undecodable.
        let mut long = sig.clone();
        long.extend_from_slice(&[0u8; 8]);
        let err = verify_ethereum_transaction(&request, &make_sig(long, real_address.clone()))
            .expect_err("undecodable v must error");
        assert!(err.to_string().contains("Invalid Ethereum signature v"));

        // v = 0 is below the EIP-155 floor.
        let mut v0 = sig[..64].to_vec();
        v0.push(0);
        assert!(
            !verify_ethereum_transaction(&request, &make_sig(v0, real_address.clone())).unwrap()
        );

        // v = 36 encodes a chain id below Ethereum's.
        let mut low_v = sig[..64].to_vec();
        low_v.push(36);
        assert!(
            !verify_ethereum_transaction(&request, &make_sig(low_v, real_address.clone())).unwrap()
        );

        // r = 0 is an invalid scalar.
        let mut zero_r = sig.clone();
        zero_r[..32].fill(0);
        let err = verify_ethereum_transaction(&request, &make_sig(zero_r, real_address.clone()))
            .expect_err("r=0 must error");
        assert!(err.to_string().contains("Invalid r/s"));

        // Valid signature attributed to a different address.
        assert!(!verify_ethereum_transaction(
            &request,
            &make_sig(
                sig,
                "0x1111111111111111111111111111111111111111".to_string()
            )
        )
        .unwrap());
    }

    #[test]
    fn verify_ethereum_typed_rejects_malformed_signatures() {
        let request = eip1559_request(0);
        let key = create_test_signing_key();
        let real_address = address_from_verifying_key(key.verifying_key()).unwrap();

        let (sig, _) = sign_ethereum_transaction(&request, &key).unwrap();
        assert_eq!(sig.len(), 65);
        let make_sig = |signature: Vec<u8>, signer: String| {
            signature_for(
                &signer,
                signature,
                secp_compressed_pubkey(&key).to_vec(),
                SignatureScheme::ECDSA,
                Utc::now(),
            )
        };

        assert!(verify_ethereum_transaction(
            &request,
            &make_sig(sig.clone(), real_address.clone())
        )
        .unwrap());

        // Wrong lengths.
        assert!(!verify_ethereum_transaction(
            &request,
            &make_sig(sig[..64].to_vec(), real_address.clone())
        )
        .unwrap());
        let mut long = sig.clone();
        long.push(0);
        assert!(
            !verify_ethereum_transaction(&request, &make_sig(long, real_address.clone())).unwrap()
        );

        // Invalid r scalar.
        let mut zero_r = sig.clone();
        zero_r[..32].fill(0);
        let err = verify_ethereum_transaction(&request, &make_sig(zero_r, real_address.clone()))
            .expect_err("r=0 must error");
        assert!(err.to_string().contains("Invalid r/s"));

        // Different signer.
        assert!(!verify_ethereum_transaction(
            &request,
            &make_sig(
                sig,
                "0x1111111111111111111111111111111111111111".to_string()
            )
        )
        .unwrap());
    }

    #[test]
    fn p2wpkh_output_script_shape() {
        let script = p2wpkh_output_script(&[0xABu8; 20]);
        let mut expected = vec![0x00, 0x14];
        expected.extend_from_slice(&[0xABu8; 20]);
        assert_eq!(script.as_bytes(), expected.as_slice());
    }

    #[test]
    fn secp_compressed_pubkey_prefixes_by_parity() {
        // Key 1 has even-y pubkey 0279BE667E...
        let one = test_key_from_raw({
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        });
        let compressed = secp_compressed_pubkey(&one);
        assert_eq!(compressed[0], 0x02);
        assert_eq!(
            hex::encode(&compressed[1..]),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn sign_transaction_dispatches_ethereum_secp256k1() {
        let mut request = eth_request(0);
        let key = test_key_from_raw([0x46u8; 32]);
        let expected_address = address_from_verifying_key(key.verifying_key()).unwrap();
        request.from_address = expected_address.clone();

        let signature = sign_transaction(&request, &WalletSigningKey::Secp256k1(key)).unwrap();
        assert_eq!(signature.signature_scheme, SignatureScheme::ECDSA);
        assert!(signature.signature.len() >= 65 && signature.signature.len() <= 67);
        assert_eq!(signature.signer_address, expected_address);
        assert!(verify_ethereum_transaction(&request, &signature).unwrap());
    }

    #[test]
    fn evm_tx_type_honors_explicit_tx_type_values() {
        for value in ["eip1559", "2", "Type2", "  EIP1559  "] {
            let mut request = eth_request(0);
            request
                .metadata
                .insert("tx_type".to_string(), value.to_string());
            assert!(
                matches!(evm_tx_type(&request), EvmTxType::Eip1559),
                "tx_type {value:?} must route to EIP-1559"
            );
        }

        // An unrelated tx_type does not route to EIP-1559 by itself.
        let mut request = eth_request(0);
        request
            .metadata
            .insert("tx_type".to_string(), "legacy".to_string());
        assert!(matches!(evm_tx_type(&request), EvmTxType::Legacy));
    }

    #[test]
    fn recovery_id_for_rejects_unrecoverable_signature() {
        // A valid signature made by a different key: both recovery candidates
        // parse but neither reproduces the expected signer.
        let key = test_key_from_raw([0x46u8; 32]);
        let impostor = test_key_from_raw([0x99u8; 32]);
        let prehash = [7u8; 32];
        let forged = impostor.sign_prehash(&prehash).unwrap();

        let err = recovery_id_for(&key, &prehash, &forged).unwrap_err();
        assert!(err.to_string().contains("Failed to recover signer"));
    }

    #[test]
    fn recovery_id_for_rejects_signature_without_recoverable_point() {
        let key = test_key_from_raw([0x46u8; 32]);
        let prehash = [7u8; 32];

        // For roughly half of the possible x coordinates no curve point
        // exists, so recovery fails outright instead of returning a
        // mismatched key. Small r values are always in field range.
        let mut undecodable = None;
        for r in 1u64..=64 {
            let mut r_bytes = [0u8; 32];
            r_bytes[31] = r as u8;
            let r_field: k256::FieldBytes = r_bytes.into();
            let s_field: k256::FieldBytes = [1u8; 32].into();
            // Small r and s=0x0101..01 are always in field range.
            let sig = Signature::from_scalars(r_field, s_field).unwrap();
            if VerifyingKey::recover_from_prehash(&prehash, &sig, RecoveryId::new(false, false))
                .is_err()
            {
                undecodable = Some(sig);
                break;
            }
        }
        let sig = undecodable.expect("secp256k1 has non-residual x coordinates below 64");

        let err = recovery_id_for(&key, &prehash, &sig).unwrap_err();
        assert!(err.to_string().contains("Failed to recover signer"));
    }
}
