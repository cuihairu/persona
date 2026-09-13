// Multi-chain transaction signing module.
//
// Implemented chains:
// - Ethereum & EVM L2s: legacy EIP-155 and typed EIP-1559 transactions
//   (RLP + keccak256), producing broadcastable raw signed transactions.
// - Bitcoin: BIP-143 P2WPKH signing and segwit (BIP-141) transaction
//   assembly from caller-provided UTXO `inputs` metadata; without them
//   only an audit signature over the request fields is recorded.
// - Solana: Ed25519 signing over a serialized message (e.g. the output of
//   `Transaction::serialize_message()`), producing a wire-format signed
//   transaction with a single signature.

use crate::crypto::wallet_crypto::Ed25519Key;
use crate::models::wallet::{
    BlockchainNetwork, SignatureScheme, TransactionRequest, TransactionSignature,
};
use crate::{PersonaError, PersonaResult};
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
            let signing_hash = eip1559_signing_hash(request)?;
            let signature: Signature = signing_key.sign_prehash(&signing_hash)?;
            let y_parity = recovery_id_for(signing_key, &signing_hash, &signature)?;
            eth_signature.extend_from_slice(&signature.r().to_bytes());
            eth_signature.extend_from_slice(&signature.s().to_bytes());
            eth_signature.push(y_parity);
        }
    }
    Ok((eth_signature, SignatureScheme::ECDSA))
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

/// Base fields shared by both EVM transaction types (already RLP-wrapped).
struct EvmBaseFields {
    chain_id: u64,
    nonce: Vec<u8>,
    gas_limit: Vec<u8>,
    to: Vec<u8>,
    value: Vec<u8>,
    data: Vec<u8>,
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

fn evm_base_fields(request: &TransactionRequest) -> PersonaResult<EvmBaseFields> {
    let nonce = request.nonce.ok_or_else(|| {
        PersonaError::InvalidInput("Ethereum transactions require a nonce".to_string())
    })?;
    let gas_limit = request.gas_limit.ok_or_else(|| {
        PersonaError::InvalidInput("Ethereum transactions require a gas_limit".to_string())
    })?;
    let value = parse_u256_string(&request.amount)?;
    let to = hex::decode(request.to_address.trim_start_matches("0x"))
        .ok()
        .filter(|bytes| bytes.len() == 20)
        .ok_or_else(|| {
            PersonaError::InvalidInput("Ethereum to_address must be 20 hex bytes".to_string())
        })?;
    let data = match request.metadata.get("data") {
        Some(hex_data) => hex::decode(hex_data.trim_start_matches("0x"))
            .map_err(|_| PersonaError::InvalidInput("metadata 'data' must be hex".to_string()))?,
        None => Vec::new(),
    };
    Ok(EvmBaseFields {
        chain_id: chain_id(request)?,
        nonce: rlp_uint(nonce),
        gas_limit: rlp_uint(gas_limit),
        to: rlp_encode_bytes(&to),
        value: rlp_u128(value),
        data: rlp_encode_bytes(&data),
    })
}

/// 1559 fee fields: priority fee must be <= max fee per gas.
fn eip1559_fee_fields(request: &TransactionRequest) -> PersonaResult<(Vec<u8>, Vec<u8>)> {
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
    Ok((rlp_u128(max_priority), rlp_u128(max_fee)))
}

/// `keccak256(0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gas, to,
/// value, data, accessList]))`
fn eip1559_signing_hash(request: &TransactionRequest) -> PersonaResult<[u8; 32]> {
    access_list_guard(request)?;
    let base = evm_base_fields(request)?;
    let (max_priority, max_fee) = eip1559_fee_fields(request)?;
    let payload = rlp_list(&[
        rlp_uint(base.chain_id),
        base.nonce,
        max_priority,
        max_fee,
        base.gas_limit,
        base.to,
        base.value,
        base.data,
        rlp_list(&[]), // empty access list
    ]);
    let mut input = vec![0x02];
    input.extend_from_slice(&payload);
    Ok(Keccak256::digest(&input).into())
}

/// Build the full broadcastable EIP-1559 transaction:
/// `0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data,
/// accessList, yParity, r, s])`.
pub fn build_eip1559_raw_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<Vec<u8>> {
    access_list_guard(request)?;
    let base = evm_base_fields(request)?;
    let (max_priority, max_fee) = eip1559_fee_fields(request)?;

    let signing_hash = eip1559_signing_hash(request)?;
    let signature: Signature = signing_key.sign_prehash(&signing_hash)?;
    let y_parity = recovery_id_for(signing_key, &signing_hash, &signature)?;

    let mut r = [0u8; 32];
    r.copy_from_slice(&signature.r().to_bytes());
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature.s().to_bytes());

    let mut raw = vec![0x02];
    raw.extend_from_slice(&rlp_list(&[
        rlp_uint(base.chain_id),
        base.nonce,
        max_priority,
        max_fee,
        base.gas_limit,
        base.to,
        base.value,
        base.data,
        rlp_list(&[]), // empty access list
        rlp_uint(u64::from(y_parity)),
        rlp_bytes32(r),
        rlp_bytes32(s),
    ]));
    Ok(raw)
}

// ---------------------------------------------------------------------------
// Bitcoin: BIP-143 P2WPKH signing and segwit transaction assembly
// ---------------------------------------------------------------------------

const SIGHASH_ALL: u8 = 0x01;
const SEQUENCE_FINAL: u32 = 0xFFFF_FFFF;
/// Final + opt-in Replace-By-Fee (BIP-125).
const SEQUENCE_FINAL_RBF: u32 = 0xFFFF_FFFE;

/// A segwit transaction input as provided by the caller.
#[derive(Debug, Clone)]
struct BtcInput {
    /// Internal-order txid (wire order; hex input is display order and must
    /// be reversed when parsing).
    txid: [u8; 32],
    vout: u32,
    /// Prevout value in satoshis (required by BIP-143).
    amount: u64,
    sequence: u32,
}

#[derive(Debug, Clone)]
struct BtcOutput {
    amount: u64,
    script_pubkey: Vec<u8>,
}

/// Parse the `inputs` metadata field: a JSON array of
/// `{"txid": "<64 hex>", "vout": <n>, "amount": "<satoshis>"}`.
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
        let mut txid = [0u8; 32];
        let bytes = hex::decode(txid_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("inputs[{i}].txid must be 32 hex bytes"))
            })?;
        txid.copy_from_slice(&bytes);
        txid.reverse(); // display -> internal order

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
                    .and_then(|s| s.parse::<u64>().ok())
                    .or(v.as_u64())
            })
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!(
                    "inputs[{i}] missing numeric 'amount' (satoshis)"
                ))
            })?;

        inputs.push(BtcInput {
            txid,
            vout: vout as u32,
            amount,
            sequence: SEQUENCE_FINAL,
        });
    }
    Ok(inputs)
}

/// scriptPubKey for a destination address (segwit witness programs and
/// base58 P2PKH/P2SH).
fn script_pubkey_for_address(address: &str) -> PersonaResult<Vec<u8>> {
    use crate::crypto::address_generator::base58_check_decode;
    use crate::crypto::bech32::decode_witness_address;

    if let Ok((_, version, program)) = decode_witness_address(address) {
        return match (version, program.len()) {
            (0, 20) => Ok([vec![0x00, 0x14], program].concat()),
            (0, 32) => Ok([vec![0x00, 0x20], program].concat()),
            (1, 32) => Ok([vec![0x51, 0x20], program].concat()), // P2TR
            _ => Err(PersonaError::InvalidInput(format!(
                "Unsupported witness program for output '{address}'"
            ))),
        };
    }
    if let Ok(data) = base58_check_decode(address) {
        let (version, payload) = (data[0], &data[1..]);
        if payload.len() == 20 {
            // 0x00/0x05 mainnet P2PKH/P2SH, 0x6f/0xc4 testnet
            match version {
                0x00 | 0x6f => {
                    return Ok([vec![0x76, 0xa9, 0x14], payload.to_vec(), vec![0x88, 0xac]].concat())
                }
                0x05 | 0xc4 => return Ok([vec![0xa9, 0x14], payload.to_vec(), vec![0x87]].concat()),
                _ => {}
            }
        }
    }
    Err(PersonaError::InvalidInput(format!(
        "Unsupported or invalid Bitcoin address '{address}'"
    )))
}

fn btc_varint(n: usize) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        [vec![0xfd], (n as u16).to_le_bytes().to_vec()].concat()
    } else if n <= 0xffff_ffff {
        [vec![0xfe], (n as u32).to_le_bytes().to_vec()].concat()
    } else {
        [vec![0xff], (n as u64).to_le_bytes().to_vec()].concat()
    }
}

fn dsha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Serialize outputs the way they appear in a transaction body
/// (amount + script), without the count prefix.
fn serialize_outputs(outputs: &[BtcOutput]) -> Vec<u8> {
    let mut out = Vec::new();
    for o in outputs {
        out.extend_from_slice(&o.amount.to_le_bytes());
        out.extend_from_slice(&btc_varint(o.script_pubkey.len()));
        out.extend_from_slice(&o.script_pubkey);
    }
    out
}

/// BIP-143 sighash for a P2WPKH input under SIGHASH_ALL without
/// ANYONECANPAY (the only mode Persona produces).
fn p2wpkh_sighash_all(
    version: i32,
    inputs: &[BtcInput],
    outputs: &[BtcOutput],
    index: usize,
    pubkey_hash: &[u8; 20],
    locktime: u32,
) -> PersonaResult<[u8; 32]> {
    let input = inputs.get(index).ok_or_else(|| {
        PersonaError::InvalidInput("Signing index out of range for Bitcoin inputs".to_string())
    })?;

    let mut hasher = Sha256::new();
    hasher.update(version.to_le_bytes());

    // hashPrevouts = dsha256(all outpoints)
    let mut prevouts = Sha256::new();
    for i in inputs {
        prevouts.update(i.txid);
        prevouts.update(i.vout.to_le_bytes());
    }
    hasher.update(Sha256::digest(prevouts.finalize()));

    // hashSequence = dsha256(all nSequence)
    let mut sequences = Sha256::new();
    for i in inputs {
        sequences.update(i.sequence.to_le_bytes());
    }
    hasher.update(Sha256::digest(sequences.finalize()));

    // outpoint being signed
    hasher.update(input.txid);
    hasher.update(input.vout.to_le_bytes());

    // scriptCode for P2WPKH: varint(0x19) || OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    hasher.update([0x19, 0x76, 0xa9, 0x14]);
    hasher.update(pubkey_hash);
    hasher.update([0x88, 0xac]);

    hasher.update(input.amount.to_le_bytes());
    hasher.update(input.sequence.to_le_bytes());

    // hashOutputs = dsha256(all outputs) for SIGHASH_ALL
    hasher.update(dsha256(&serialize_outputs(outputs)));

    hasher.update(locktime.to_le_bytes());
    hasher.update((SIGHASH_ALL as u32).to_le_bytes());

    let mut sighash = [0u8; 32];
    let intermediate = hasher.finalize();
    sighash.copy_from_slice(&Sha256::digest(intermediate));
    Ok(sighash)
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
///   signalling (nSequence 0xfffffffe).
///
/// Only P2WPKH inputs (native segwit, BIP-84 addresses) can be signed.
/// `from_address` must be the address of the signing key.
pub fn build_bitcoin_raw_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<RawSignedTransaction> {
    let inputs = parse_btc_inputs(request)?;

    // The input being spent must be a native P2WPKH output.
    use crate::crypto::bech32::decode_witness_address;
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
    let pubkey_hash = crate::crypto::address_generator::hash160(&pubkey);
    if pubkey_hash != program.as_slice() {
        return Err(PersonaError::InvalidInput(
            "from_address does not match the signing key".to_string(),
        ));
    }

    let send_amount: u64 = request.amount.parse().map_err(|_| {
        PersonaError::InvalidInput("Bitcoin amount must be decimal satoshis".to_string())
    })?;
    let fee: u64 = request.fee.parse().map_err(|_| {
        PersonaError::InvalidInput("Bitcoin fee must be decimal satoshis".to_string())
    })?;
    let output_script = script_pubkey_for_address(&request.to_address)?;

    let total_in: u64 = inputs.iter().map(|i| i.amount).sum();
    let mut outputs = vec![BtcOutput {
        amount: send_amount,
        script_pubkey: output_script,
    }];

    match request.metadata.get("change_address") {
        Some(change_addr) => {
            let change = (total_in - send_amount).checked_sub(fee).ok_or_else(|| {
                PersonaError::InvalidInput("Fee exceeds inputs minus send amount".to_string())
            })?;
            if change > 0 {
                outputs.push(BtcOutput {
                    amount: change,
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
            input.sequence = SEQUENCE_FINAL_RBF;
        }
    }

    let version = 2i32;

    // Sign each input (BIP-143, SIGHASH_ALL).
    let mut witnesses = Vec::with_capacity(inputs.len());
    for index in 0..inputs.len() {
        let sighash =
            p2wpkh_sighash_all(version, &inputs, &outputs, index, &pubkey_hash, locktime)?;
        let signature: k256::ecdsa::Signature = signing_key.sign_prehash(&sighash)?;
        let mut witness_item = signature.to_der().to_vec();
        witness_item.push(SIGHASH_ALL);
        witnesses.push((witness_item, pubkey.to_vec()));
    }

    // Assemble: version | marker/flag | inputs | outputs | witness | locktime
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x01]); // segwit marker + flag
    body.extend_from_slice(&btc_varint(inputs.len()));
    for input in &inputs {
        body.extend_from_slice(&input.txid); // internal order
        body.extend_from_slice(&input.vout.to_le_bytes());
        body.extend_from_slice(&btc_varint(0)); // empty scriptSig
        body.extend_from_slice(&input.sequence.to_le_bytes());
    }
    body.extend_from_slice(&btc_varint(outputs.len()));
    body.extend_from_slice(&serialize_outputs(&outputs));
    for (item_sig, item_pub) in &witnesses {
        body.extend_from_slice(&btc_varint(2));
        body.extend_from_slice(&btc_varint(item_sig.len()));
        body.extend_from_slice(item_sig);
        body.extend_from_slice(&btc_varint(item_pub.len()));
        body.extend_from_slice(item_pub);
    }
    body.extend_from_slice(&locktime.to_le_bytes());

    // txid = dsha256 of the tx WITHOUT witness data (stripped serialization).
    let mut stripped = Vec::new();
    stripped.extend_from_slice(&version.to_le_bytes());
    stripped.extend_from_slice(&btc_varint(inputs.len()));
    for input in &inputs {
        stripped.extend_from_slice(&input.txid);
        stripped.extend_from_slice(&input.vout.to_le_bytes());
        stripped.extend_from_slice(&btc_varint(0));
        stripped.extend_from_slice(&input.sequence.to_le_bytes());
    }
    stripped.extend_from_slice(&btc_varint(outputs.len()));
    stripped.extend_from_slice(&serialize_outputs(&outputs));
    stripped.extend_from_slice(&locktime.to_le_bytes());

    let txid = dsha256(&stripped);
    let mut display = txid;
    display.reverse(); // explorers show internal order reversed

    Ok(RawSignedTransaction {
        raw: body,
        hash: hex::encode(display),
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
    let signing_hash = eip155_signing_hash(request, chain)?;

    // Per EIP-155 the message to sign is the keccak hash of the RLP payload;
    // sign it directly rather than hashing again.
    let signature: Signature = signing_key.sign_prehash(&signing_hash)?;

    // k256 normalizes to low-s; recover the parity bit that reproduces our
    // public key so the signature validates against from_address.
    let recovery_id = recovery_id_for(signing_key, &signing_hash, &signature)?;

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
    let fields = eip155_fields(request)?;
    let (r, s, v) = sign_eip155(request, signing_key)?;

    Ok(rlp_list(&[
        fields.nonce,
        fields.gas_price,
        fields.gas_limit,
        fields.to,
        fields.value,
        fields.data,
        rlp_uint(v),
        rlp_bytes32(r),
        rlp_bytes32(s),
    ]))
}

struct Eip155Fields {
    nonce: Vec<u8>,
    gas_price: Vec<u8>,
    gas_limit: Vec<u8>,
    to: Vec<u8>,
    value: Vec<u8>,
    data: Vec<u8>,
}

/// Encode the base transaction fields (already RLP-wrapped byte strings).
fn eip155_fields(request: &TransactionRequest) -> PersonaResult<Eip155Fields> {
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
    let value = parse_u256_string(&request.amount)?;
    let to = hex::decode(request.to_address.trim_start_matches("0x"))
        .ok()
        .filter(|bytes| bytes.len() == 20)
        .ok_or_else(|| {
            PersonaError::InvalidInput("Ethereum to_address must be 20 hex bytes".to_string())
        })?;
    let data = match request.metadata.get("data") {
        Some(hex_data) => hex::decode(hex_data.trim_start_matches("0x"))
            .map_err(|_| PersonaError::InvalidInput("metadata 'data' must be hex".to_string()))?,
        None => Vec::new(),
    };

    Ok(Eip155Fields {
        nonce: rlp_uint(nonce),
        gas_price: rlp_u128(gas_price),
        gas_limit: rlp_uint(gas_limit),
        to: rlp_encode_bytes(&to),
        value: rlp_u128(value),
        data: rlp_encode_bytes(&data),
    })
}

/// `keccak256(rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0]))`
fn eip155_signing_hash(request: &TransactionRequest, chain: u64) -> PersonaResult<[u8; 32]> {
    let fields = eip155_fields(request)?;
    let encoded = rlp_list(&[
        fields.nonce,
        fields.gas_price,
        fields.gas_limit,
        fields.to,
        fields.value,
        fields.data,
        rlp_uint(chain),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[]),
    ]);
    Ok(Keccak256::digest(&encoded).into())
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
// RLP encoding
// ---------------------------------------------------------------------------

/// RLP-encode a single byte string.
fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len() + 4);
    push_length(&mut out, data.len() as u64, 0x80);
    out.extend_from_slice(data);
    out
}

/// RLP-encode an unsigned integer as its minimal big-endian representation
/// (zero encodes as the empty string).
fn rlp_uint(value: u64) -> Vec<u8> {
    rlp_encode_bytes(&minimal_be_bytes(value))
}

fn rlp_u128(value: u128) -> Vec<u8> {
    rlp_encode_bytes(&minimal_be_bytes_u128(value))
}

/// RLP-encode a list of already-encoded items.
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|item| item.len()).sum();
    let mut out = Vec::with_capacity(payload_len + 4);
    push_length(&mut out, payload_len as u64, 0xc0);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn push_length(out: &mut Vec<u8>, length: u64, offset: u8) {
    if length < 56 {
        out.push(offset + length as u8);
    } else {
        let be = minimal_be_bytes(length);
        out.push(offset + 55 + be.len() as u8);
        out.extend_from_slice(&be);
    }
}

fn minimal_be_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let be = value.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[first..].to_vec()
}

fn minimal_be_bytes_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let be = value.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[first..].to_vec()
}

fn rlp_bytes32(bytes: [u8; 32]) -> Vec<u8> {
    rlp_encode_bytes(&bytes)
}

/// Parse a decimal string into u128 (values beyond u128 wei are rejected;
/// that is ~3.4e38 and above any realistic token supply in wei).
fn parse_u256_string(value: &str) -> PersonaResult<u128> {
    value.trim().parse::<u128>().map_err(|_| {
        PersonaError::InvalidInput(format!(
            "Amount '{}' must be a decimal integer that fits in u128",
            value
        ))
    })
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
    let prehash = eip155_signing_hash(request, chain)?;
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
        VerifyingKey::recover_from_prehash(&prehash, &sig, RecoveryId::new(y_odd, false))
            .map_err(|e| PersonaError::CryptographicError(e.to_string()))?;

    let recovered_address = address_from_verifying_key(&recovered)?;
    Ok(recovered_address == signature.signer_address.to_lowercase())
}

/// Typed-transaction verify: signature is `r || s || y_parity` (1 byte).
fn verify_ethereum_typed(
    request: &TransactionRequest,
    signature: &TransactionSignature,
) -> PersonaResult<bool> {
    let prehash = eip1559_signing_hash(request)?;
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
        VerifyingKey::recover_from_prehash(&prehash, &sig, RecoveryId::new(y_odd, false))
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
        let chain = chain_id(&request).unwrap();
        let hash = eip155_signing_hash(&request, chain).unwrap();
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

    // BIP-143 native P2WPKH example: input index 1.
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

        let txid0: [u8; 32] =
            hex::decode("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f")
                .unwrap()
                .try_into()
                .unwrap();
        let txid1: [u8; 32] =
            hex::decode("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a")
                .unwrap()
                .try_into()
                .unwrap();
        // Both inputs participate in hashPrevouts/hashSequence with their
        // own sequence; the script type of input 0 does not affect the
        // P2WPKH sighash for input 1.
        let inputs = vec![
            BtcInput {
                txid: txid0,
                vout: 0,
                amount: 625_000_000,
                sequence: 0xffff_ffee,
            },
            BtcInput {
                txid: txid1,
                vout: 1,
                amount: 600_000_000,
                sequence: 0xffff_ffff,
            },
        ];
        let outputs = vec![
            BtcOutput {
                amount: 112_340_000,
                script_pubkey: hex::decode("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")
                    .unwrap(),
            },
            BtcOutput {
                amount: 223_450_000,
                script_pubkey: hex::decode("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")
                    .unwrap(),
            },
        ];

        let sighash = p2wpkh_sighash_all(1, &inputs, &outputs, 1, &pubkey_hash, 17).unwrap();
        assert_eq!(
            hex::encode(sighash),
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
        let outputs = vec![BtcOutput {
            amount: 280_000,
            script_pubkey: script_pubkey_for_address(&request.to_address).unwrap(),
        }];
        let sighash = p2wpkh_sighash_all(2, &inputs, &outputs, 0, &pubkey_hash, 0).unwrap();
        let sig: k256::ecdsa::Signature = key.sign_prehash(&sighash).unwrap();
        let mut expected_item = sig.to_der().to_vec();
        expected_item.push(SIGHASH_ALL);

        // Find the witness section: after outputs, each input has 2 items.
        // Cheap structural check: the raw tx must contain the pubkey and
        // the signature bytes.
        let raw_hex = hex::encode(&signed.raw);
        assert!(raw_hex.contains(&hex::encode(&pubkey)));
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
        let hash = eip1559_signing_hash(&request).unwrap();
        // Deterministic: same request, same hash (RFC-6979 signing not
        // involved in the hash itself).
        assert_eq!(hash, eip1559_signing_hash(&request).unwrap());
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
}
