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

use super::{secp_compressed_pubkey, RawSignedTransaction};
use crate::models::wallet::{SignatureScheme, TransactionRequest};
use crate::{PersonaError, PersonaResult};
use bitcoin::absolute::LockTime;
use bitcoin::amount::Amount;
use bitcoin::consensus::serialize as consensus_serialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Network, OutPoint, ScriptBuf, Sequence, Txid};
use k256::ecdsa::{
    signature::{hazmat::PrehashSigner, DigestSigner, SignatureEncoding},
    Signature, SigningKey,
};
use sha2::{Digest, Sha256};

pub(super) const SIGHASH_ALL: u8 = 0x01;
pub(super) const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

/// Sign Bitcoin transaction (audit signature over Persona's internal
/// sighash scheme; not a broadcastable Bitcoin transaction).
pub(super) fn sign_bitcoin_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<(Vec<u8>, SignatureScheme)> {
    let sighash = create_bitcoin_sighash(request)?;
    let signature = sign_with_secp256k1(signing_key, &sighash)?;

    // Bitcoin uses DER-encoded signatures
    let der_signature = signature.to_der().to_vec();

    Ok((der_signature, SignatureScheme::ECDSA))
}

/// Sign using secp256k1 (ECDSA)
pub(super) fn sign_with_secp256k1(
    signing_key: &SigningKey,
    message: &[u8],
) -> PersonaResult<Signature> {
    // signature 3.0 的 DigestSigner 改收 Fn(&mut D) 闭包
    Ok(signing_key.sign_digest(|d: &mut Sha256| d.update(message)))
}

/// Create Bitcoin sighash for the audit signature (internal scheme).
pub(super) fn create_bitcoin_sighash(request: &TransactionRequest) -> PersonaResult<[u8; 32]> {
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

/// A segwit transaction input as provided by the caller.
#[derive(Debug, Clone)]
pub(crate) struct BtcInput {
    pub(super) outpoint: OutPoint,
    /// Prevout value in satoshis (required by BIP-143).
    pub(crate) amount: u64,
    pub(super) sequence: Sequence,
}

pub(super) fn parse_satoshis(value: &str, field: &str) -> PersonaResult<u64> {
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
pub(super) fn parse_btc_inputs(request: &TransactionRequest) -> PersonaResult<Vec<BtcInput>> {
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
pub(super) fn script_pubkey_for_address(address: &str) -> PersonaResult<ScriptBuf> {
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
pub(crate) fn p2wpkh_output_script(pubkey_hash: &[u8; 20]) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(22);
    bytes.extend_from_slice(&[0x00, 0x14]);
    bytes.extend_from_slice(pubkey_hash);
    ScriptBuf::from_bytes(bytes)
}

/// Shared P2WPKH spend construction for the direct-sign
/// ([`build_bitcoin_raw_transaction`]) and PSBT
/// ([`crate::crypto::transaction_psbt`]) paths: parse the UTXO inputs,
/// validate `from_address` as a native P2WPKH output (optionally pinned to
/// the signing key's hash), and assemble the unsigned transaction per the
/// metadata contract below.
///
/// Metadata contract:
/// - `inputs`: JSON array of `{txid, vout, amount}` (satoshis)
/// - `change_address`: optional; receives `sum(inputs) - amount - fee`.
///   Without it, inputs must exactly equal `amount + fee` so no value is
///   silently burned.
/// - `locktime`: optional u32 (default 0); `rbf`: "true" enables BIP-125
///   replace-by-fee signalling.
///
/// Returns `(unsigned transaction, parsed inputs, from_address witness script)`.
pub(crate) fn build_p2wpkh_transaction(
    request: &TransactionRequest,
    expected_pubkey_hash: Option<&[u8; 20]>,
) -> PersonaResult<(Transaction, Vec<BtcInput>, ScriptBuf)> {
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

    // Guard against spending funds from an address we don't control.
    if let Some(expected) = expected_pubkey_hash {
        if *expected != program.as_slice() {
            return Err(PersonaError::InvalidInput(
                "from_address does not match the signing key".to_string(),
            ));
        }
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

    let tx = Transaction {
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

    let mut program20 = [0u8; 20];
    program20.copy_from_slice(&program);
    let witness_script = p2wpkh_output_script(&program20);
    Ok((tx, inputs, witness_script))
}

/// Build the broadcastable segwit (BIP-141) transaction spending the given
/// P2WPKH prevouts, signed with SIGHASH_ALL.
///
/// Only P2WPKH inputs (native segwit, BIP-84 addresses) can be signed.
/// `from_address` must be the address of the signing key.
pub fn build_bitcoin_raw_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<RawSignedTransaction> {
    use crate::crypto::address_generator::hash160;

    let pubkey = secp_compressed_pubkey(signing_key);
    let pubkey_hash = hash160(&pubkey);

    let (mut tx, inputs, witness_script) = build_p2wpkh_transaction(request, Some(&pubkey_hash))?;

    // Sign each input (BIP-143 P2WPKH, SIGHASH_ALL) via rust-bitcoin's
    // sighash implementation.
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
