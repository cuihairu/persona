// BIP-174 PSBT workflow for single-signature P2WPKH spends.
//
// The export/sign/finalize trio mirrors the airgapped signing workflow:
// export an unsigned PSBT on an online (or watch-only) wallet, carry the
// base64 blob to the key-holding machine, sign the inputs owned by that
// wallet, bring the signed PSBT back and finalize it into the raw
// broadcastable transaction. rust-bitcoin supplies the BIP-174 wire format,
// the sighash machinery and `Psbt::combine` for multi-party merging; the
// P2WPKH finalization step is ours (the crate no longer ships a finalizer).

use crate::crypto::address_generator::hash160;
use crate::crypto::transaction_signing::{
    build_p2wpkh_transaction, p2wpkh_output_script, RawSignedTransaction,
};
use crate::models::wallet::TransactionRequest;
use crate::{PersonaError, PersonaResult};
use bitcoin::amount::Amount;
use bitcoin::consensus::serialize as consensus_serialize;
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::TxOut;
use bitcoin::{PublicKey as BtcPublicKey, Witness};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::Signature as K256Signature;
use k256::ecdsa::SigningKey;

/// Build an unsigned PSBT (BIP-174) for a single-sig P2WPKH spend using the
/// same request shape and metadata contract as
/// [`build_bitcoin_raw_transaction`](crate::crypto::transaction_signing::build_bitcoin_raw_transaction).
///
/// No signing key is required: `from_address` only needs to be a valid
/// mainnet P2WPKH address, so watch-only wallets can prepare the artifact
/// for an airgapped signer. Ownership is enforced when the PSBT is signed.
pub fn export_bitcoin_psbt(request: &TransactionRequest) -> PersonaResult<Vec<u8>> {
    let (tx, inputs, witness_script) = build_p2wpkh_transaction(request, None)?;

    let mut psbt = Psbt::from_unsigned_tx(tx)
        .map_err(|e| PersonaError::InvalidInput(format!("Cannot wrap transaction in PSBT: {e}")))?;
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(inputs[index].amount),
            // For P2WPKH the prevout script equals the witness script.
            script_pubkey: witness_script.clone(),
        });
        input.witness_script = Some(witness_script.clone());
        input.sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
    }
    Ok(psbt.serialize())
}

/// Sign every input of the PSBT whose witness script belongs to
/// `signing_key` (single-sig: all inputs must be ours), recording the
/// signatures as BIP-174 partial signatures without finalizing.
///
/// Returns the re-serialized PSBT; combining signatures from multiple
/// devices can later go through [`Psbt::combine`].
pub fn sign_bitcoin_psbt(psbt_bytes: &[u8], signing_key: &SigningKey) -> PersonaResult<Vec<u8>> {
    let mut psbt = Psbt::deserialize(psbt_bytes)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid PSBT: {e}")))?;

    let pubkey = signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let mut pubkey_hash = [0u8; 20];
    pubkey_hash.copy_from_slice(&hash160(&pubkey));
    let expected_script = p2wpkh_output_script(&pubkey_hash);

    let mut cache = SighashCache::new(&mut psbt.unsigned_tx);
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!(
                    "PSBT input {index} has no witness_script; only P2WPKH inputs are supported"
                ))
            })?
            .clone();
        if witness_script != expected_script {
            return Err(PersonaError::InvalidInput(format!(
                "PSBT input {index} does not belong to this wallet's key (witness script mismatch)"
            )));
        }
        let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
            PersonaError::InvalidInput(format!("PSBT input {index} has no witness_utxo"))
        })?;
        let sighash = cache
            .p2wpkh_signature_hash(
                index,
                witness_script.as_script(),
                utxo.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| {
                PersonaError::InvalidInput(format!("Cannot sign PSBT input {index}: {e}"))
            })?;
        let signature: K256Signature = signing_key.sign_prehash(&sighash.to_byte_array())?;
        let der = signature.to_der();
        let secp_signature = bitcoin::secp256k1::ecdsa::Signature::from_der(der.as_bytes())
            .map_err(|e| PersonaError::CryptographicError(format!("PSBT signature: {e}")))?;
        let secp_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pubkey)
            .map_err(|e| PersonaError::CryptographicError(format!("wallet public key: {e}")))?;
        input.partial_sigs.insert(
            BtcPublicKey::new(secp_pubkey),
            bitcoin::ecdsa::Signature::sighash_all(secp_signature),
        );
    }

    Ok(psbt.serialize())
}

/// Finalize a signed PSBT: for each input, promote its single partial
/// signature (SIGHASH_ALL) into the final script witness and extract the
/// raw broadcastable transaction. Only single-signature P2WPKH inputs are
/// supported; inputs with zero or multiple partial signatures are refused.
pub fn finalize_bitcoin_psbt(psbt_bytes: &[u8]) -> PersonaResult<RawSignedTransaction> {
    let mut psbt = Psbt::deserialize(psbt_bytes)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid PSBT: {e}")))?;

    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        if input.final_script_witness.is_some() {
            continue;
        }
        if input.final_script_sig.is_some() {
            return Err(PersonaError::InvalidInput(format!(
                "PSBT input {index} carries a legacy final script_sig; only P2WPKH \
                 witness finalization is supported"
            )));
        }
        if input.partial_sigs.len() != 1 {
            return Err(PersonaError::InvalidInput(format!(
                "PSBT input {index} has {} partial signature(s); finalization requires \
                 exactly one (single-signature P2WPKH)",
                input.partial_sigs.len()
            )));
        }
        let (pubkey, signature) = input.partial_sigs.iter().next().expect("len checked == 1");
        if signature.sighash_type != EcdsaSighashType::All {
            return Err(PersonaError::InvalidInput(
                "only SIGHASH_ALL partial signatures can be finalized".to_string(),
            ));
        }
        let witness_items = [signature.serialize().to_vec(), pubkey.to_bytes()];
        input.final_script_witness = Some(Witness::from_slice(&witness_items));
        input.partial_sigs.clear();
    }

    let tx = psbt
        .extract_tx()
        .map_err(|e| PersonaError::InvalidInput(format!("PSBT is not complete: {e}")))?;
    Ok(RawSignedTransaction {
        raw: consensus_serialize(&tx),
        // compute_txid hashes the stripped (witness-free) serialization,
        // matching what explorers display.
        hash: tx.compute_txid().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::wallet::BlockchainNetwork;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use std::collections::HashMap;

    fn test_key(raw: [u8; 32]) -> SigningKey {
        SigningKey::from_slice(&raw).unwrap()
    }

    fn p2wpkh_address(compressed_pubkey: &[u8; 33]) -> String {
        crate::crypto::address_generator::generate_bitcoin_address_from_compressed_pubkey(
            compressed_pubkey,
            crate::crypto::address_generator::BitcoinAddressType::P2WPKH,
            false,
        )
        .unwrap()
    }

    fn btc_request(
        key: &SigningKey,
        to_address: String,
        amount: &str,
        fee: &str,
        txids: [String; 2],
    ) -> TransactionRequest {
        let pubkey = key.verifying_key().to_sec1_point(true);
        let from_address = p2wpkh_address(pubkey.as_bytes().try_into().unwrap());
        let inputs_json = format!(
            r#"[
            {{"txid":"{}","vout":0,"amount":"100000"}},
            {{"txid":"{}","vout":1,"amount":"200000"}}
        ]"#,
            txids[0], txids[1]
        );
        TransactionRequest {
            id: uuid::Uuid::new_v4(),
            wallet_id: uuid::Uuid::new_v4(),
            network: BlockchainNetwork::Bitcoin,
            from_address,
            to_address,
            amount: amount.to_string(),
            fee: fee.to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: None,
            raw_transaction_data: None,
            required_signatures: 1,
            created_at: chrono::Utc::now(),
            expires_at: None,
            metadata: HashMap::from([("inputs".to_string(), inputs_json)]),
        }
    }

    fn recipient_address() -> String {
        crate::crypto::address_generator::generate_bitcoin_address_from_compressed_pubkey(
            &[0x02u8; 33],
            crate::crypto::address_generator::BitcoinAddressType::P2WPKH,
            false,
        )
        .unwrap()
    }

    /// Two placeholder 64-hex txids for the input metadata.
    fn fake_txids() -> [String; 2] {
        ["11".repeat(32), "22".repeat(32)]
    }

    /// The end-to-end anchor: same request through the direct-signing path
    /// and the PSBT path (export → sign → finalize) must produce
    /// byte-identical raw transactions and txids (k256 signing is
    /// deterministic RFC-6979, so both paths sign identical sighashes).
    #[test]
    fn psbt_roundtrip_matches_direct_signing() {
        use crate::crypto::transaction_signing::build_bitcoin_raw_transaction;

        let key = test_key([0x42; 32]);
        let request = btc_request(&key, recipient_address(), "280000", "20000", fake_txids());

        let direct = build_bitcoin_raw_transaction(&request, &key).unwrap();

        let unsigned = export_bitcoin_psbt(&request).unwrap();
        let signed = sign_bitcoin_psbt(&unsigned, &key).unwrap();
        let finalized = finalize_bitcoin_psbt(&signed).unwrap();

        assert_eq!(finalized.raw, direct.raw);
        assert_eq!(finalized.hash, direct.hash);
    }

    #[test]
    fn exported_psbt_is_deterministic_deserializable_and_complete() {
        let key = test_key([0x42; 32]);
        let request = btc_request(&key, recipient_address(), "280000", "20000", fake_txids());

        let first = export_bitcoin_psbt(&request).unwrap();
        let second = export_bitcoin_psbt(&request).unwrap();
        assert_eq!(first, second, "PSBT export must be deterministic");

        let psbt = Psbt::deserialize(&first).unwrap();
        assert_eq!(psbt.inputs.len(), 2);
        assert_eq!(psbt.outputs.len(), 1);
        assert!(psbt.inputs.iter().all(|i| {
            i.witness_utxo.is_some()
                && i.witness_script.is_some()
                && i.sighash_type == Some(PsbtSighashType::from(EcdsaSighashType::All))
        }));
        // No signatures yet: signing is a separate step.
        assert!(psbt.inputs.iter().all(|i| i.partial_sigs.is_empty()));

        // The unsigned tx inside the PSBT is a valid v2 transaction whose
        // txid equals the final (post-finalization) txid — signing never
        // changes the stripped serialization.
        let unsigned_txid = psbt.unsigned_tx.compute_txid();
        let signed = sign_bitcoin_psbt(&first, &key).unwrap();
        let finalized = finalize_bitcoin_psbt(&signed).unwrap();
        assert_eq!(finalized.hash, unsigned_txid.to_string());
    }

    #[test]
    fn signed_psbt_carries_partial_sigs_and_reserializes() {
        let key = test_key([0x42; 32]);
        let request = btc_request(&key, recipient_address(), "280000", "20000", fake_txids());
        let unsigned = export_bitcoin_psbt(&request).unwrap();

        let signed_bytes = sign_bitcoin_psbt(&unsigned, &key).unwrap();
        let psbt = Psbt::deserialize(&signed_bytes).unwrap();
        for input in &psbt.inputs {
            assert_eq!(input.partial_sigs.len(), 1);
            let (pk, sig) = input.partial_sigs.iter().next().unwrap();
            assert_eq!(
                pk.to_bytes().as_slice(),
                key.verifying_key().to_sec1_point(true).as_bytes()
            );
            assert_eq!(sig.sighash_type, EcdsaSighashType::All);
            assert!(
                input.final_script_witness.is_none(),
                "sign must not finalize"
            );
        }

        // Round-trip: the signed PSBT re-serializes losslessly.
        assert_eq!(
            sign_bitcoin_psbt(&signed_bytes, &key).unwrap(),
            signed_bytes
        );
    }

    #[test]
    fn sign_rejects_psbt_from_a_foreign_key() {
        let owner = test_key([0x42; 32]);
        let stranger = test_key([0x07; 32]);
        let request = btc_request(&owner, recipient_address(), "280000", "20000", fake_txids());
        let unsigned = export_bitcoin_psbt(&request).unwrap();

        let err = sign_bitcoin_psbt(&unsigned, &stranger).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not belong to this wallet's key"));
    }

    #[test]
    fn finalize_rejects_unsigned_and_foreign_sigset_inputs() {
        let key = test_key([0x42; 32]);
        let request = btc_request(&key, recipient_address(), "280000", "20000", fake_txids());

        // Zero signatures: nothing to finalize.
        let unsigned = export_bitcoin_psbt(&request).unwrap();
        let err = finalize_bitcoin_psbt(&unsigned).unwrap_err();
        assert!(err.to_string().contains("partial signature(s)"));

        // A PSBT finalized by hand for a DIFFERENT key must be refused by
        // the signer and therefore never reaches a valid finalization.
        let stranger = test_key([0x07; 32]);
        assert!(sign_bitcoin_psbt(&unsigned, &stranger).is_err());
    }

    #[test]
    fn invalid_psbt_bytes_are_rejected_with_the_magic_check() {
        // Wrong magic.
        let err = finalize_bitcoin_psbt(b"not a psbt at all........").unwrap_err();
        assert!(err.to_string().contains("Invalid PSBT"));
        assert!(sign_bitcoin_psbt(b"psbt\xff\xff\xff", &test_key([1; 32])).is_err());

        // Export refuses the same malformed requests as the direct path.
        let key = test_key([0x42; 32]);
        let mut request = btc_request(&key, recipient_address(), "280000", "20000", fake_txids());
        request.metadata.remove("inputs");
        let err = export_bitcoin_psbt(&request).unwrap_err();
        assert!(err.to_string().contains("inputs"));
    }

    #[test]
    fn unsigned_transaction_shape_is_preserved() {
        let key = test_key([0x42; 32]);
        let request = btc_request(&key, recipient_address(), "280000", "20000", fake_txids());
        let bytes = export_bitcoin_psbt(&request).unwrap();
        let psbt = Psbt::deserialize(&bytes).unwrap();

        // version 2, locktime 0, two empty-script inputs, one output of
        // 280000 sats — exactly what the direct path would assemble.
        assert_eq!(psbt.unsigned_tx.version, Version::TWO);
        assert_eq!(psbt.unsigned_tx.lock_time, LockTime::from_consensus(0));
        assert_eq!(psbt.unsigned_tx.input.len(), 2);
        assert!(psbt
            .unsigned_tx
            .input
            .iter()
            .all(|i| i.script_sig.is_empty()));
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
        assert_eq!(psbt.unsigned_tx.output[0].value, Amount::from_sat(280_000));
    }
}
