// Multi-chain transaction signing module.
//
// Implemented chains:
// - Ethereum & EVM L2s: legacy EIP-155 transactions (RLP + keccak256),
//   producing a broadcastable raw signed transaction.
// - Solana: Ed25519 signing over a serialized message (e.g. the output of
//   `Transaction::serialize_message()`), producing a wire-format signed
//   transaction with a single signature.
//
// Bitcoin signing is intentionally limited: `sign_transaction` returns a
// real secp256k1 signature over Persona's internal sighash scheme (useful
// for audits and `verify_transaction_signature`), but `build_raw_transaction`
// refuses to assemble a Bitcoin transaction until full PSBT support lands.

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
        BlockchainNetwork::Bitcoin => Err(PersonaError::InvalidInput(
            "Bitcoin raw transaction assembly (PSBT) is not yet implemented; \
             only the audit signature is available via sign_transaction"
                .to_string(),
        )),
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
            let raw = build_eip155_raw_transaction(request, k)?;
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

/// Sign an Ethereum transaction (EIP-155 legacy).
///
/// Returns `r || s || v` where `v = 35 + 2*chain_id + recovery_id`.
fn sign_ethereum_transaction(
    request: &TransactionRequest,
    signing_key: &SigningKey,
) -> PersonaResult<(Vec<u8>, SignatureScheme)> {
    let (r, s, v) = sign_eip155(request, signing_key)?;
    let mut eth_signature = Vec::with_capacity(65);
    eth_signature.extend_from_slice(&r);
    eth_signature.extend_from_slice(&s);
    eth_signature.extend_from_slice(&minimal_be_bytes(v));
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

/// Recompute the EIP-155 signing hash for `request` and check that the
/// signature recovers `signer_address`.
pub fn verify_ethereum_transaction(
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
    fn test_bitcoin_raw_transaction_refused() {
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
        // ...but raw assembly is honestly refused until PSBT support lands.
        assert!(build_raw_transaction(&request, &key).is_err());
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
}
