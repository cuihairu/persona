// Multi-chain address generation from public keys

use crate::crypto::bech32::{decode_witness_address, encode_witness_address};
use crate::crypto::wallet_crypto::DerivedKey;
use crate::{PersonaError, PersonaResult};
use k256::elliptic_curve::{sec1::ToEncodedPoint, FieldBytes, ScalarPrimitive};
use k256::{ProjectivePoint, PublicKey, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Bitcoin address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinAddressType {
    /// Legacy P2PKH (starts with 1)
    P2PKH,
    /// P2SH-P2WPKH nested SegWit (starts with 3)
    P2SHP2WPKH,
    /// Native SegWit P2WPKH (starts with bc1q)
    P2WPKH,
    /// Taproot P2TR (starts with bc1p)
    P2TR,
}

/// Generate Bitcoin address from derived key
pub fn generate_bitcoin_address(
    key: &DerivedKey,
    address_type: BitcoinAddressType,
    testnet: bool,
) -> PersonaResult<String> {
    let pubkey_bytes = key.public_key_bytes();

    match address_type {
        BitcoinAddressType::P2PKH => generate_p2pkh_address(&pubkey_bytes, testnet),
        BitcoinAddressType::P2SHP2WPKH => generate_p2sh_p2wpkh_address(&pubkey_bytes, testnet),
        BitcoinAddressType::P2WPKH => generate_p2wpkh_address(&pubkey_bytes, testnet),
        BitcoinAddressType::P2TR => generate_p2tr_address(&pubkey_bytes, testnet),
    }
}

/// Generate Bitcoin address directly from a compressed secp256k1 public key.
pub fn generate_bitcoin_address_from_compressed_pubkey(
    pubkey: &[u8; 33],
    address_type: BitcoinAddressType,
    testnet: bool,
) -> PersonaResult<String> {
    match address_type {
        BitcoinAddressType::P2PKH => generate_p2pkh_address(pubkey, testnet),
        BitcoinAddressType::P2SHP2WPKH => generate_p2sh_p2wpkh_address(pubkey, testnet),
        BitcoinAddressType::P2WPKH => generate_p2wpkh_address(pubkey, testnet),
        BitcoinAddressType::P2TR => generate_p2tr_address(pubkey, testnet),
    }
}

/// hash160 = RIPEMD160(SHA256(data)), the hash used by Bitcoin addresses.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    Ripemd160::digest(sha256_hash).into()
}

/// Generate P2PKH (Pay-to-Public-Key-Hash) address
fn generate_p2pkh_address(pubkey: &[u8; 33], testnet: bool) -> PersonaResult<String> {
    // Add version byte (0x00 for mainnet, 0x6f for testnet)
    let version = if testnet { 0x6f } else { 0x00 };
    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(&hash160(pubkey));

    // Base58Check encoding
    Ok(base58_check_encode(&payload))
}

/// Generate P2SH-P2WPKH address (BIP-49).
///
/// The redeem script is `OP_0 <20-byte key hash>` and the address is the
/// hash160 of that script, so it is spendable with the standard nested
/// SegWit witness.
fn generate_p2sh_p2wpkh_address(pubkey: &[u8; 33], testnet: bool) -> PersonaResult<String> {
    let witness_program = hash160(pubkey);
    let mut redeem_script = Vec::with_capacity(22);
    redeem_script.push(0x00); // OP_0
    redeem_script.push(0x14); // push 20 bytes
    redeem_script.extend_from_slice(&witness_program);

    let version = if testnet { 0xc4 } else { 0x05 };
    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(&hash160(&redeem_script));

    Ok(base58_check_encode(&payload))
}

/// Generate Native SegWit (Bech32) P2WPKH address
fn generate_p2wpkh_address(pubkey: &[u8; 33], testnet: bool) -> PersonaResult<String> {
    let hrp = if testnet { "tb" } else { "bc" };

    // Bech32 encoding (witness version 0)
    encode_witness_address(hrp, 0, &hash160(pubkey))
}

/// Generate Taproot (Bech32m) P2TR address per BIP-86.
///
/// The output key is the BIP-341 tweak of the internal key with an empty
/// Merkle root: `Q = P + t*G` where `t = tagged_hash("TapTweak", x-only P)`.
fn generate_p2tr_address(pubkey: &[u8; 33], testnet: bool) -> PersonaResult<String> {
    let x_only = tweak_pubkey_taproot(pubkey)?;
    let hrp = if testnet { "tb" } else { "bc" };

    // Bech32m encoding (witness version 1)
    encode_witness_address(hrp, 1, &x_only)
}

/// Apply the BIP-341/TIP BIP-86 `TapTweak` to a compressed internal key and
/// return the 32-byte x-only output key.
pub fn tweak_pubkey_taproot(pubkey: &[u8; 33]) -> PersonaResult<[u8; 32]> {
    if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
        return Err(PersonaError::Cryptography(
            "Taproot tweak requires a compressed secp256k1 pubkey".to_string(),
        ));
    }
    let x_only = &pubkey[1..];
    let tweak = tagged_hash(b"TapTweak", x_only);
    // BIP-341: the tweak is reduced mod n; a value >= n is astronomically
    // unlikely for a hash output, but rejecting it matches the spec's "fail"
    // condition without silently wrapping.
    let tweak_bytes: &FieldBytes<k256::Secp256k1> =
        k256::elliptic_curve::generic_array::GenericArray::from_slice(&tweak);
    let tweak_primitive = ScalarPrimitive::<k256::Secp256k1>::from_bytes(tweak_bytes)
        .into_option()
        .ok_or_else(|| PersonaError::Cryptography("TapTweak out of range (t >= n)".to_string()))?;
    let tweak_scalar = Scalar::from(tweak_primitive);

    // from_sec1_bytes recovers the full point (including y parity), but the
    // BIP-340 x-only internal key is interpreted as the even-y point, so an
    // odd-y (0x03) key must be negated before tweaking.
    let internal_key = PublicKey::from_sec1_bytes(pubkey)
        .map_err(|_| PersonaError::Cryptography("Invalid internal key for taproot".to_string()))?;
    let internal_point = {
        let p = ProjectivePoint::from(&internal_key);
        if pubkey[0] == 0x03 {
            -p
        } else {
            p
        }
    };

    let output_point = internal_point + ProjectivePoint::GENERATOR * tweak_scalar;
    let encoded = output_point.to_affine().to_encoded_point(false);
    let bytes: [u8; 65] = encoded.as_bytes().try_into().map_err(|_| {
        PersonaError::Cryptography("Failed to encode tweaked taproot key".to_string())
    })?;

    Ok(bytes[1..33].try_into().expect("65-byte uncompressed key"))
}

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// Generate Ethereum address from public key
pub fn generate_ethereum_address(key: &DerivedKey) -> PersonaResult<String> {
    let pubkey_bytes = key.public_key_bytes();

    let uncompressed = uncompress_secp256k1_pubkey(&pubkey_bytes)?;

    generate_ethereum_address_from_uncompressed_pubkey(&uncompressed)
}

/// Generate EIP-55 checksummed Ethereum address
pub fn generate_ethereum_address_checksummed(key: &DerivedKey) -> PersonaResult<String> {
    let address = generate_ethereum_address(key)?;
    Ok(apply_eip55_checksum(&address))
}

/// Generate EIP-55 checksummed Ethereum address from a compressed secp256k1 public key.
pub fn generate_ethereum_address_checksummed_from_compressed_pubkey(
    compressed: &[u8; 33],
) -> PersonaResult<String> {
    let uncompressed = uncompress_secp256k1_pubkey(compressed)?;
    let address = generate_ethereum_address_from_uncompressed_pubkey(&uncompressed)?;
    Ok(apply_eip55_checksum(&address))
}

fn generate_ethereum_address_from_uncompressed_pubkey(
    uncompressed: &[u8],
) -> PersonaResult<String> {
    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        return Err(PersonaError::Cryptography(
            "Invalid uncompressed secp256k1 pubkey".to_string(),
        ));
    }

    let hash = Keccak256::digest(&uncompressed[1..]);
    let address_bytes = &hash[12..];
    Ok(format!("0x{}", hex::encode(address_bytes)))
}

fn apply_eip55_checksum(address: &str) -> String {
    let address_lower = address.trim_start_matches("0x").to_lowercase();

    // Keccak256 hash of lowercase address
    let hash = Keccak256::digest(address_lower.as_bytes());
    let hash_hex = hex::encode(hash);

    // Apply EIP-55 checksum
    let mut checksummed = String::from("0x");
    for (i, c) in address_lower.chars().enumerate() {
        if c.is_ascii_digit() {
            checksummed.push(c);
        } else {
            let hash_char = hash_hex.chars().nth(i).unwrap();
            if hash_char >= '8' {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c);
            }
        }
    }

    checksummed
}

/// Generate Solana address (base58-encoded Ed25519 public key)
pub fn generate_solana_address(pubkey_bytes: &[u8]) -> PersonaResult<String> {
    if pubkey_bytes.len() != 32 {
        return Err(PersonaError::Cryptography(
            "Solana requires 32-byte Ed25519 public key".to_string(),
        ));
    }

    Ok(bs58::encode(pubkey_bytes).into_string())
}

// Helper functions

/// Base58Check encoding (Bitcoin-style)
fn base58_check_encode(payload: &[u8]) -> String {
    // Calculate checksum (first 4 bytes of double SHA256)
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    let checksum = &hash2[..4];

    // Concatenate payload and checksum
    let mut data = payload.to_vec();
    data.extend_from_slice(checksum);

    bs58::encode(data).into_string()
}

/// Base58Check decode, returning the payload without version/checksum.
pub fn base58_check_decode(encoded: &str) -> PersonaResult<Vec<u8>> {
    let data = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid base58 address: {}", e)))?;
    if data.len() < 5 {
        return Err(PersonaError::InvalidInput(
            "Base58 address too short".to_string(),
        ));
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    if &hash2[..4] != checksum {
        return Err(PersonaError::InvalidInput(
            "Base58 address checksum mismatch".to_string(),
        ));
    }
    Ok(payload.to_vec())
}

/// Uncompress secp256k1 public key
fn uncompress_secp256k1_pubkey(compressed: &[u8; 33]) -> PersonaResult<Vec<u8>> {
    let pubkey = PublicKey::from_sec1_bytes(compressed)
        .map_err(|e| PersonaError::Cryptography(format!("Invalid compressed pubkey: {}", e)))?;

    let uncompressed = pubkey.to_encoded_point(false);
    Ok(uncompressed.as_bytes().to_vec())
}

/// Validate Bitcoin address format (P2PKH/P2SH base58 or bech32/bech32m SegWit)
pub fn validate_bitcoin_address(address: &str) -> bool {
    if address.starts_with("bc1") || address.starts_with("tb1") || address.starts_with("BC1") {
        decode_witness_address(address).is_ok()
    } else {
        match base58_check_decode(address) {
            Ok(payload) => {
                // mainnet 0x00/0x05, testnet 0x6f/0xc4
                matches!(payload[0], 0x00 | 0x05 | 0x6f | 0xc4) && payload.len() == 21
            }
            Err(_) => false,
        }
    }
}

/// Validate Ethereum address format
pub fn validate_ethereum_address(address: &str) -> bool {
    if !address.starts_with("0x") {
        return false;
    }

    let addr = &address[2..];
    addr.len() == 40 && addr.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate Solana address format
pub fn validate_solana_address(address: &str) -> bool {
    // Solana addresses are 32-44 characters base58
    if address.len() < 32 || address.len() > 44 {
        return false;
    }

    match bs58::decode(address).into_vec() {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wallet_crypto::{
        Bip44PathBuilder, CoinType, MasterKey, MnemonicWordCount, SecureMnemonic,
    };

    /// The canonical BIP39 test mnemonic used by BIP-84/86 vectors.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn master_from_test_mnemonic() -> MasterKey {
        let mnemonic = SecureMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
        MasterKey::from_mnemonic(&mnemonic, "").unwrap()
    }

    #[test]
    fn test_bitcoin_address_generation() {
        let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words12).unwrap();
        let master = MasterKey::from_mnemonic(&mnemonic, "").unwrap();

        let path = Bip44PathBuilder::new(CoinType::Bitcoin).build();
        let key = master.derive_path(&path).unwrap();

        let address = generate_bitcoin_address(&key, BitcoinAddressType::P2PKH, false).unwrap();
        assert!(validate_bitcoin_address(&address));
        assert!(address.starts_with('1'));
    }

    #[test]
    fn test_ethereum_address_generation() {
        let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words12).unwrap();
        let master = MasterKey::from_mnemonic(&mnemonic, "").unwrap();

        let path = Bip44PathBuilder::new(CoinType::Ethereum).build();
        let key = master.derive_path(&path).unwrap();

        let address = generate_ethereum_address_checksummed(&key).unwrap();
        assert!(validate_ethereum_address(&address));
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_address_validation() {
        assert!(validate_bitcoin_address(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        ));
        assert!(validate_bitcoin_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
        // checksum-valid P2SH mainnet address
        assert!(validate_bitcoin_address(
            "3P14159f73E4gFr7JterCCQh9QjiTjiZrG"
        ));
        assert!(!validate_bitcoin_address("invalid"));

        assert!(validate_ethereum_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
        ));
        assert!(!validate_ethereum_address(
            "742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
        ));
        assert!(!validate_ethereum_address("0xInvalid"));
    }

    // BIP-84 test vector: first native SegWit receiving address
    #[test]
    fn test_bip84_p2wpkh_vector() {
        let master = master_from_test_mnemonic();
        let key = master.derive_path("m/84'/0'/0'/0/0").unwrap();
        let address = generate_bitcoin_address(&key, BitcoinAddressType::P2WPKH, false).unwrap();
        assert_eq!(address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    // BIP-49-style nested SegWit must hash the redeem script, not the pubkey
    #[test]
    fn test_p2sh_p2wpkh_hashes_redeem_script() {
        let master = master_from_test_mnemonic();
        let key = master.derive_path("m/84'/0'/0'/0/0").unwrap();
        let pubkey = key.public_key_bytes();

        let address =
            generate_bitcoin_address(&key, BitcoinAddressType::P2SHP2WPKH, false).unwrap();
        assert!(address.starts_with('3'));
        assert!(validate_bitcoin_address(&address));

        // Reconstruct the redeem script independently and compare hashes
        let witness_program = hash160(&pubkey);
        let mut redeem_script = vec![0x00, 0x14];
        redeem_script.extend_from_slice(&witness_program);
        let mut payload = vec![0x05];
        payload.extend_from_slice(&hash160(&redeem_script));
        assert_eq!(address, base58_check_encode(&payload));
    }

    // BIP-86 test vector: first taproot receiving address
    #[test]
    fn test_bip86_p2tr_vector() {
        let master = master_from_test_mnemonic();
        let key = master.derive_path("m/86'/0'/0'/0/0").unwrap();
        let address = generate_bitcoin_address(&key, BitcoinAddressType::P2TR, false).unwrap();
        assert_eq!(
            address,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    // BIP-86 test vector: the tweaked output key itself
    #[test]
    fn test_bip86_tweaked_output_key() {
        let master = master_from_test_mnemonic();
        let key = master.derive_path("m/86'/0'/0'/0/0").unwrap();
        let tweaked = tweak_pubkey_taproot(&key.public_key_bytes()).unwrap();
        assert_eq!(
            hex::encode(tweaked),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
    }

    #[test]
    fn test_solana_address_validation() {
        let valid = bs58::encode([7u8; 32]).into_string();
        assert!(validate_solana_address(&valid));
        let short = bs58::encode([7u8; 31]).into_string();
        assert!(!validate_solana_address(&short));
    }

    #[test]
    fn test_validate_bitcoin_address_rejects_tampered_base58() {
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let mut tampered = addr.to_string();
        tampered.replace_range(3..4, if addr.as_bytes()[3] == b'z' { "y" } else { "z" });
        // A random swap may or may not keep base58 validity, but the checksum
        // must fail either way (or the address decodes as unchanged).
        if tampered != addr {
            assert!(!validate_bitcoin_address(&tampered));
        }
    }
}
