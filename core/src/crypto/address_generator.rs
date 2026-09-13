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

/// Apply the EIP-55 mixed-case checksum via `alloy-primitives`.
fn apply_eip55_checksum(address: &str) -> String {
    match address.parse::<alloy_primitives::Address>() {
        Ok(addr) => addr.to_checksum(None),
        // Callers pass internally-generated 0x-prefixed addresses; fall back
        // to the input rather than panicking on malformed strings.
        Err(_) => address.to_string(),
    }
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

/// Base58Check encoding (Bitcoin-style), delegated to bs58's `check` support.
fn base58_check_encode(payload: &[u8]) -> String {
    bs58::encode(payload).with_check().into_string()
}

/// Base58Check decode, returning the payload including the version byte
/// (checksum verified by bs58).
pub fn base58_check_decode(encoded: &str) -> PersonaResult<Vec<u8>> {
    let data = bs58::decode(encoded)
        .with_check(None)
        .into_vec()
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid base58 address: {}", e)))?;
    if data.is_empty() {
        return Err(PersonaError::InvalidInput(
            "Base58 address too short".to_string(),
        ));
    }
    Ok(data)
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

    #[test]
    fn test_testnet_address_generation() {
        let key = {
            let mnemonic = SecureMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
            let master = MasterKey::from_mnemonic(&mnemonic, "").unwrap();
            master.derive_path("m/84'/1'/0'/0/0").unwrap()
        };

        let p2pkh = generate_bitcoin_address(&key, BitcoinAddressType::P2PKH, true).unwrap();
        assert!(p2pkh.starts_with('m') || p2pkh.starts_with('n'));
        assert!(validate_bitcoin_address(&p2pkh));

        let p2sh = generate_bitcoin_address(&key, BitcoinAddressType::P2SHP2WPKH, true).unwrap();
        assert!(p2sh.starts_with('2'));
        assert!(validate_bitcoin_address(&p2sh));

        let p2wpkh = generate_bitcoin_address(&key, BitcoinAddressType::P2WPKH, true).unwrap();
        assert!(p2wpkh.starts_with("tb1q"));
        assert!(validate_bitcoin_address(&p2wpkh));

        let p2tr = generate_bitcoin_address(&key, BitcoinAddressType::P2TR, true).unwrap();
        assert!(p2tr.starts_with("tb1p"));
        assert!(validate_bitcoin_address(&p2tr));
    }

    #[test]
    fn test_from_compressed_pubkey_matches_derived_key_path() {
        let master = master_from_test_mnemonic();
        let key = master.derive_path("m/84'/0'/0'/0/0").unwrap();
        let pubkey = key.public_key_bytes();

        for address_type in [
            BitcoinAddressType::P2PKH,
            BitcoinAddressType::P2SHP2WPKH,
            BitcoinAddressType::P2WPKH,
            BitcoinAddressType::P2TR,
        ] {
            let via_key = generate_bitcoin_address(&key, address_type, false).unwrap();
            let via_pubkey =
                generate_bitcoin_address_from_compressed_pubkey(&pubkey, address_type, false)
                    .unwrap();
            assert_eq!(via_key, via_pubkey);
            assert!(validate_bitcoin_address(&via_pubkey));
        }
    }

    #[test]
    fn test_taproot_tweak_rejects_uncompressed_and_invalid_keys() {
        // 0x04 prefix is not a compressed key.
        let err =
            tweak_pubkey_taproot(&[0x04u8; 33]).expect_err("uncompressed prefix must be rejected");
        assert!(err.to_string().contains("compressed secp256k1 pubkey"));

        // 0x02 prefix but not a valid curve point.
        let mut invalid = [0x02u8; 33];
        invalid[1..].fill(0xFF); // x = n-1 region is not a valid x-only key
        assert!(tweak_pubkey_taproot(&invalid).is_err());

        // Odd-y (0x03) vs even-y (0x02) forms of the same x-only key: BIP-340
        // semantics interpret the internal key as the even-y point either way,
        // so both compressed forms must tweak to the same output key.
        let master = master_from_test_mnemonic();
        let key = master.derive_path("m/86'/0'/0'/0/0").unwrap();
        let mut even = key.public_key_bytes();
        even[0] = 0x02;
        let mut odd = even;
        odd[0] = 0x03;
        assert_ne!(even[0], odd[0]);
        assert_eq!(
            tweak_pubkey_taproot(&even).unwrap(),
            tweak_pubkey_taproot(&odd).unwrap(),
            "x-only tweak must be parity-independent"
        );
    }

    #[test]
    fn test_ethereum_address_variants_agree() {
        let master = master_from_test_mnemonic();
        let key = master.derive_path("m/44'/60'/0'/0/0").unwrap();

        // Plain (no EIP-55 checksum) vs checksummed.
        let plain = generate_ethereum_address(&key).unwrap();
        let checksummed = generate_ethereum_address_checksummed(&key).unwrap();
        assert!(plain.starts_with("0x"));
        assert_eq!(plain.len(), 42);
        assert_eq!(plain.to_lowercase(), checksummed.to_lowercase());
        // The checksum casing must differ from all-lowercase for this address,
        // or EIP-55 would be a no-op.
        assert_eq!(plain, plain.to_lowercase());
        assert_ne!(plain, checksummed);

        // The compressed-pubkey entry point produces the same address.
        let via_pubkey =
            generate_ethereum_address_checksummed_from_compressed_pubkey(&key.public_key_bytes())
                .unwrap();
        assert_eq!(via_pubkey, checksummed);
    }

    #[test]
    fn test_solana_address_rejects_wrong_length() {
        let err = generate_solana_address(&[7u8; 31]).expect_err("31-byte pubkey must be rejected");
        assert!(err.to_string().contains("32-byte Ed25519 public key"));
        assert!(generate_solana_address(&[7u8; 33]).is_err());
        assert!(generate_solana_address(&[]).is_err());
    }

    #[test]
    fn test_base58_check_decode_rejects_bad_input() {
        assert!(base58_check_decode("").is_err());
        assert!(base58_check_decode("not base58!").is_err());
        // Valid base58 characters but broken checksum.
        assert!(base58_check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb").is_err());

        // Round-trip through the encoder used by the address functions.
        let payload = {
            let mut p = vec![0x00u8];
            p.extend_from_slice(&hash160(&[1u8; 33]));
            p
        };
        let encoded = bs58::encode(&payload).with_check().into_string();
        assert_eq!(base58_check_decode(&encoded).unwrap(), payload);
    }

    #[test]
    fn test_validate_bitcoin_address_accepts_uppercase_mainnet_prefix() {
        // Upper-case Bech32 is valid per BIP-173 (decoders must accept it).
        // Note: the prefix dispatch only special-cases "BC1"; an upper-case
        // "TB1..." falls through to the base58 branch and is rejected.
        assert!(validate_bitcoin_address(
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
        ));
    }

    #[test]
    fn test_validate_bitcoin_address_rejects_known_version_bytes() {
        // Checksum-valid base58 with a non-Bitcoin version byte (Litecoin
        // P2PKH 0x30) must be rejected.
        let mut payload = vec![0x30u8];
        payload.extend_from_slice(&hash160(&[2u8; 33]));
        let ltc_style = bs58::encode(&payload).with_check().into_string();
        assert!(!validate_bitcoin_address(&ltc_style));

        // Checksum-valid base58 with a too-short payload (version + 19 bytes).
        let mut short_payload = vec![0x00u8];
        short_payload.extend_from_slice(&[1u8; 19]);
        let short = bs58::encode(&short_payload).with_check().into_string();
        assert!(!validate_bitcoin_address(&short));
    }

    #[test]
    fn test_validate_ethereum_address_length_and_hex_checks() {
        assert!(validate_ethereum_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
        ));
        // 39 and 41 hex chars are invalid.
        assert!(!validate_ethereum_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
        ));
        assert!(!validate_ethereum_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb00"
        ));
        // Non-hex payload.
        assert!(!validate_ethereum_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbG"
        ));
        // Empty string.
        assert!(!validate_ethereum_address(""));
    }

    #[test]
    fn test_validate_solana_address_boundaries() {
        // 32 random bytes encode to 43-44 base58 chars.
        let max_len = bs58::encode([0xFFu8; 32]).into_string();
        assert_eq!(max_len.len(), 44);
        assert!(validate_solana_address(&max_len));

        // 32 zero bytes encode to a short (32-char) but valid address.
        let all_zero = bs58::encode([0u8; 32]).into_string();
        assert_eq!(all_zero.len(), 32);
        assert!(validate_solana_address(&all_zero));

        // 44 chars decoding to the wrong byte count is rejected.
        let long_44 = "11111111111111111111111111111111111111111111";
        assert_eq!(long_44.len(), 44);
        assert!(!validate_solana_address(long_44));

        // Base58-invalid characters (0, O, I, l) are rejected.
        assert!(!validate_solana_address(
            "0OIl0000000000000000000000000000000000000000"
        ));

        // Length bounds: 31 and 45 chars.
        assert!(!validate_solana_address(&"a".repeat(31)));
        assert!(!validate_solana_address(&"a".repeat(45)));
    }

    #[test]
    fn test_hash160_matches_double_digest_composition() {
        let data = b"hash160 composition check";
        let expected = ripemd::Ripemd160::digest(Sha256::digest(data));
        assert_eq!(hash160(data), expected.as_slice());
    }
}
