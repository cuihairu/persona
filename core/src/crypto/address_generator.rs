// Multi-chain address generation from public keys

use crate::crypto::wallet_crypto::DerivedKey;
use crate::{PersonaError, PersonaResult};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Bitcoin address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinAddressType {
    /// Legacy P2PKH (starts with 1)
    P2PKH,
    /// P2SH (starts with 3)
    P2SH,
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
        BitcoinAddressType::P2SH => generate_p2sh_address(&pubkey_bytes, testnet),
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
        BitcoinAddressType::P2SH => generate_p2sh_address(pubkey, testnet),
        BitcoinAddressType::P2WPKH => generate_p2wpkh_address(pubkey, testnet),
        BitcoinAddressType::P2TR => generate_p2tr_address(pubkey, testnet),
    }
}

/// Generate P2PKH (Pay-to-Public-Key-Hash) address
fn generate_p2pkh_address(pubkey: &[u8; 33], testnet: bool) -> PersonaResult<String> {
    // SHA256 then RIPEMD160
    let sha256_hash = Sha256::digest(pubkey);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);

    // Add version byte (0x00 for mainnet, 0x6f for testnet)
    let version = if testnet { 0x6f } else { 0x00 };
    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(&ripemd_hash);

    // Base58Check encoding
    Ok(base58_check_encode(&payload))
}

/// Generate P2SH address (simplified - actual P2SH requires redeem script)
fn generate_p2sh_address(pubkey: &[u8; 33], testnet: bool) -> PersonaResult<String> {
    // For demonstration: wrap in a simple P2SH script
    // Real implementation would need actual redeem script
    let sha256_hash = Sha256::digest(pubkey);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);

    let version = if testnet { 0xc4 } else { 0x05 };
    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(&ripemd_hash);

    Ok(base58_check_encode(&payload))
}

/// Generate Native SegWit (Bech32) address
fn generate_p2wpkh_address(pubkey: &[u8; 33], testnet: bool) -> PersonaResult<String> {
    let sha256_hash = Sha256::digest(pubkey);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);

    let hrp = if testnet { "tb" } else { "bc" };

    // Bech32 encoding (witness version 0)
    bech32_encode(hrp, 0, &ripemd_hash)
}

/// Generate Taproot address (simplified)
fn generate_p2tr_address(pubkey: &[u8; 33], testnet: bool) -> PersonaResult<String> {
    // Taproot uses x-only pubkey (32 bytes)
    let x_only_pubkey = &pubkey[1..]; // Remove compression prefix

    let hrp = if testnet { "tb" } else { "bc" };

    // Bech32m encoding (witness version 1)
    bech32_encode(hrp, 1, x_only_pubkey)
}

/// Generate Ethereum address from public key
pub fn generate_ethereum_address(key: &DerivedKey) -> PersonaResult<String> {
    let pubkey_bytes = key.public_key_bytes();

    // Remove the compression prefix (0x02 or 0x03) to get uncompressed key
    // For Ethereum, we need the full 64-byte uncompressed public key
    // This is simplified - real implementation needs proper uncompression
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

fn generate_ethereum_address_from_uncompressed_pubkey(uncompressed: &[u8]) -> PersonaResult<String> {
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
    let hash2 = Sha256::digest(&hash1);
    let checksum = &hash2[..4];

    // Concatenate payload and checksum
    let mut data = payload.to_vec();
    data.extend_from_slice(checksum);

    bs58::encode(data).into_string()
}

/// Bech32/Bech32m encoding (simplified)
fn bech32_encode(hrp: &str, witness_version: u8, witness_program: &[u8]) -> PersonaResult<String> {
    // This is a simplified version - production code should use proper bech32 library
    // For now, return a placeholder format
    Ok(format!(
        "{}1q{}{}",
        hrp,
        witness_version,
        bs58::encode(witness_program).into_string().to_lowercase()
    ))
}

/// Uncompress secp256k1 public key (simplified)
fn uncompress_secp256k1_pubkey(compressed: &[u8; 33]) -> PersonaResult<Vec<u8>> {
    use k256::PublicKey;

    let pubkey = PublicKey::from_sec1_bytes(compressed)
        .map_err(|e| PersonaError::Cryptography(format!("Invalid compressed pubkey: {}", e)))?;

    let uncompressed = pubkey.to_encoded_point(false);
    Ok(uncompressed.as_bytes().to_vec())
}

/// Validate Bitcoin address format
pub fn validate_bitcoin_address(address: &str) -> bool {
    // Simplified validation
    if address.starts_with("bc1") || address.starts_with("tb1") {
        // Bech32 address
        address.len() >= 14 && address.len() <= 90
    } else if address.starts_with('1')
        || address.starts_with('3')
        || address.starts_with('m')
        || address.starts_with('n')
        || address.starts_with('2')
    {
        // Base58 address
        address.len() >= 26 && address.len() <= 35
    } else {
        false
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

    bs58::decode(address).into_vec().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wallet_crypto::{
        Bip44PathBuilder, CoinType, MasterKey, MnemonicWordCount, SecureMnemonic,
    };

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
        assert!(!validate_bitcoin_address("invalid"));

        assert!(validate_ethereum_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
        ));
        assert!(!validate_ethereum_address(
            "742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
        ));
        assert!(!validate_ethereum_address("0xInvalid"));
    }
}
