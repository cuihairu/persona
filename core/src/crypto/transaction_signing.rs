// Multi-chain transaction signing module
// Supports Bitcoin (PSBT), Ethereum (EIP-1559), and Solana transactions

use crate::crypto::wallet_crypto::DerivedKey;
use crate::models::wallet::{BlockchainNetwork, SignatureScheme, TransactionRequest, TransactionSignature};
use crate::{PersonaError, PersonaResult};
use chrono::Utc;
use k256::ecdsa::{
    signature::{DigestSigner, DigestVerifier, SignatureEncoding},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

// Add conversion from k256::ecdsa::Error to PersonaError
impl From<k256::ecdsa::Error> for PersonaError {
    fn from(err: k256::ecdsa::Error) -> Self {
        PersonaError::CryptographicError(err.to_string())
    }
}

/// Sign a transaction using the appropriate scheme for the network
pub fn sign_transaction(
    request: &TransactionRequest,
    private_key: &DerivedKey,
) -> PersonaResult<TransactionSignature> {
    let (signature, scheme) = match request.network {
        BlockchainNetwork::Bitcoin => sign_bitcoin_transaction(request, private_key)?,
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => sign_ethereum_transaction(request, private_key)?,
        BlockchainNetwork::Solana => sign_solana_transaction(request, private_key)?,
        _ => return Err(PersonaError::InvalidInput("Transaction signing for this network".to_string())),
    };

    Ok(TransactionSignature {
        signer_address: request.from_address.clone(),
        signature: signature.clone(),
        public_key: private_key.public_key_bytes().to_vec(),
        signature_scheme: scheme,
        signed_at: Utc::now(),
    })
}

/// Sign Bitcoin transaction (PSBT)
fn sign_bitcoin_transaction(
    request: &TransactionRequest,
    private_key: &DerivedKey,
) -> PersonaResult<(Vec<u8>, SignatureScheme)> {
    // For demonstration, we'll create a simplified signature
    // In a real implementation, you would:
    // 1. Parse the PSBT (Partially Signed Bitcoin Transaction)
    // 2. Find the inputs to sign
    // 3. Create the sighash for each input
    // 4. Sign with the private key
    // 5. Add the signature to the PSBT

    // Simplified implementation:
    let sighash = create_bitcoin_sighash(request)?;
    let signature = sign_with_secp256k1(private_key, &sighash)?;

    // Bitcoin uses DER-encoded signatures
    let der_signature = signature.to_der().to_vec();

    Ok((der_signature, SignatureScheme::ECDSA))
}

/// Sign Ethereum transaction (EIP-1559)
fn sign_ethereum_transaction(
    request: &TransactionRequest,
    private_key: &DerivedKey,
) -> PersonaResult<(Vec<u8>, SignatureScheme)> {
    // For demonstration, simplified Ethereum transaction signing
    // Real implementation would:
    // 1. Serialize the transaction according to EIP-1559
    // 2. Hash the transaction (Keccak256)
    // 3. Sign with the private key
    // 4. Create the signature with recovery id (v, r, s)

    let eth_hash = create_ethereum_transaction_hash(request)?;
    let signature = sign_with_secp256k1(private_key, &eth_hash)?;

    // Ethereum needs r, s, and v (recovery id)
    let r_bytes = signature.r().to_bytes();
    let s_bytes = signature.s().to_bytes();

    // Recovery id (simplified - real implementation would compute this)
    let recovery_id = 0u8;

    // Combine into Ethereum signature format
    let mut eth_signature = Vec::with_capacity(65);
    eth_signature.extend_from_slice(&r_bytes);
    eth_signature.extend_from_slice(&s_bytes);
    eth_signature.push(recovery_id + 27); // Ethereum v = recovery_id + 27

    Ok((eth_signature, SignatureScheme::ECDSA))
}

/// Sign Solana transaction
fn sign_solana_transaction(
    request: &TransactionRequest,
    private_key: &DerivedKey,
) -> PersonaResult<(Vec<u8>, SignatureScheme)> {
    // Solana uses Ed25519 signatures
    // For demonstration, we'll create a simplified signature
    // Real implementation would:
    // 1. Parse the Solana transaction
    // 2. Verify the message to sign
    // 3. Sign with Ed25519 private key
    // 4. Return the 64-byte signature

    let message = create_solana_message(request)?;
    let signature = sign_with_ed25519(private_key, &message)?;

    Ok((signature.to_vec(), SignatureScheme::EdDSA))
}

/// Create simplified Bitcoin sighash for demonstration
fn create_bitcoin_sighash(request: &TransactionRequest) -> PersonaResult<[u8; 32]> {
    let mut hasher = Sha256::new();

    // Include transaction fields (simplified)
    hasher.update(request.to_address.as_bytes());
    hasher.update(request.from_address.as_bytes());

    // Parse amount and fee as strings to numbers
    if let Ok(amount_u64) = request.amount.parse::<u64>() {
        hasher.update(&amount_u64.to_le_bytes());
    }
    if let Ok(fee_u64) = request.fee.parse::<u64>() {
        hasher.update(&fee_u64.to_le_bytes());
    }

    let hash = hasher.finalize();
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&hash);

    Ok(sighash)
}

/// Create Ethereum transaction hash (simplified EIP-1559)
fn create_ethereum_transaction_hash(request: &TransactionRequest) -> PersonaResult<[u8; 32]> {
    let mut hasher = sha3::Keccak256::new();

    // Include transaction fields (simplified)
    hasher.update(request.from_address.as_bytes());
    hasher.update(request.to_address.as_bytes());

    // Parse amount as string to number
    if let Ok(amount_u128) = request.amount.parse::<u128>() {
        hasher.update(&amount_u128.to_be_bytes());
    }
    if let Some(nonce) = request.nonce {
        hasher.update(&nonce.to_be_bytes());
    }

    let hash = hasher.finalize();
    let mut eth_hash = [0u8; 32];
    eth_hash.copy_from_slice(&hash);

    Ok(eth_hash)
}

/// Create Solana message hash (simplified)
fn create_solana_message(request: &TransactionRequest) -> PersonaResult<[u8; 32]> {
    let mut hasher = Sha256::new();

    // Include transaction fields (simplified)
    hasher.update(request.from_address.as_bytes());
    hasher.update(request.to_address.as_bytes());

    // Parse amount as string to number
    if let Ok(amount_u64) = request.amount.parse::<u64>() {
        hasher.update(&amount_u64.to_le_bytes());
    }

    let hash = hasher.finalize();
    let mut message = [0u8; 32];
    message.copy_from_slice(&hash);

    Ok(message)
}

/// Sign using secp256k1 (ECDSA)
fn sign_with_secp256k1(private_key: &DerivedKey, message: &[u8]) -> PersonaResult<Signature> {
    let signing_key = SigningKey::from_slice(&private_key.private_key_bytes())
        .map_err(|e| PersonaError::CryptographicError(format!("Failed to create signing key: {}", e)))?;

    let digest = Sha256::new().chain_update(message);
    let signature = signing_key.sign_digest(digest);
    Ok(signature)
}

/// Sign using Ed25519
fn sign_with_ed25519(_private_key: &DerivedKey, _message: &[u8]) -> PersonaResult<ed25519_dalek::Signature> {
    // In a real implementation, you would:
    // 1. Convert the private key to Ed25519 format
    // 2. Sign the message
    // For now, return a placeholder signature
    Err(PersonaError::InvalidInput("Ed25519 signing not yet implemented".to_string()))
}

/// Verify a transaction signature
pub fn verify_transaction_signature(
    signature: &TransactionSignature,
    message: &[u8],
) -> PersonaResult<bool> {
    match signature.signature_scheme {
        SignatureScheme::ECDSA => verify_ecdsa_signature(&signature.public_key, &signature.signature, message),
        SignatureScheme::EdDSA => verify_ed25519_signature(&signature.public_key, &signature.signature, message),
        _ => Err(PersonaError::InvalidInput("Signature verification for this scheme".to_string())),
    }
}

/// Verify ECDSA (secp256k1) signature
fn verify_ecdsa_signature(public_key: &[u8], signature: &[u8], message: &[u8]) -> PersonaResult<bool> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| PersonaError::CryptographicError(format!("Invalid public key: {}", e)))?;
    let signature = Signature::from_der(signature)
        .map_err(|e| PersonaError::CryptographicError(format!("Invalid signature: {}", e)))?;

    // Create digest of the message
    let digest = Sha256::new().chain_update(message);

    match verifying_key.verify_digest(digest, &signature) {
        Ok(_) => Ok(true),
        Err(e) => {
            println!("Verification failed: {}", e);
            Ok(false)
        },
    }
}

/// Verify Ed25519 signature
fn verify_ed25519_signature(_public_key: &[u8], _signature: &[u8], _message: &[u8]) -> PersonaResult<bool> {
    // In a real implementation, you would verify using ed25519-dalek
    Err(PersonaError::InvalidInput("Ed25519 verification not yet implemented".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wallet_crypto::MasterKey;
    use bip39::Mnemonic;
    use std::str::FromStr;

    fn create_test_private_key() -> DerivedKey {
        // Create a test mnemonic
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_str(phrase).unwrap();
        let seed = mnemonic.to_seed("");

        // Create master key
        let master_key = MasterKey::from_seed(&seed).unwrap();

        // Derive a child key (simplified path)
        master_key.derive_path("m/44'/0'/0'/0/0").unwrap()
    }

    #[test]
    fn test_bitcoin_transaction_signing() {
        let private_key = create_test_private_key();
        let request = TransactionRequest {
            id: uuid::Uuid::new_v4(),
            wallet_id: uuid::Uuid::new_v4(),
            network: BlockchainNetwork::Bitcoin,
            from_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            to_address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            amount: "100000".to_string(), // 0.001 BTC in satoshis
            fee: "1000".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: None,
            raw_transaction_data: None,
            required_signatures: 1,
            created_at: Utc::now(),
            expires_at: None,
            metadata: std::collections::HashMap::new(),
        };

        let result = sign_bitcoin_transaction(&request, &private_key);
        assert!(result.is_ok());
        let (signature, scheme) = result.unwrap();
        assert_eq!(scheme, SignatureScheme::ECDSA);
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_ethereum_transaction_signing() {
        let private_key = create_test_private_key();
        let request = TransactionRequest {
            id: uuid::Uuid::new_v4(),
            wallet_id: uuid::Uuid::new_v4(),
            network: BlockchainNetwork::Ethereum,
            from_address: "0x742d35Cc6634C0532925a3b8D4E7E0E0e9e0dF6D".to_string(),
            to_address: "0x8ba1f109551bD432803012645Hac136c".to_string(),
            amount: "1000000000000000000".to_string(), // 1 ETH in wei
            fee: "0".to_string(),
            gas_price: Some("20000000000".to_string()), // 20 gwei
            gas_limit: Some(21000),
            nonce: Some(0),
            memo: None,
            raw_transaction_data: None,
            required_signatures: 1,
            created_at: Utc::now(),
            expires_at: None,
            metadata: std::collections::HashMap::new(),
        };

        let result = sign_ethereum_transaction(&request, &private_key);
        assert!(result.is_ok());
        let (signature, scheme) = result.unwrap();
        assert_eq!(scheme, SignatureScheme::ECDSA);
        assert_eq!(signature.len(), 65); // r(32) + s(32) + v(1)
    }
}