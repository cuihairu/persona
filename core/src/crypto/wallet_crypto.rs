// Wallet cryptography module for HD wallets and key derivation

use crate::{PersonaError, PersonaResult};
use bip32::{ChildNumber, DerivationPath, Prefix, XPrv};
use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use k256::ecdsa::{SigningKey, VerifyingKey};
use sha2::Sha512;
use std::str::{self, FromStr};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Mnemonic phrase wrapper with security features
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureMnemonic {
    #[zeroize(skip)]
    mnemonic: Mnemonic,
}

impl SecureMnemonic {
    /// Generate a new mnemonic with specified word count
    pub fn generate(word_count: MnemonicWordCount) -> PersonaResult<Self> {
        let mut entropy = vec![0u8; word_count.entropy_bytes()];
        getrandom::fill(&mut entropy).expect("failed to generate random entropy");
        let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| {
            PersonaError::Cryptography(format!("Failed to generate mnemonic: {}", e))
        })?;
        Ok(Self { mnemonic })
    }

    /// Create from existing phrase
    pub fn from_phrase(phrase: &str) -> PersonaResult<Self> {
        let mnemonic = phrase
            .parse::<Mnemonic>()
            .map_err(|e| PersonaError::Cryptography(format!("Invalid mnemonic: {}", e)))?;
        Ok(Self { mnemonic })
    }

    /// Get the phrase as string (use with caution!)
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Derive seed from mnemonic with optional passphrase
    pub fn to_seed(&self, passphrase: &str) -> Vec<u8> {
        self.mnemonic.to_seed(passphrase).to_vec()
    }

    /// Get word count
    pub fn word_count(&self) -> usize {
        self.mnemonic.word_count()
    }

    /// Validate a mnemonic phrase
    pub fn validate(phrase: &str) -> bool {
        phrase.parse::<Mnemonic>().is_ok()
    }
}

/// Standard BIP39 mnemonic word counts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicWordCount {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

impl MnemonicWordCount {
    /// Return the number of words represented by this variant.
    pub fn as_usize(self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words15 => 15,
            Self::Words18 => 18,
            Self::Words21 => 21,
            Self::Words24 => 24,
        }
    }

    fn entropy_bytes(self) -> usize {
        match self {
            Self::Words12 => 16,
            Self::Words15 => 20,
            Self::Words18 => 24,
            Self::Words21 => 28,
            Self::Words24 => 32,
        }
    }
}

/// HD wallet master key
pub struct MasterKey {
    xprv: XPrv,
}

impl MasterKey {
    /// Create master key from seed
    pub fn from_seed(seed: &[u8]) -> PersonaResult<Self> {
        let xprv = XPrv::new(seed).map_err(|e| {
            PersonaError::Cryptography(format!("Failed to derive master key: {}", e))
        })?;
        Ok(Self { xprv })
    }

    /// Create from mnemonic
    pub fn from_mnemonic(mnemonic: &SecureMnemonic, passphrase: &str) -> PersonaResult<Self> {
        let seed = mnemonic.to_seed(passphrase);
        Self::from_seed(&seed)
    }

    /// Derive child key at path
    pub fn derive_path(&self, path: &str) -> PersonaResult<DerivedKey> {
        let derivation_path = DerivationPath::from_str(path)
            .map_err(|e| PersonaError::Cryptography(format!("Invalid derivation path: {}", e)))?;

        let mut derived_key = self.xprv.clone();
        for child_number in derivation_path {
            derived_key = derived_key
                .derive_child(child_number)
                .map_err(|e| PersonaError::Cryptography(format!("Derivation failed: {}", e)))?;
        }

        Ok(DerivedKey { xprv: derived_key })
    }

    /// Get extended public key (xpub)
    pub fn to_xpub(&self) -> String {
        self.xprv.public_key().to_string(Prefix::XPUB)
    }

    /// Export as bytes (private - handle with care!)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.xprv
            .to_extended_key(Prefix::XPRV)
            .to_string()
            .into_bytes()
    }

    /// Import from bytes
    pub fn from_bytes(bytes: &[u8]) -> PersonaResult<Self> {
        let encoded = str::from_utf8(bytes)
            .map_err(|e| PersonaError::Cryptography(format!("Invalid key encoding: {}", e)))?;
        let xprv = encoded
            .parse::<XPrv>()
            .map_err(|e| PersonaError::Cryptography(format!("Invalid master key: {}", e)))?;
        Ok(Self { xprv })
    }
}

/// Derived key from HD wallet
#[derive(Clone)]
pub struct DerivedKey {
    xprv: XPrv,
}

impl DerivedKey {
    /// Get private key bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.xprv.private_key().to_bytes().into()
    }

    /// Get public key bytes (compressed)
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.xprv.public_key().to_bytes()
    }

    /// Get signing key for secp256k1
    pub fn to_signing_key(&self) -> PersonaResult<SigningKey> {
        let private_bytes = self.private_key_bytes();
        SigningKey::from_bytes(&private_bytes.into())
            .map_err(|e| PersonaError::Cryptography(format!("Failed to create signing key: {}", e)))
    }

    /// Get verifying key
    pub fn to_verifying_key(&self) -> PersonaResult<VerifyingKey> {
        Ok(*self.to_signing_key()?.verifying_key())
    }

    /// Derive child from this key
    pub fn derive_child(&self, index: u32, hardened: bool) -> PersonaResult<DerivedKey> {
        let child_number = if hardened {
            ChildNumber::new(index, true)
                .map_err(|e| PersonaError::Cryptography(format!("Invalid child index: {}", e)))?
        } else {
            ChildNumber::new(index, false)
                .map_err(|e| PersonaError::Cryptography(format!("Invalid child index: {}", e)))?
        };

        let derived = self
            .xprv
            .derive_child(child_number)
            .map_err(|e| PersonaError::Cryptography(format!("Child derivation failed: {}", e)))?;

        Ok(DerivedKey { xprv: derived })
    }
}

/// Standard BIP44 coin types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinType {
    Bitcoin = 0,
    Testnet = 1,
    Litecoin = 2,
    Dogecoin = 3,
    Ethereum = 60,
    EthereumClassic = 61,
    Cosmos = 118,
    Binance = 714,
    Solana = 501,
    Polygon = 966,
    Arbitrum = 9001,
    Optimism = 10,
}

impl CoinType {
    /// Get the BIP44 coin type value
    pub fn value(&self) -> u32 {
        *self as u32
    }
}

/// BIP44 derivation path builder
pub struct Bip44PathBuilder {
    purpose: u32,
    coin_type: u32,
    account: u32,
    change: u32,
    address_index: u32,
}

impl Bip44PathBuilder {
    /// Create new builder with BIP44 purpose
    pub fn new(coin_type: CoinType) -> Self {
        Self {
            purpose: 44,
            coin_type: coin_type.value(),
            account: 0,
            change: 0,
            address_index: 0,
        }
    }

    /// Create with BIP49 (P2SH-P2WPKH)
    pub fn bip49(coin_type: CoinType) -> Self {
        Self {
            purpose: 49,
            coin_type: coin_type.value(),
            account: 0,
            change: 0,
            address_index: 0,
        }
    }

    /// Create with BIP84 (Native SegWit)
    pub fn bip84(coin_type: CoinType) -> Self {
        Self {
            purpose: 84,
            coin_type: coin_type.value(),
            account: 0,
            change: 0,
            address_index: 0,
        }
    }

    /// Create with BIP86 (Taproot)
    pub fn bip86(coin_type: CoinType) -> Self {
        Self {
            purpose: 86,
            coin_type: coin_type.value(),
            account: 0,
            change: 0,
            address_index: 0,
        }
    }

    /// Set account index
    pub fn account(mut self, account: u32) -> Self {
        self.account = account;
        self
    }

    /// Set change chain (0 = external, 1 = internal/change)
    pub fn change(mut self, change: u32) -> Self {
        self.change = change;
        self
    }

    /// Set address index
    pub fn address_index(mut self, index: u32) -> Self {
        self.address_index = index;
        self
    }

    /// Build the derivation path string
    pub fn build(&self) -> String {
        format!(
            "m/{}'/{}'/{}'/{}/{}",
            self.purpose, self.coin_type, self.account, self.change, self.address_index
        )
    }
}

/// Ed25519 extended key derived per SLIP-0010 (ed25519, hardened only).
///
/// Curves like Solana use Ed25519 keys that cannot come from a secp256k1
/// `XPrv`; this type derives them straight from the BIP39 seed.
#[derive(Clone)]
pub struct Ed25519Key {
    key: ed25519_dalek::SigningKey,
    chain_code: [u8; 32],
}

impl Drop for Ed25519Key {
    fn drop(&mut self) {
        // ed25519-dalek's `zeroize` feature clears the inner signing key on
        // drop; the chain code has no such guarantee, so clear it here.
        self.chain_code.zeroize();
    }
}

impl Ed25519Key {
    const ED25519_SEED_KEY: &'static [u8] = b"ed25519 seed";

    /// Derive the SLIP-0010 master node from a BIP39 seed.
    pub fn from_seed(seed: &[u8]) -> PersonaResult<Self> {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(Self::ED25519_SEED_KEY)
            .map_err(|e| PersonaError::Cryptography(format!("HMAC init failed: {}", e)))?;
        mac.update(seed);
        let output = mac.finalize().into_bytes();

        let key = ed25519_dalek::SigningKey::from_bytes(
            output[..32].try_into().expect("32-byte HMAC output"),
        );
        let chain_code: [u8; 32] = output[32..].try_into().expect("32-byte HMAC chain code");
        Ok(Self { key, chain_code })
    }

    /// Derive a hardened child at `index` (the hardened bit is applied here).
    pub fn derive_child_hardened(&self, index: u32) -> PersonaResult<Self> {
        let hardened = index | 0x8000_0000;
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.chain_code)
            .map_err(|e| PersonaError::Cryptography(format!("HMAC init failed: {}", e)))?;
        mac.update(&[0u8]); // ed25519 private-key derivation prefix
        mac.update(&self.key.to_bytes());
        mac.update(&hardened.to_be_bytes());
        let output = mac.finalize().into_bytes();

        let key = ed25519_dalek::SigningKey::from_bytes(
            output[..32].try_into().expect("32-byte HMAC output"),
        );
        let chain_code: [u8; 32] = output[32..].try_into().expect("32-byte HMAC chain code");
        Ok(Self { key, chain_code })
    }

    /// Derive the node at `path` (e.g. `m/44'/501'/0'/0'`).
    ///
    /// Ed25519 only supports hardened derivation; non-hardened components
    /// are rejected.
    pub fn derive_path(&self, path: &str) -> PersonaResult<Self> {
        let trimmed = path.strip_prefix('m').unwrap_or(path);
        let mut current = self.clone();
        for component in trimmed.split('/').filter(|c| !c.is_empty()) {
            let Some(stripped) = component.strip_suffix('\'') else {
                return Err(PersonaError::Cryptography(format!(
                    "Ed25519 derivation requires hardened path components: {}",
                    component
                )));
            };
            let index: u32 = stripped.parse().map_err(|_| {
                PersonaError::Cryptography(format!("Invalid path index: {}", component))
            })?;
            if index >= 0x8000_0000 {
                return Err(PersonaError::Cryptography(format!(
                    "Invalid hardened index: {}",
                    component
                )));
            }
            current = current.derive_child_hardened(index)?;
        }
        Ok(current)
    }

    /// 32-byte public key (the Solana address payload).
    pub fn public_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// 32-byte secret key (handle with care).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Split into `(secret, chain_code)` for encrypted persistence.
    pub fn to_parts(&self) -> ([u8; 32], [u8; 32]) {
        (self.key.to_bytes(), self.chain_code)
    }

    /// Rebuild a node from its `(secret, chain_code)` parts.
    pub fn from_parts(secret: [u8; 32], chain_code: [u8; 32]) -> PersonaResult<Self> {
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        Ok(Self { key, chain_code })
    }

    /// Sign a message, returning the 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.key.sign(message).to_bytes()
    }

    /// Verify a 64-byte Ed25519 signature over a message.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.key
            .verify(message, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prelude::*, sample::select};

    fn word_count_strategy() -> impl Strategy<Value = MnemonicWordCount> {
        select(vec![
            MnemonicWordCount::Words12,
            MnemonicWordCount::Words15,
            MnemonicWordCount::Words18,
            MnemonicWordCount::Words21,
            MnemonicWordCount::Words24,
        ])
    }

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words12).unwrap();
        assert_eq!(mnemonic.word_count(), 12);

        let phrase = mnemonic.phrase();
        assert!(!phrase.is_empty());

        // Validate the generated mnemonic
        assert!(SecureMnemonic::validate(&phrase));
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecureMnemonic::from_phrase(test_phrase).unwrap();
        assert_eq!(mnemonic.phrase(), test_phrase);
    }

    #[test]
    fn test_master_key_derivation() {
        let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words12).unwrap();
        let master_key = MasterKey::from_mnemonic(&mnemonic, "").unwrap();

        // Derive a standard BIP44 path
        let path = Bip44PathBuilder::new(CoinType::Bitcoin).build();
        let derived = master_key.derive_path(&path).unwrap();

        assert_eq!(derived.private_key_bytes().len(), 32);
        assert_eq!(derived.public_key_bytes().len(), 33);
    }

    #[test]
    fn test_bip44_path_builder() {
        let path = Bip44PathBuilder::new(CoinType::Ethereum)
            .account(0)
            .address_index(0)
            .build();
        assert_eq!(path, "m/44'/60'/0'/0/0");

        let path = Bip44PathBuilder::bip84(CoinType::Bitcoin)
            .account(0)
            .address_index(5)
            .build();
        assert_eq!(path, "m/84'/0'/0'/0/5");
    }

    #[test]
    fn test_child_derivation() {
        let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words24).unwrap();
        let master_key = MasterKey::from_mnemonic(&mnemonic, "test_passphrase").unwrap();

        let path = "m/44'/60'/0'/0";
        let parent = master_key.derive_path(path).unwrap();

        // Derive multiple child addresses
        let child0 = parent.derive_child(0, false).unwrap();
        let child1 = parent.derive_child(1, false).unwrap();

        // Keys should be different
        assert_ne!(child0.private_key_bytes(), child1.private_key_bytes());
    }

    proptest! {
        #[test]
        fn mnemonic_roundtrip(word_count in word_count_strategy()) {
            let mnemonic = SecureMnemonic::generate(word_count).unwrap();
            let phrase = mnemonic.phrase();
            let parsed = SecureMnemonic::from_phrase(&phrase).unwrap();
            prop_assert_eq!(parsed.phrase(), phrase);
            prop_assert_eq!(parsed.word_count(), word_count.as_usize());
        }
    }

    proptest! {
        #[test]
        fn mnemonic_validation_matches_parse(input in ".*") {
            let parsed = SecureMnemonic::from_phrase(&input);
            let is_valid = SecureMnemonic::validate(&input);
            prop_assert_eq!(parsed.is_ok(), is_valid);
        }
    }

    #[test]
    fn test_ed25519_non_hardened_path_rejected() {
        let seed = [1u8; 64];
        let key = Ed25519Key::from_seed(&seed).unwrap();
        assert!(key.derive_path("m/44'/501'/0'/0").is_err());
        assert!(key.derive_path("m/44'/501'/0'/0'").is_ok());
    }
}

#[cfg(test)]
mod slip10_tests {
    use super::*;

    // SLIP-0010 ed25519 Test Vector 1
    // seed = 000102030405060708090a0b0c0d0e0f
    #[test]
    fn test_slip10_vector1_master() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = Ed25519Key::from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(key.secret_bytes()),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(key.chain_code),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
        assert_eq!(
            hex::encode(key.public_bytes()),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );
    }

    // SLIP-0010 ed25519 Test Vector 1: m/0'
    #[test]
    fn test_slip10_vector1_child0() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = Ed25519Key::from_seed(&seed)
            .unwrap()
            .derive_path("m/0'")
            .unwrap();
        assert_eq!(
            hex::encode(key.secret_bytes()),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex::encode(key.chain_code),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
        );
    }

    // SLIP-0010 ed25519 Test Vector 1: m/0'/1'
    #[test]
    fn test_slip10_vector1_child1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = Ed25519Key::from_seed(&seed)
            .unwrap()
            .derive_path("m/0'/1'")
            .unwrap();
        assert_eq!(
            hex::encode(key.secret_bytes()),
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"
        );
        assert_eq!(
            hex::encode(key.chain_code),
            "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"
        );
    }

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let seed = [42u8; 64];
        let key = Ed25519Key::from_seed(&seed).unwrap();
        let message = b"persona solana transfer message";
        let signature = key.sign(message);
        assert!(key.verify(message, &signature));
        assert!(!key.verify(b"tampered", &signature));
    }
}
