// Wallet cryptography module for HD wallets and key derivation

use crate::{PersonaError, PersonaResult};
use bip32::{ChildNumber, DerivationPath, Prefix, XPrv};
use bip39::Mnemonic;
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
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
        OsRng.fill_bytes(&mut entropy);
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
}
