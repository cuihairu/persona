use super::keystore::derive_keystore_key;
use super::*;
use crate::crypto::encryption::encrypt_data;
use crate::crypto::wallet_crypto::{MasterKey, MnemonicWordCount, SecureMnemonic};
use aes::cipher::{KeyIvInit, StreamCipher};
use proptest::{collection, prelude::*};
use sha2::Digest;
use std::ops::RangeInclusive;
use uuid::Uuid;

fn hex_string(range: RangeInclusive<usize>) -> impl Strategy<Value = String> {
    collection::vec(any::<u8>(), range).prop_map(hex::encode)
}

fn keystore_strategy() -> impl Strategy<Value = KeystoreV3> {
    (
        proptest::option::of(hex_string(20..=40)),
        hex_string(32..=64),
        hex_string(16..=32),
        hex_string(32..=64),
        hex_string(32..=64),
        hex_string(8..=32),
    )
        .prop_map(
            |(address, ciphertext, iv, mac, salt, _id_fragment)| KeystoreV3 {
                version: 3,
                id: Uuid::new_v4().to_string(),
                address,
                crypto: KeystoreCrypto {
                    cipher: "aes-128-ctr".to_string(),
                    ciphertext,
                    cipherparams: CipherParams { iv },
                    kdf: "scrypt".to_string(),
                    kdfparams: KdfParams::Scrypt {
                        dklen: 32,
                        n: 16384,
                        p: 1,
                        r: 8,
                        salt,
                    },
                    mac,
                },
            },
        )
}

proptest! {
    #[test]
    fn keystore_json_roundtrip(keystore in keystore_strategy()) {
        let json = serde_json::to_string(&keystore).unwrap();
        let parsed: KeystoreV3 = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(parsed, keystore);
    }
}

/// Build a full pbkdf2 keystore JSON for roundtrip tests (the KDF layer
/// itself is pinned to OpenSSL above; this exercises the MAC + AES
/// composition through the same public surface as a real file).
fn build_pbkdf2_keystore_json(secret: &[u8], password: &str, c: u32) -> String {
    use sha3::Digest;
    let salt = [0x42u8; 16];
    let iv = [0x43u8; 16];
    let mut dk = vec![0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, c, &mut dk);
    let mut ciphertext = secret.to_vec();
    ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&dk[..16], &iv)
        .unwrap()
        .apply_keystream(&mut ciphertext);
    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(&dk[16..32]);
    mac_input.extend_from_slice(&ciphertext);
    let mac = sha3::Keccak256::digest(&mac_input);
    serde_json::json!({
        "version": 3,
        "id": Uuid::new_v4(),
        "crypto": {
            "cipher": "aes-128-ctr",
            "ciphertext": hex::encode(&ciphertext),
            "cipherparams": {"iv": hex::encode(iv)},
            "kdf": "pbkdf2",
            "kdfparams": {
                "dklen": 32, "c": c, "prf": "hmac-sha256", "salt": hex::encode(salt)
            },
            "mac": hex::encode(mac)
        }
    })
    .to_string()
}

mod encryption;
mod keystore;
mod material;
