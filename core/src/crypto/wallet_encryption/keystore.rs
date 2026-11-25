//! Web3 Secret Storage v3 (the geth/MyCrypto interchange format): structure,
//! scrypt/pbkdf2 limits, and import/export.

use crate::{PersonaError, PersonaResult};
use aes::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::Zeroize;

/// Keystore format (Web3 Secret Storage v3, the geth/MyCrypto interchange JSON)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeystoreV3 {
    pub version: u32,
    pub id: String,
    pub address: Option<String>,
    pub crypto: KeystoreCrypto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeystoreCrypto {
    pub cipher: String,
    pub ciphertext: String,
    pub cipherparams: CipherParams,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipherParams {
    pub iv: String,
}

/// KDF parameters. The standard names two shapes: scrypt
/// (`{dklen, n, r, p, salt}`) and pbkdf2 (`{dklen, c, prf, salt}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum KdfParams {
    Scrypt {
        dklen: u32,
        n: u32,
        r: u32,
        p: u32,
        salt: String,
    },
    Pbkdf2 {
        dklen: u32,
        c: u32,
        prf: String,
        salt: String,
    },
}

/// scrypt work factors used when exporting. `log_n` encodes n = 2^log_n.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScryptExportParams {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

/// Geth's standard export work factors (n = 2^18, r = 8, p = 1, ~0.5s native).
pub const SCRYPT_EXPORT_DEFAULT: ScryptExportParams = ScryptExportParams {
    log_n: 18,
    r: 8,
    p: 1,
};

/// Upper bound on scrypt memory (128 * r * n bytes) we are willing to spend
/// while importing an untrusted keystore. Equals geth's default (r=8, n=2^18),
/// so standard exports still import; hostile files asking for more are
/// rejected before any work is done.
const SCRYPT_IMPORT_MAX_MEM: u64 = 256 * 1024 * 1024;

/// Upper bound on the derived-key length accepted from an untrusted keystore.
/// Web3 v3 files use 32; anything above 128 is nonsense, and an unchecked
/// u32 dklen would allocate up to 4 GiB before any check runs.
const KEYSTORE_DKLEN_MAX: u32 = 128;

/// Upper bound on pbkdf2 iteration count accepted from an untrusted keystore.
/// c is a free-form u32; without a cap a hostile file can pin the import for
/// hours. 1,000,000 is ~8x geth's default (262,144) and ~2s of SHA-256 work.
const PBKDF2_IMPORT_MAX_ITERATIONS: u32 = 1_000_000;

fn hex_decode_field(field: &str, name: &str) -> PersonaResult<Vec<u8>> {
    hex::decode(field)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid hex in keystore {name}: {e}")))
}

/// Derive the keystore encryption key (per Web3 Secret Storage v3).
pub(super) fn derive_keystore_key(
    crypto: &KeystoreCrypto,
    password: &str,
) -> PersonaResult<Vec<u8>> {
    let password_bytes = password.as_bytes();
    let mut dk = match (crypto.kdf.as_str(), &crypto.kdfparams) {
        (
            "scrypt",
            KdfParams::Scrypt {
                dklen,
                n,
                r,
                p,
                salt,
            },
        ) => {
            let salt = hex_decode_field(salt, "kdfparams.salt")?;
            if *r == 0 || *p == 0 || n == &0 {
                return Err(PersonaError::InvalidInput(
                    "Invalid scrypt params: zero work factor".to_string(),
                ));
            }
            // Validate the params up front: n/r are u32 values read from the file
            // (untrusted), and 128*r*n can overflow u64, panicking in debug
            // (DoS) or wrapping in release and slipping past the cap;
            // checked_mul checks for it first.
            let mem = 128u64
                .checked_mul(u64::from(*r))
                .and_then(|v| v.checked_mul(u64::from(*n)))
                .ok_or_else(|| {
                    PersonaError::InvalidInput("scrypt work factor too high".to_string())
                })?;
            if mem > SCRYPT_IMPORT_MAX_MEM {
                return Err(PersonaError::InvalidInput(format!(
                    "scrypt work factor too high ({} bytes > {} cap)",
                    mem, SCRYPT_IMPORT_MAX_MEM
                )));
            }
            if *dklen > KEYSTORE_DKLEN_MAX {
                return Err(PersonaError::InvalidInput(format!(
                    "keystore dklen too high ({} > {} cap)",
                    dklen, KEYSTORE_DKLEN_MAX
                )));
            }
            let log_n = u8::try_from(31 - n.leading_zeros())
                .map_err(|_| PersonaError::InvalidInput("scrypt n out of range".to_string()))?;
            if 1u32 << log_n != *n {
                return Err(PersonaError::InvalidInput(
                    "Invalid scrypt params: n must be a power of two".to_string(),
                ));
            }
            let dklen_us = usize::try_from(*dklen).map_err(|_| {
                PersonaError::InvalidInput("keystore dklen out of range".to_string())
            })?;
            let params = scrypt::Params::new(log_n, *r, *p)
                .map_err(|e| PersonaError::InvalidInput(format!("Invalid scrypt params: {e}")))?;
            let mut out = vec![0u8; dklen_us];
            scrypt::scrypt(password_bytes, &salt, &params, &mut out)
                .map_err(|e| PersonaError::CryptographicError(format!("scrypt failed: {e}")))?;
            out
        }
        (
            "pbkdf2",
            KdfParams::Pbkdf2 {
                dklen,
                c,
                prf,
                salt,
            },
        ) => {
            if prf != "hmac-sha256" {
                return Err(PersonaError::InvalidInput(format!(
                    "Unsupported pbkdf2 prf: {prf}"
                )));
            }
            if *c > PBKDF2_IMPORT_MAX_ITERATIONS {
                return Err(PersonaError::InvalidInput(format!(
                    "pbkdf2 work factor too high ({} > {} cap)",
                    c, PBKDF2_IMPORT_MAX_ITERATIONS
                )));
            }
            if *dklen > KEYSTORE_DKLEN_MAX {
                return Err(PersonaError::InvalidInput(format!(
                    "keystore dklen too high ({} > {} cap)",
                    dklen, KEYSTORE_DKLEN_MAX
                )));
            }
            let salt = hex_decode_field(salt, "kdfparams.salt")?;
            let dklen_us = usize::try_from(*dklen).map_err(|_| {
                PersonaError::InvalidInput("keystore dklen out of range".to_string())
            })?;
            let mut out = vec![0u8; dklen_us];
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password_bytes, &salt, *c, &mut out);
            out
        }
        (kdf, _) => {
            return Err(PersonaError::InvalidInput(format!(
                "Unsupported keystore kdf: {kdf}"
            )))
        }
    };
    if dk.len() < 32 {
        dk.zeroize();
        return Err(PersonaError::InvalidInput(
            "keystore dklen must be at least 32".to_string(),
        ));
    }
    Ok(dk)
}

/// Import a private key from Web3 Secret Storage v3 keystore JSON
/// (scrypt or pbkdf2-hmac-sha256 KDF, AES-128-CTR, keccak-256 MAC).
pub fn import_from_keystore(keystore_json: &str, password: &str) -> PersonaResult<Vec<u8>> {
    let keystore: KeystoreV3 = serde_json::from_str(keystore_json)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid keystore format: {}", e)))?;

    if keystore.version != 3 {
        return Err(PersonaError::InvalidInput(format!(
            "Unsupported keystore version: {}",
            keystore.version
        )));
    }
    if keystore.crypto.cipher != "aes-128-ctr" {
        return Err(PersonaError::InvalidInput(format!(
            "Unsupported keystore cipher: {}",
            keystore.crypto.cipher
        )));
    }

    let ciphertext = hex_decode_field(&keystore.crypto.ciphertext, "ciphertext")?;
    let iv = hex_decode_field(&keystore.crypto.cipherparams.iv, "cipherparams.iv")?;
    if iv.len() != 16 {
        return Err(PersonaError::InvalidInput(format!(
            "Invalid keystore iv length: {} (want 16)",
            iv.len()
        )));
    }
    let mac = hex_decode_field(&keystore.crypto.mac, "mac")?;

    let mut dk = derive_keystore_key(&keystore.crypto, password)?;

    // MAC covers dk[16..32] ‖ ciphertext — verify before touching AES.
    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(&dk[16..32]);
    mac_input.extend_from_slice(&ciphertext);
    let expected = sha3::Keccak256::digest(&mac_input);
    let mac_ok: bool = subtle::ConstantTimeEq::ct_eq(&mac[..], &expected[..]).into();
    if !mac_ok {
        dk.zeroize();
        return Err(PersonaError::CryptographicError(
            "Keystore MAC mismatch: wrong password or corrupted keystore".to_string(),
        ));
    }

    let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&dk[..16], &iv)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid keystore key/iv: {e}")))?;
    let mut plaintext = ciphertext.clone();
    cipher.apply_keystream(&mut plaintext);
    dk.zeroize();
    Ok(plaintext)
}

/// Export a private key to Web3 Secret Storage v3 keystore JSON with geth's
/// standard scrypt work factors (n = 2^18, r = 8, p = 1).
pub fn export_to_keystore(
    private_key: &[u8],
    password: &str,
    address: Option<String>,
) -> PersonaResult<String> {
    export_to_keystore_with_params(private_key, password, address, SCRYPT_EXPORT_DEFAULT)
}

/// Export with explicit scrypt work factors (tests and tooling use small
/// factors to stay fast; real exports should use [`SCRYPT_EXPORT_DEFAULT`]).
pub fn export_to_keystore_with_params(
    private_key: &[u8],
    password: &str,
    address: Option<String>,
    params: ScryptExportParams,
) -> PersonaResult<String> {
    if params.r == 0 || params.p == 0 {
        return Err(PersonaError::InvalidInput(
            "Invalid scrypt params: zero work factor".to_string(),
        ));
    }
    if params.log_n > 23 {
        return Err(PersonaError::InvalidInput(
            "Invalid scrypt params: log_n above 23".to_string(),
        ));
    }
    // Same as on the import side: use checked_mul for 128*r*n to avoid overflow
    // (r is unrestricted, log_n<=23 already checked).
    let mem = 128u64
        .checked_mul(u64::from(params.r))
        .and_then(|v| v.checked_mul(1u64 << params.log_n))
        .ok_or_else(|| PersonaError::InvalidInput("scrypt work factor too high".to_string()))?;
    if mem > SCRYPT_IMPORT_MAX_MEM {
        return Err(PersonaError::InvalidInput(format!(
            "scrypt work factor too high ({} bytes > {} cap)",
            mem, SCRYPT_IMPORT_MAX_MEM
        )));
    }

    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).expect("failed to generate random salt");
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).expect("failed to generate random iv");

    let scrypt_params = scrypt::Params::new(params.log_n, params.r, params.p)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid scrypt params: {e}")))?;
    let mut dk = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), &salt, &scrypt_params, &mut dk)
        .map_err(|e| PersonaError::CryptographicError(format!("scrypt failed: {e}")))?;

    let mut ciphertext = private_key.to_vec();
    ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&dk[..16], &iv)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid key/iv: {e}")))?
        .apply_keystream(&mut ciphertext);

    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(&dk[16..32]);
    mac_input.extend_from_slice(&ciphertext);
    let mac = sha3::Keccak256::digest(&mac_input);
    dk.zeroize();

    let keystore = KeystoreV3 {
        version: 3,
        id: uuid::Uuid::new_v4().to_string(),
        address,
        crypto: KeystoreCrypto {
            cipher: "aes-128-ctr".to_string(),
            ciphertext: hex::encode(&ciphertext),
            cipherparams: CipherParams {
                iv: hex::encode(iv),
            },
            kdf: "scrypt".to_string(),
            kdfparams: KdfParams::Scrypt {
                dklen: 32,
                n: 1u32 << params.log_n,
                r: params.r,
                p: params.p,
                salt: hex::encode(salt),
            },
            mac: hex::encode(mac),
        },
    };
    ciphertext.zeroize();
    serde_json::to_string_pretty(&keystore)
        .map_err(|e| PersonaError::CryptographicError(format!("Failed to serialize keystore: {e}")))
}
