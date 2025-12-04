//! 加密操作模块
//!
//! 提供密码哈希、密钥派生、对称加密等功能

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use argon2::{
    Argon2, PasswordHash, PasswordHasher as Argon2Hasher, PasswordVerifier,
    password_hash::{rand_core::OsRng, SaltString},
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};
use pbkdf2::pbkdf2_hmac;

/// 密码哈希结果
#[wasm_bindgen]
#[derive(Clone)]
pub struct PasswordHashResult {
    hash: String,
}

#[wasm_bindgen]
impl PasswordHashResult {
    /// 获取哈希字符串
    pub fn hash(&self) -> String {
        self.hash.clone()
    }
}

/// 使用Argon2哈希密码
#[wasm_bindgen]
pub fn hash_password(password: &str) -> Result<PasswordHashResult, JsValue> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| JsValue::from_str(&format!("Hashing failed: {}", e)))?
        .to_string();

    Ok(PasswordHashResult { hash })
}

/// 验证密码
#[wasm_bindgen]
pub fn verify_password(password: &str, hash: &str) -> Result<bool, JsValue> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| JsValue::from_str(&format!("Invalid hash: {}", e)))?;

    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(JsValue::from_str(&format!("Verification failed: {}", e))),
    }
}

/// 密钥派生结果
#[wasm_bindgen]
pub struct DerivedKey {
    key: Vec<u8>,
}

#[wasm_bindgen]
impl DerivedKey {
    /// 获取密钥的base64编码
    pub fn to_base64(&self) -> String {
        base64::encode(&self.key)
    }

    /// 获取密钥的hex编码
    pub fn to_hex(&self) -> String {
        hex::encode(&self.key)
    }
}

/// 使用PBKDF2派生密钥
#[wasm_bindgen]
pub fn derive_key_pbkdf2(
    password: &str,
    salt: &str,
    iterations: u32,
    key_length: usize,
) -> Result<DerivedKey, JsValue> {
    if key_length == 0 || key_length > 128 {
        return Err(JsValue::from_str("Key length must be between 1 and 128 bytes"));
    }

    let mut key = vec![0u8; key_length];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        iterations,
        &mut key,
    );

    Ok(DerivedKey { key })
}

/// 加密数据结果
#[wasm_bindgen]
pub struct EncryptedData {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptedData {
    /// 获取密文的base64编码
    pub fn ciphertext_base64(&self) -> String {
        base64::encode(&self.ciphertext)
    }

    /// 获取nonce的base64编码
    pub fn nonce_base64(&self) -> String {
        base64::encode(&self.nonce)
    }

    /// 转换为JSON字符串
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "ciphertext": base64::encode(&self.ciphertext),
            "nonce": base64::encode(&self.nonce),
        })
        .to_string()
    }
}

/// 使用AES-256-GCM加密数据
#[wasm_bindgen]
pub fn encrypt_aes256gcm(plaintext: &str, key_base64: &str) -> Result<EncryptedData, JsValue> {
    let key_bytes = base64::decode(key_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid key encoding: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes (256 bits)"));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to create cipher: {}", e)))?;

    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

    Ok(EncryptedData {
        ciphertext,
        nonce: nonce.to_vec(),
    })
}

/// 使用AES-256-GCM解密数据
#[wasm_bindgen]
pub fn decrypt_aes256gcm(
    ciphertext_base64: &str,
    nonce_base64: &str,
    key_base64: &str,
) -> Result<String, JsValue> {
    let key_bytes = base64::decode(key_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid key encoding: {}", e)))?;

    let ciphertext = base64::decode(ciphertext_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid ciphertext encoding: {}", e)))?;

    let nonce_bytes = base64::decode(nonce_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid nonce encoding: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes (256 bits)"));
    }

    if nonce_bytes.len() != 12 {
        return Err(JsValue::from_str("Nonce must be 12 bytes (96 bits)"));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8: {}", e)))
}

/// SHA-256哈希
#[wasm_bindgen]
pub fn sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// 生成随机字节
#[wasm_bindgen]
pub fn random_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
    if length == 0 || length > 1024 {
        return Err(JsValue::from_str("Length must be between 1 and 1024 bytes"));
    }

    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| JsValue::from_str(&format!("Random generation failed: {}", e)))?;

    Ok(bytes)
}

/// 生成随机字节的base64编码
#[wasm_bindgen]
pub fn random_bytes_base64(length: usize) -> Result<String, JsValue> {
    let bytes = random_bytes(length)?;
    Ok(base64::encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let result = hash_password(password).unwrap();
        assert!(verify_password(password, &result.hash()).unwrap());
        assert!(!verify_password("wrong_password", &result.hash()).unwrap());
    }

    #[wasm_bindgen_test]
    fn test_sha256() {
        let hash = sha256("hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[wasm_bindgen_test]
    fn test_encryption_decryption() {
        let key = random_bytes_base64(32).unwrap();
        let plaintext = "Secret message 🔐";

        let encrypted = encrypt_aes256gcm(plaintext, &key).unwrap();
        let decrypted = decrypt_aes256gcm(
            &encrypted.ciphertext_base64(),
            &encrypted.nonce_base64(),
            &key,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
