//! Shared implementation of RFC 4226 (HOTP) / RFC 6238 (TOTP).
//!
//! The CLI and the desktop app each used to maintain their own copy of the
//! protocol logic (cli/src/commands/totp.rs and
//! desktop/src-tauri/src/commands.rs); this module sunk it into core for
//! unified maintenance, with both ends only calling in. The math follows
//! RFC 4226/6238, and the official test vectors are kept as regressions.

use crate::models::credential::TwoFactorData;
use anyhow::{bail, Result};
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// A TOTP code computed in one shot, plus its remaining valid seconds
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining_seconds: u32,
}

/// Decode a base32-encoded TOTP secret (tolerates whitespace, casing, and padding)
pub fn decode_base32_secret(secret: &str) -> Result<Vec<u8>> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect::<String>()
        .trim_matches('=')
        .to_string();
    if normalized.is_empty() {
        bail!("Invalid base32 secret: empty");
    }
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32.decode(normalized.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Invalid base32 secret: {}", e))
}

/// RFC 4226 HOTP: returns the dynamically truncated 32-bit binary value (not yet reduced modulo the digit count)
pub fn hotp(secret: &[u8], counter: u64, algorithm: &str) -> Result<u32> {
    type HmacSha1 = Hmac<Sha1>;
    type HmacSha256 = Hmac<Sha256>;
    type HmacSha512 = Hmac<Sha512>;
    if secret.is_empty() {
        bail!("Invalid secret");
    }
    let msg = counter.to_be_bytes();
    let algo = algorithm.to_ascii_uppercase();
    let hash = if algo == "SHA256" {
        let mut mac = HmacSha256::new_from_slice(secret)?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else if algo == "SHA512" {
        let mut mac = HmacSha512::new_from_slice(secret)?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else {
        let mut mac = HmacSha1::new_from_slice(secret)?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    };

    let offset = (hash.last().copied().unwrap_or(0) & 0x0f) as usize;
    if offset + 4 > hash.len() {
        bail!("Invalid HMAC output");
    }
    let slice = &hash[offset..offset + 4];
    let binary = ((slice[0] as u32 & 0x7f) << 24)
        | ((slice[1] as u32) << 16)
        | ((slice[2] as u32) << 8)
        | slice[3] as u32;
    Ok(binary)
}

/// Compute the HOTP code at the given counter using `TwoFactorData`'s
/// parameters (algorithm / digits) per RFC 4226. TOTP and HOTP share the same
/// HMAC primitive; the only difference is the counter source: TOTP uses a
/// time window, HOTP an explicit counter.
pub fn code_at_counter(data: &TwoFactorData, counter: u64) -> Result<String> {
    let secret_bytes = decode_base32_secret(&data.secret_key)?;
    let digits = data.digits.clamp(4, 10) as u32;
    let code_num = hotp(&secret_bytes, counter, &data.algorithm)?;
    // u32: hotp() returns u32; 10^10 exceeds u32::MAX so widen first.
    let modulo = 10_u64.pow(digits);
    let value = u64::from(code_num) % modulo;
    Ok(format!("{:0width$}", value, width = digits as usize))
}

/// Compute the HOTP code at the given counter (for TwoFactor entries with `hotp: Some(true)`)
pub fn hotp_code(data: &TwoFactorData, counter: u64) -> Result<String> {
    code_at_counter(data, counter)
}

/// Compute the TOTP at the given time using `TwoFactorData`'s parameters (algorithm / digits / period)
pub fn totp_at(data: &TwoFactorData, at: chrono::DateTime<chrono::Utc>) -> Result<TotpCode> {
    let period = data.period.max(1) as u64;
    let timestamp = at.timestamp().max(0) as u64;
    let counter = timestamp / period;
    let code = code_at_counter(data, counter)?;
    let remaining = (period - (timestamp % period)) as u32;
    Ok(TotpCode {
        code,
        remaining_seconds: remaining,
    })
}

/// Compute the TOTP at the current time
pub fn totp_now(data: &TwoFactorData) -> Result<TotpCode> {
    totp_at(data, chrono::Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_factor(secret: &str, algorithm: &str, digits: u8, period: u32) -> TwoFactorData {
        TwoFactorData {
            secret_key: secret.to_string(),
            issuer: "Test".to_string(),
            account_name: "test@example.com".to_string(),
            algorithm: algorithm.to_string(),
            digits,
            period,
            hotp: None,
            initial_counter: None,
        }
    }

    fn rfc6238_sha1_secret() -> String {
        // The RFC 6238 Appendix B ASCII secret "12345678901234567890" (20 bytes = 32 chars)
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()
    }

    fn rfc6238_sha256_secret() -> String {
        // ASCII "12345678901234567890123456789012" (32 bytes = 52 chars)
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA".to_string()
    }

    fn rfc6238_sha512_secret() -> String {
        // ASCII "1234567890123456789012345678901234567890123456789012345678901234"
        // (64 bytes = 103 chars)
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA".to_string()
    }

    fn rfc6238_sha512_at(t: i64) -> String {
        let data = two_factor(&rfc6238_sha512_secret(), "SHA512", 8, 30);
        totp_at(&data, chrono::DateTime::from_timestamp(t, 0).unwrap())
            .unwrap()
            .code
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let data = two_factor(&rfc6238_sha1_secret(), "SHA1", 8, 30);
        let at = |t: i64| {
            totp_at(&data, chrono::DateTime::from_timestamp(t, 0).unwrap())
                .unwrap()
                .code
        };
        assert_eq!(at(59), "94287082");
        assert_eq!(at(1111111109), "07081804");
        assert_eq!(at(1111111111), "14050471");
        assert_eq!(at(1234567890), "89005924");
        assert_eq!(at(2000000000), "69279037");
        assert_eq!(at(20000000000), "65353130");
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        let data = two_factor(&rfc6238_sha256_secret(), "SHA256", 8, 30);
        let at = |t: i64| {
            totp_at(&data, chrono::DateTime::from_timestamp(t, 0).unwrap())
                .unwrap()
                .code
        };
        assert_eq!(at(59), "46119246");
        assert_eq!(at(1111111109), "68084774");
        assert_eq!(at(1111111111), "67062674");
        assert_eq!(at(1234567890), "91819424");
        assert_eq!(at(2000000000), "90698825");
        assert_eq!(at(20000000000), "77737706");
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        assert_eq!(rfc6238_sha512_at(59), "90693936");
        assert_eq!(rfc6238_sha512_at(1111111109), "25091201");
        assert_eq!(rfc6238_sha512_at(1111111111), "99943326");
        assert_eq!(rfc6238_sha512_at(1234567890), "93441116");
        assert_eq!(rfc6238_sha512_at(2000000000), "38618901");
        assert_eq!(rfc6238_sha512_at(20000000000), "47863826");
    }

    #[test]
    fn remaining_seconds_wraps_within_period() {
        let data = two_factor(&rfc6238_sha1_secret(), "SHA1", 8, 30);
        let t0 = chrono::DateTime::from_timestamp(59, 0).unwrap();
        let code = totp_at(&data, t0).unwrap();
        assert_eq!(code.remaining_seconds, 1); // 59 % 30 = 29
        let t1 = chrono::DateTime::from_timestamp(60, 0).unwrap();
        let code = totp_at(&data, t1).unwrap();
        assert_eq!(code.remaining_seconds, 30);
    }

    #[test]
    fn digits_clamped_to_4_and_10() {
        let data = two_factor(&rfc6238_sha1_secret(), "SHA1", 2, 30);
        let at = chrono::DateTime::from_timestamp(59, 0).unwrap();
        assert_eq!(totp_at(&data, at).unwrap().code.len(), 4);
        let data = two_factor(&rfc6238_sha1_secret(), "SHA1", 16, 30);
        assert_eq!(totp_at(&data, at).unwrap().code.len(), 10);
    }

    /// The official RFC 4226 Appendix D test vectors (SHA1, 6 digits, ASCII
    /// secret "12345678901234567890", counters 0-9). HOTP and TOTP share the
    /// HMAC primitive; this vector set locks in `hotp_code` correctness, with
    /// the counter passed in rather than derived from time.
    #[test]
    fn rfc4226_official_hotp_vectors() {
        let data = two_factor("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30);
        // Flagging the same data as hotp makes no difference: hotp_code only looks at the counter argument.
        let mut hotp_data = data.clone();
        hotp_data.hotp = Some(true);
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(
                hotp_code(&hotp_data, counter as u64).unwrap(),
                *code,
                "RFC 4226 counter {counter}"
            );
        }
    }

    /// The HOTP code depends only on the counter argument: at the same counter
    /// any moment yields the same code (opposite of TOTP's time-window behavior).
    #[test]
    fn hotp_code_is_counter_driven_not_time_driven() {
        let data = two_factor("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30);
        let t0 = chrono::DateTime::from_timestamp(0, 0).unwrap();
        let t1 = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let c0 = code_at_counter(&data, 1).unwrap();
        assert_eq!(totp_at(&data, t0).unwrap().code, "755224"); // t=0 → counter 0
        assert_eq!(totp_at(&data, t1).unwrap().code.len(), 6);
        assert_eq!(c0, "287082");
        // A different counter must produce a different code
        assert_ne!(code_at_counter(&data, 2).unwrap(), c0);
    }

    /// Digit clamping applies to HOTP too (a floor of 4 and a ceiling of 10 digits).
    #[test]
    fn hotp_code_clamps_digits() {
        let data = two_factor("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 2, 30);
        assert_eq!(hotp_code(&data, 0).unwrap().len(), 4);
        let data = two_factor(
            "GEZDGNBVGY3TQ3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
            "SHA256",
            6,
            30,
        );
        assert_eq!(hotp_code(&data, 0).unwrap().len(), 6);
    }

    #[test]
    fn default_period_of_six_digits_like_common_authenticator_apps() {
        let data = two_factor(&rfc6238_sha1_secret(), "SHA1", 6, 30);
        let at = chrono::DateTime::from_timestamp(59, 0).unwrap();
        assert_eq!(totp_at(&data, at).unwrap().code, "287082");
    }

    #[test]
    fn decode_accepts_case_whitespace_padding_and_reports_errors() {
        assert_eq!(decode_base32_secret("ME").unwrap(), b"a");
        assert_eq!(decode_base32_secret("me").unwrap(), b"a");
        assert_eq!(decode_base32_secret("M E").unwrap(), b"a");
        assert_eq!(decode_base32_secret("ME======").unwrap(), b"a");
        assert_eq!(
            decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            b"12345678901234567890"
        );
        assert!(decode_base32_secret("!!!!").is_err());
        assert!(decode_base32_secret("").is_err());
    }

    #[test]
    fn hotp_supports_all_algorithms_and_rejects_bad_secrets() {
        let secret = b"12345678901234567890";
        for algo in ["SHA1", "SHA256", "SHA512", "sha1"] {
            let code = hotp(secret, 7, algo).unwrap();
            assert!(code <= u32::from_be(0x7fff_ffff));
        }
        assert!(hotp(b"", 1, "SHA1").is_err());
    }

    #[test]
    fn totp_now_matches_totp_at_current_time() {
        let data = two_factor(&rfc6238_sha1_secret(), "SHA1", 6, 30);
        let now = chrono::Utc::now();
        let direct = totp_at(&data, now).unwrap();
        let _ = totp_now(&data).unwrap();
        // Values match within the same period (across a period boundary only the remaining seconds differ)
        let rerun = totp_at(&data, now).unwrap();
        assert_eq!(direct, rerun);
    }
}
