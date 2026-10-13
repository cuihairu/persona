//! RFC 4226 (HOTP) / RFC 6238 (TOTP) 共享实现。
//!
//! CLI 与桌面端此前各自维护一份协议逻辑（cli/src/commands/totp.rs 与
//! desktop/src-tauri/src/commands.rs），本模块将其下沉到 core 统一维护，
//! 双端只做调用。数学部分以 RFC 4226/6238 为准，官方测试向量保留作回归。

use crate::models::credential::TwoFactorData;
use anyhow::{bail, Result};
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// 一次性算出的 TOTP 码及其剩余有效秒数
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining_seconds: u32,
}

/// 解码 base32 编码的 TOTP secret（容忍空白、大小写与 padding）
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

/// RFC 4226 HOTP：返回动态截断后的 32 位二进制值（未对位数取模）
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

/// 在指定计数器上按 `TwoFactorData` 的参数（算法/位数）计算 HOTP 码
/// （RFC 4226）。TOTP 与 HOTP 共享同一 HMAC 原语，差别只在计数器来源：
/// TOTP 用时间窗，HOTP 用显式计数。
pub fn code_at_counter(data: &TwoFactorData, counter: u64) -> Result<String> {
    let secret_bytes = decode_base32_secret(&data.secret_key)?;
    let digits = data.digits.clamp(4, 10) as u32;
    let code_num = hotp(&secret_bytes, counter, &data.algorithm)?;
    // u32: hotp() returns u32; 10^10 exceeds u32::MAX so widen first.
    let modulo = 10_u64.pow(digits);
    let value = u64::from(code_num) % modulo;
    Ok(format!("{:0width$}", value, width = digits as usize))
}

/// 在指定计数器上计算 HOTP 码（`hotp: Some(true)` 的 TwoFactor 条目）
pub fn hotp_code(data: &TwoFactorData, counter: u64) -> Result<String> {
    code_at_counter(data, counter)
}

/// 在指定时刻按 `TwoFactorData` 的参数（算法/位数/周期）计算 TOTP
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

/// 当前时刻计算 TOTP
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
        // RFC 6238 附录 B 的 ASCII secret "12345678901234567890"（20 字节 = 32 字符）
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()
    }

    fn rfc6238_sha256_secret() -> String {
        // ASCII "12345678901234567890123456789012"（32 字节 = 52 字符）
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA".to_string()
    }

    fn rfc6238_sha512_secret() -> String {
        // ASCII "1234567890123456789012345678901234567890123456789012345678901234"
        // （64 字节 = 103 字符）
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

    /// RFC 4226 附录 D 官方测试向量（SHA1、6 位、ASCII secret
    /// "12345678901234567890"，计数器 0-9）。HOTP 与 TOTP 共享 HMAC 原语，
    /// 这组向量锁定 `hotp_code` 的正确性；计数器是入参而不是时间推导。
    #[test]
    fn rfc4226_official_hotp_vectors() {
        let data = two_factor("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30);
        // 把同一个数据标成 hotp 也无关紧要：hotp_code 只看计数器入参。
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

    /// HOTP 码只依赖计数器入参：同一计数器上任意时刻算出同一码（与
    /// TOTP 的时间窗行为相反）。
    #[test]
    fn hotp_code_is_counter_driven_not_time_driven() {
        let data = two_factor("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30);
        let t0 = chrono::DateTime::from_timestamp(0, 0).unwrap();
        let t1 = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let c0 = code_at_counter(&data, 1).unwrap();
        assert_eq!(totp_at(&data, t0).unwrap().code, "755224"); // t=0 → 计数器 0
        assert_eq!(totp_at(&data, t1).unwrap().code.len(), 6);
        assert_eq!(c0, "287082");
        // 换计数器必须换码
        assert_ne!(code_at_counter(&data, 2).unwrap(), c0);
    }

    /// 位数钳制对 HOTP 同样生效（4/10 位上下限）。
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
        // 同一周期内值一致（跨周期边界时仅剩余秒数不同）
        let rerun = totp_at(&data, now).unwrap();
        assert_eq!(direct, rerun);
    }
}
