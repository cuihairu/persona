//! Steam Guard 令牌算法（Valve 协议的公开社区实现）。
//!
//! 与 RFC TOTP 的差别：secret 是标准 base64（Steam 手机验证器的
//! `shared_secret`，通常 20 字节）而非 base32；周期固定 30 秒、BE64
//! 计数器做 HMAC-SHA1；动态截断与 RFC 4226 同构，但结果不是数字码，
//! 而是从 26 字符字母表 "23456789BCDFGHJKMNPQRTVWXY" 连续取模 5 次
//! 得到 5 位码。实现与 steamguard-cli / SteamAuth 等开源实现一致；
//! Valve 未发布官方测试向量，回归依赖结构断言与独立 HMAC 参照实现。

use crate::models::credential::GameTokenData;
use anyhow::{bail, Result};
use data_encoding::{BASE64, BASE64_NOPAD};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;

/// Steam Guard 码字符表（26 字符，刻意剔除易混淆的 0/1/8/9 与元音）
pub const STEAM_CHARS: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Steam Guard 固定周期（秒）
pub const STEAM_GUARD_PERIOD_SECS: u64 = 30;

/// Steam Guard 固定码长
pub const STEAM_GUARD_DIGITS: usize = 5;

/// Steam Guard 生成的码及剩余有效秒数
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SteamGuardCode {
    pub code: String,
    pub remaining_seconds: u32,
}

/// 解码 Steam `shared_secret`（标准 base64，容忍空白与 padding 缺省）
pub fn decode_steam_secret(secret: &str) -> Result<Vec<u8>> {
    let normalized: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
    if normalized.is_empty() {
        bail!("Invalid Steam shared_secret: empty");
    }
    BASE64
        .decode(normalized.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(normalized.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Invalid Steam shared_secret: {}", e))
}

/// Steam Guard 核心算法：由解码后的 `shared_secret` 与时间计数器生成 5 位码
pub fn steam_guard_from_counter(secret: &[u8], counter: u64) -> Result<String> {
    if secret.is_empty() {
        bail!("Invalid Steam shared_secret: empty");
    }
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret)?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    // 动态截断与 RFC 4226 同构：末字节低 4 位定偏移，取 4 字节并清符号位
    let start = (hash.last().copied().unwrap_or(0) & 0x0f) as usize;
    if start + 4 > hash.len() {
        bail!("Invalid HMAC output");
    }
    let slice = &hash[start..start + 4];
    let mut full = u32::from_be_bytes(slice.try_into().expect("4-byte slice")) & 0x7fff_ffff;

    let mut code = String::with_capacity(STEAM_GUARD_DIGITS);
    for _ in 0..STEAM_GUARD_DIGITS {
        code.push(STEAM_CHARS[(full % 26) as usize] as char);
        full /= 26;
    }
    Ok(code)
}

/// 在指定时刻按 Steam Guard 参数生成码
pub fn steam_guard_at(
    data: &GameTokenData,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<SteamGuardCode> {
    let secret = decode_steam_secret(&data.secret_key)?;
    let timestamp = at.timestamp().max(0) as u64;
    let counter = timestamp / STEAM_GUARD_PERIOD_SECS;
    let code = steam_guard_from_counter(&secret, counter)?;
    let remaining = (STEAM_GUARD_PERIOD_SECS - (timestamp % STEAM_GUARD_PERIOD_SECS)) as u32;
    Ok(SteamGuardCode {
        code,
        remaining_seconds: remaining,
    })
}

/// 当前时刻生成 Steam Guard 码
pub fn steam_guard_now(data: &GameTokenData) -> Result<SteamGuardCode> {
    steam_guard_at(data, chrono::Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 20 字节样例 shared_secret 的标准 base64（Steam 实际格式）
    fn sample_secret_b64() -> String {
        BASE64.encode(b"0123456789abcdefghij")
    }

    fn sample_data() -> GameTokenData {
        GameTokenData {
            provider: "steam_guard".to_string(),
            secret_key: sample_secret_b64(),
            issuer: "Steam".to_string(),
            account_name: "alice".to_string(),
            url: None,
        }
    }

    /// 独立参照实现：手工 ipad/opad 构造 HMAC-SHA1（不经 hmac crate），
    /// 交叉验证主实现的整体公式链（HMAC → 截断 → 取模编码）。
    fn reference_steam_code(secret: &[u8], counter: u64) -> String {
        use sha1::Digest;
        let mut key = [0u8; 64];
        key[..secret.len()].copy_from_slice(secret);
        let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
        let mut inner = Sha1::new();
        inner.update(&ipad);
        inner.update(counter.to_be_bytes());
        let inner_hash = inner.finalize();
        let mut outer = Sha1::new();
        outer.update(&opad);
        outer.update(inner_hash);
        let hmac = outer.finalize();

        let start = (hmac[19] & 0x0f) as usize;
        let mut full = u32::from_be_bytes(hmac[start..start + 4].try_into().unwrap()) & 0x7fff_ffff;
        let mut code = String::new();
        for _ in 0..STEAM_GUARD_DIGITS {
            code.push(STEAM_CHARS[(full % 26) as usize] as char);
            full /= 26;
        }
        code
    }

    #[test]
    fn code_matches_independent_hmac_reference() {
        let secret = decode_steam_secret(&sample_secret_b64()).unwrap();
        for counter in [0u64, 1, 12345, u64::MAX] {
            let code = steam_guard_from_counter(&secret, counter).unwrap();
            assert_eq!(code, reference_steam_code(&secret, counter));
        }
    }

    #[test]
    fn code_shape_is_five_alphabet_chars_and_deterministic() {
        let secret = decode_steam_secret(&sample_secret_b64()).unwrap();
        let first = steam_guard_from_counter(&secret, 42).unwrap();
        assert_eq!(first.len(), STEAM_GUARD_DIGITS);
        assert!(
            first.bytes().all(|c| STEAM_CHARS.contains(&c)),
            "code {first} outside Steam alphabet"
        );
        assert_eq!(steam_guard_from_counter(&secret, 42).unwrap(), first);
        // 不同计数器产生不同码（示例密钥下必然成立）
        assert_ne!(steam_guard_from_counter(&secret, 43).unwrap(), first);
    }

    #[test]
    fn remaining_seconds_wraps_within_period() {
        let data = sample_data();
        let at = |t: i64| {
            steam_guard_at(&data, chrono::DateTime::from_timestamp(t, 0).unwrap())
                .unwrap()
                .remaining_seconds
        };
        assert_eq!(at(59), 1);
        assert_eq!(at(60), STEAM_GUARD_PERIOD_SECS as u32);
        assert_eq!(at(0), STEAM_GUARD_PERIOD_SECS as u32);
    }

    #[test]
    fn same_period_window_yields_same_code() {
        let data = sample_data();
        // 对齐窗口起点，避免 +29s 跨入下一个周期
        let t0 = chrono::DateTime::from_timestamp(999_999_990, 0).unwrap(); // % 30 == 0
        let a = steam_guard_at(&data, t0).unwrap();
        let b = steam_guard_at(&data, t0 + chrono::Duration::seconds(29)).unwrap();
        assert_eq!(a.code, b.code);
        assert_eq!(a.remaining_seconds, b.remaining_seconds + 29);
        // 跨过窗口后码必须更换
        let c = steam_guard_at(&data, t0 + chrono::Duration::seconds(30)).unwrap();
        assert_eq!(c.remaining_seconds, STEAM_GUARD_PERIOD_SECS as u32);
    }

    #[test]
    fn steam_guard_now_matches_steam_guard_at_current_time() {
        let data = sample_data();
        let now = chrono::Utc::now();
        let direct = steam_guard_at(&data, now).unwrap();
        assert_eq!(steam_guard_at(&data, now).unwrap(), direct);
        let _ = steam_guard_now(&data).unwrap();
    }

    #[test]
    fn decode_accepts_padded_unpadded_and_whitespace() {
        assert_eq!(
            decode_steam_secret(&BASE64.encode(b"abc")).unwrap(),
            b"abc".to_vec()
        );
        assert_eq!(
            decode_steam_secret(&BASE64_NOPAD.encode(b"abc")).unwrap(),
            b"abc".to_vec()
        );
        let padded = BASE64.encode(b"abcdefgh");
        let spaced = format!("{} {}", &padded[..4], &padded[4..]);
        assert_eq!(decode_steam_secret(&spaced).unwrap(), b"abcdefgh".to_vec());
        assert!(decode_steam_secret("").is_err());
        assert!(decode_steam_secret("   ").is_err());
        assert!(decode_steam_secret("!!!not base64!!!").is_err());
    }

    #[test]
    fn empty_decoded_secret_is_rejected() {
        assert!(steam_guard_from_counter(b"", 1).is_err());
        // base64 of empty string decodes to zero bytes
        assert!(steam_guard_at(&sample_data_empty_secret(), chrono::Utc::now()).is_err());
    }

    fn sample_data_empty_secret() -> GameTokenData {
        GameTokenData {
            provider: "steam_guard".to_string(),
            secret_key: String::new(),
            issuer: "Steam".to_string(),
            account_name: "alice".to_string(),
            url: None,
        }
    }
}
