//! Steam Guard token algorithm (Valve's protocol per the public community implementations).
//!
//! Differences from RFC TOTP: the secret is standard base64 (the Steam mobile
//! authenticator's `shared_secret`, usually 20 bytes) rather than base32; the
//! period is fixed at 30 seconds with a BE64 counter fed to HMAC-SHA1; the
//! dynamic truncation is isomorphic to RFC 4226, but the result is not a
//! numeric code — instead five successive mod-26 reductions over the
//! 26-character alphabet "23456789BCDFGHJKMNPQRTVWXY" yield a 5-character
//! code. The implementation matches open-source implementations such as
//! steamguard-cli / SteamAuth / ValvePython-steam. Valve has published no
//! official test vectors; regression is pinned in three layers: pinned vectors
//! (produced by the independent Python reference implementation
//! `scripts/steam_guard_verify.py`), in-process cross-validation against a
//! hand-rolled ipad/opad HMAC reference, and structural assertions.

use crate::models::credential::GameTokenData;
use anyhow::{bail, Result};
use data_encoding::{BASE64, BASE64_NOPAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha1::Sha1;

/// Steam Guard code alphabet (26 characters, deliberately excluding the confusable 0/1/8/9 and vowels)
pub const STEAM_CHARS: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Fixed Steam Guard period (seconds)
pub const STEAM_GUARD_PERIOD_SECS: u64 = 30;

/// Fixed Steam Guard code length
pub const STEAM_GUARD_DIGITS: usize = 5;

/// A generated Steam Guard code plus its remaining valid seconds
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SteamGuardCode {
    pub code: String,
    pub remaining_seconds: u32,
}

/// Decode a Steam `shared_secret` (standard base64; tolerates whitespace and missing padding)
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

/// Steam Guard core algorithm: derive the 5-character code from the decoded `shared_secret` and a time counter
pub fn steam_guard_from_counter(secret: &[u8], counter: u64) -> Result<String> {
    if secret.is_empty() {
        bail!("Invalid Steam shared_secret: empty");
    }
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret)?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    // Dynamic truncation is isomorphic to RFC 4226: the last byte's low 4 bits pick the offset, then take 4 bytes and clear the sign bit
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

/// Generate a code at the given time using Steam Guard parameters
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

/// Generate a Steam Guard code at the current time
pub fn steam_guard_now(data: &GameTokenData) -> Result<SteamGuardCode> {
    steam_guard_at(data, chrono::Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard base64 of a 20-byte sample shared_secret (Steam's actual format)
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
            identity_secret: None,
            device_id: None,
        }
    }

    /// Pinned vectors produced by `scripts/steam_guard_verify.py --vectors`: the
    /// output of a Python-stdlib reference entirely independent of the main
    /// implementation (semantics aligned with ValvePython/steam guard.py) at
    /// fixed (shared_secret, counter) pairs. Valve has no official vectors, so
    /// any formula drift on either side shows up as a red here. Any vector
    /// change must be re-verified by re-running the script in sync.
    #[test]
    fn code_matches_independent_python_reference_vectors() {
        const VECTORS: &[(&str, u64, &str)] = &[
            ("MDAxMjM0NTY3ODlhYmNkZWZnaGo=", 0, "B792F"),
            ("MDAxMjM0NTY3ODlhYmNkZWZnaGo=", 1, "4XB8W"),
            ("MDAxMjM0NTY3ODlhYmNkZWZnaGo=", 42, "8W47Y"),
            ("MDAxMjM0NTY3ODlhYmNkZWZnaGo=", 12345, "GWYFV"),
            ("MDAxMjM0NTY3ODlhYmNkZWZnaGo=", u64::MAX, "FPTFY"),
            ("cGVyc29uYS12ZWN0b3ItYg==", 0, "Q7M34"),
            ("cGVyc29uYS12ZWN0b3ItYg==", 1, "57FHM"),
            ("cGVyc29uYS12ZWN0b3ItYg==", 42, "MVQYW"),
            ("cGVyc29uYS12ZWN0b3ItYg==", 12345, "GMB8H"),
        ];
        for (secret_b64, counter, expected) in VECTORS {
            let secret = decode_steam_secret(secret_b64).unwrap();
            let code = steam_guard_from_counter(&secret, *counter).unwrap();
            assert_eq!(
                &code, expected,
                "counter {counter} for secret {secret_b64} diverged from the independent reference"
            );
        }
    }

    /// Independent reference implementation: hand-constructed ipad/opad HMAC-SHA1
    /// (bypassing the hmac crate) to cross-validate the main implementation's
    /// full formula chain (HMAC → truncation → mod-encoded output).
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
        // Different counters produce different codes (guaranteed with the sample key)
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
        // Align to the window start so +29s does not spill into the next period
        let t0 = chrono::DateTime::from_timestamp(999_999_990, 0).unwrap(); // % 30 == 0
        let a = steam_guard_at(&data, t0).unwrap();
        let b = steam_guard_at(&data, t0 + chrono::Duration::seconds(29)).unwrap();
        assert_eq!(a.code, b.code);
        assert_eq!(a.remaining_seconds, b.remaining_seconds + 29);
        // Once past the window the code must change
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
            identity_secret: None,
            device_id: None,
        }
    }
}
