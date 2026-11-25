//! Unified game-token dispatcher: routes GameToken credentials to the concrete
//! algorithm by provider.
//!
//! Desktop / mobile / CLI should all generate token codes through this module
//! rather than calling the concrete algorithms directly. That way, when
//! vendor-bound providers are added later (Tencent Security Center, miHoYo
//! Security Token, etc. — bound to the vendor's server, impossible to compute
//! offline; see the game-token roadmap in todo.md), the read path will report
//! a single "offline generation not supported" error here instead of silently
//! generating a wrong code. RFC TOTP credentials (TwoFactor) can also be
//! fetched through [`generate_code`], giving consumers one entry point for
//! both credential kinds.

use crate::models::credential::{CredentialData, GameTokenData};
use anyhow::{bail, Result};
use serde::Serialize;

/// Steam Guard (Valve), computable offline
pub const PROVIDER_STEAM_GUARD: &str = "steam_guard";

/// Providers currently supporting offline generation (G2 items get appended
/// per the roadmap)
pub const SUPPORTED_PROVIDERS: &[&str] = &[PROVIDER_STEAM_GUARD];

/// Whether the provider supports offline generation
pub fn is_supported_provider(provider: &str) -> bool {
    SUPPORTED_PROVIDERS.contains(&provider)
}

/// The code a game token generated, plus seconds remaining and its period
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GameTokenCode {
    pub code: String,
    pub remaining_seconds: u32,
    pub period: u32,
}

fn unsupported(provider: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Unsupported game token provider '{}': offline code generation is not available (supported: {:?}; vendor-bound tokens generate codes in the vendor's official app — this entry is a vault record)",
        provider,
        SUPPORTED_PROVIDERS
    )
}

/// Generate a token code at `at` from the concrete vendor data
pub fn generate_game_token_code_at(
    data: &GameTokenData,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<GameTokenCode> {
    match data.provider.as_str() {
        PROVIDER_STEAM_GUARD => {
            let c = super::steam::steam_guard_at(data, at)?;
            Ok(GameTokenCode {
                code: c.code,
                remaining_seconds: c.remaining_seconds,
                period: super::steam::STEAM_GUARD_PERIOD_SECS as u32,
            })
        }
        other => Err(unsupported(other)),
    }
}

/// Generate the current token code from the concrete vendor data
pub fn generate_game_token_code_now(data: &GameTokenData) -> Result<GameTokenCode> {
    generate_game_token_code_at(data, chrono::Utc::now())
}

/// Generate the current token code from credential data: TwoFactor uses RFC
/// TOTP, GameToken goes through the vendor dispatcher
pub fn generate_code_now(data: &CredentialData) -> Result<GameTokenCode> {
    generate_code_at(data, chrono::Utc::now())
}

/// Generate a token code at `at` from credential data
pub fn generate_code_at(
    data: &CredentialData,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<GameTokenCode> {
    match data {
        CredentialData::GameToken(d) => generate_game_token_code_at(d, at),
        CredentialData::TwoFactor(t) => {
            // HOTP is counter-based: the dispatcher does not know the caller's current
            // counter, so it uniformly reports "offline generation not supported"
            // instead of silently generating a wrong code against a time window
            // (the fail-closed stance described in the module header).
            if t.hotp.unwrap_or(false) {
                bail!("HOTP entries are counter-based and need an explicit counter — use `persona totp code <id> --counter N`");
            }
            let c = super::totp::totp_at(t, at)?;
            Ok(GameTokenCode {
                code: c.code,
                remaining_seconds: c.remaining_seconds,
                period: t.period.max(1),
            })
        }
        _ => bail!("Credential data is not a game token"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::credential::{PasswordCredentialData, TwoFactorData};

    fn steam_data(secret: &str) -> GameTokenData {
        GameTokenData {
            provider: PROVIDER_STEAM_GUARD.to_string(),
            secret_key: secret.to_string(),
            issuer: "Steam".to_string(),
            account_name: "alice".to_string(),
            url: None,
            identity_secret: None,
            device_id: None,
        }
    }

    fn two_factor_data() -> TwoFactorData {
        TwoFactorData {
            // The ASCII secret "12345678901234567890" from RFC 6238 appendix B
            secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            issuer: "Test".to_string(),
            account_name: "a@b.c".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            hotp: None,
            initial_counter: None,
        }
    }

    #[test]
    fn steam_provider_dispatches_and_reports_period() {
        let data = steam_data("QUJDREVGR0hJSktMTU5PUA=="); // base64 "ABCDEFGHIJKLMNO"
        let at = chrono::DateTime::from_timestamp(59, 0).unwrap();
        let code = generate_game_token_code_at(&data, at).unwrap();
        assert_eq!(code.remaining_seconds, 1);
        assert_eq!(code.period, 30);
        assert_eq!(code.code.len(), 5);
    }

    #[test]
    fn unknown_provider_is_rejected_not_misgenerated() {
        let mut data = steam_data("QUJDREVGR0hJSktMTU5PUA==");
        data.provider = "tencent_security".to_string();
        let err = generate_game_token_code_now(&data)
            .expect_err("binding-based providers must not silently generate");
        assert!(err.to_string().contains("Unsupported game token provider"));
    }

    #[test]
    fn empty_provider_is_rejected() {
        let mut data = steam_data("QUJDREVGR0hJSktMTU5PUA==");
        data.provider = String::new();
        assert!(generate_game_token_code_now(&data).is_err());
    }

    #[test]
    fn generate_code_covers_two_factor_and_game_token_and_rejects_others() {
        let at = chrono::DateTime::from_timestamp(59, 0).unwrap();

        // TwoFactor goes through RFC TOTP (official test vector: t=59 -> 94287082,
        // 8 digits; with 6 digits here we take the suffix).
        let tf_code = generate_code_at(&CredentialData::TwoFactor(two_factor_data()), at).unwrap();
        assert_eq!(tf_code.code, "287082");
        assert_eq!(tf_code.period, 30);

        // GameToken goes through the vendor dispatcher.
        let gt_code = generate_code_at(
            &CredentialData::GameToken(steam_data("QUJDREVGR0hJSktMTU5PUA==")),
            at,
        )
        .unwrap();
        assert_eq!(gt_code.period, 30);

        // The other credential kinds report "not a game token".
        let err = generate_code_at(
            &CredentialData::Password(PasswordCredentialData {
                password: "x".to_string(),
                email: None,
                security_questions: vec![],
            }),
            at,
        )
        .expect_err("password data must not generate a token");
        assert!(err.to_string().contains("not a game token"));
    }

    #[test]
    fn two_factor_code_matches_direct_totp_call() {
        let data = CredentialData::TwoFactor(two_factor_data());
        let via_dispatcher = generate_code_now(&data).unwrap();
        let via_totp = super::super::totp::totp_now(&two_factor_data()).unwrap();
        assert_eq!(via_dispatcher.code, via_totp.code);
    }

    /// An HOTP entry must be explicitly rejected by the dispatcher (its counter is
    /// unknown); it must not silently produce a wrong code off a time window.
    #[test]
    fn hotp_two_factor_is_rejected_by_dispatcher() {
        let mut hotp_data = two_factor_data();
        hotp_data.hotp = Some(true);
        hotp_data.initial_counter = Some(3);
        let data = CredentialData::TwoFactor(hotp_data);
        let err = generate_code_now(&data)
            .expect_err("counter-based HOTP must not go through time windows");
        assert!(err.to_string().contains("counter-based"));
        assert!(err.to_string().contains("--counter"));
    }

    #[test]
    fn provider_list_contains_steam_guard() {
        assert!(is_supported_provider(PROVIDER_STEAM_GUARD));
        assert!(!is_supported_provider("netease_ufs"));
        assert!(!is_supported_provider(""));
    }
}
