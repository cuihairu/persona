//! 游戏令牌统一调度器：按 provider 将 GameToken 凭据路由到具体算法。
//!
//! 桌面端/手机端/CLI 一律经本模块生成令牌码，而非直调具体算法——这样
//! 未来接入绑定型 provider（腾讯安全中心/米哈游安全令等厂商服务端绑定，
//! 无法离线计算，见 TODO.md 游戏令牌路线图）时，读取路径会在此统一报
//! "不支持离线生成"，而不是静默生成错误码。RFC TOTP 凭据（TwoFactor）
//! 也可经 [`generate_code`] 统一取码，便于消费端用单一入口处理两类凭据。

use crate::models::credential::{CredentialData, GameTokenData};
use anyhow::{bail, Result};
use serde::Serialize;

/// Steam Guard（Valve），离线可算
pub const PROVIDER_STEAM_GUARD: &str = "steam_guard";

/// 当前支持离线生成的 provider 清单（G2 按路线图追加）
pub const SUPPORTED_PROVIDERS: &[&str] = &[PROVIDER_STEAM_GUARD];

/// provider 是否支持离线生成
pub fn is_supported_provider(provider: &str) -> bool {
    SUPPORTED_PROVIDERS.contains(&provider)
}

/// 游戏令牌生成的码及剩余有效秒数/周期
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GameTokenCode {
    pub code: String,
    pub remaining_seconds: u32,
    pub period: u32,
}

fn unsupported(provider: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Unsupported game token provider '{}': offline code generation is not available (provider must be one of {:?}; binding-based providers are on the roadmap)",
        provider,
        SUPPORTED_PROVIDERS
    )
}

/// 按具体厂商数据在指定时刻生成令牌码
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

/// 按具体厂商数据生成当前令牌码
pub fn generate_game_token_code_now(data: &GameTokenData) -> Result<GameTokenCode> {
    generate_game_token_code_at(data, chrono::Utc::now())
}

/// 按凭据数据生成当前令牌码：TwoFactor 走 RFC TOTP，GameToken 走厂商调度
pub fn generate_code_now(data: &CredentialData) -> Result<GameTokenCode> {
    generate_code_at(data, chrono::Utc::now())
}

/// 按凭据数据在指定时刻生成令牌码
pub fn generate_code_at(
    data: &CredentialData,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<GameTokenCode> {
    match data {
        CredentialData::GameToken(d) => generate_game_token_code_at(d, at),
        CredentialData::TwoFactor(t) => {
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
        }
    }

    fn two_factor_data() -> TwoFactorData {
        TwoFactorData {
            // RFC 6238 附录 B 的 ASCII secret "12345678901234567890"
            secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            issuer: "Test".to_string(),
            account_name: "a@b.c".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
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

        // TwoFactor 经 RFC TOTP（官方向量：t=59 → 94287082，8 位；此处 6 位取后缀）
        let tf_code = generate_code_at(&CredentialData::TwoFactor(two_factor_data()), at).unwrap();
        assert_eq!(tf_code.code, "287082");
        assert_eq!(tf_code.period, 30);

        // GameToken 经厂商调度
        let gt_code = generate_code_at(
            &CredentialData::GameToken(steam_data("QUJDREVGR0hJSktMTU5PUA==")),
            at,
        )
        .unwrap();
        assert_eq!(gt_code.period, 30);

        // 其余数据类型报"非令牌"
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

    #[test]
    fn provider_list_contains_steam_guard() {
        assert!(is_supported_provider(PROVIDER_STEAM_GUARD));
        assert!(!is_supported_provider("netease_ufs"));
        assert!(!is_supported_provider(""));
    }
}
