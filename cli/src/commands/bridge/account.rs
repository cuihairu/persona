use super::*;

/// 账号域 bearer（静态服务器令牌 / SRP 短期令牌 / 24h 会话令牌）的
/// keyring service——与桌面 token_store 的 ACCOUNT_SERVICE 同名同键
/// （条目键 = vault db_path），桌面与桥读写同一枚令牌。
pub(super) const KEYRING_SERVICE_ACCOUNT: &str = "persona-account";

/// 账号令牌仓抽象：生产走 OS keyring；测试注入内存实现（与桌面
/// token_store 的 TokenStore trait 同构，参数化 service 名的思路一致）。
pub(super) trait AccountTokenStore: Send + Sync {
    fn set_token(&self, db_key: &str, token: &str) -> Result<()>;
    fn get_token(&self, db_key: &str) -> Result<Option<String>>;
    fn delete_token(&self, db_key: &str) -> Result<()>;
}

pub(super) struct KeyringAccountTokenStore;

impl AccountTokenStore for KeyringAccountTokenStore {
    fn set_token(&self, db_key: &str, token: &str) -> Result<()> {
        keyring::Entry::new(KEYRING_SERVICE_ACCOUNT, db_key)
            .and_then(|e| e.set_password(token))
            .map_err(|e| anyhow!("account_keyring_unavailable: {e}"))
    }

    fn get_token(&self, db_key: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE_ACCOUNT, db_key)
            .map_err(|e| anyhow!("account_keyring_unavailable: {e}"))?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("account_keyring_unavailable: {e}")),
        }
    }

    fn delete_token(&self, db_key: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE_ACCOUNT, db_key)
            .map_err(|e| anyhow!("account_keyring_unavailable: {e}"))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // 幂等
            Err(e) => Err(anyhow!("account_keyring_unavailable: {e}")),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct AccountLoginRequest {
    pub(super) account_id: String,
    pub(super) password: String,
    pub(super) device_name: String,
    #[serde(default)]
    pub(super) user_gesture: bool,
}

/// `account_login_response`：SRP 编排产物（core `AccountSrpLoginOutcome`
/// 的展示投影）。令牌本体直写 keyring，不过桥协议下发——扩展只见
/// 有效期与会话指纹（与桌面 account_srp_login 的响应口径一致）。
#[derive(Debug, Serialize)]
pub(super) struct AccountLoginPayload {
    pub(super) expires_in_secs: u64,
    pub(super) session_key_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub(super) struct AccountStatusPayload {
    pub(super) has_session: bool,
    pub(super) server_configured: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct AccountLogoutRequest {
    pub(super) account_id: String,
    #[serde(default)]
    pub(super) user_gesture: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct AccountLogoutPayload {
    pub(super) revoked_on_server: bool,
}

pub(super) async fn run_account_login(
    db_path: &Path,
    account_id: &str,
    password: &str,
    device_name: &str,
    store: &dyn AccountTokenStore,
) -> Result<AccountLoginPayload> {
    let server_url = read_sync_server_url(db_path).await?;
    let api = persona_core::accounts::remote::AccountsApi::new(&server_url).map_err(|e| {
        anyhow!("account_not_configured: invalid account server configuration: {e}")
    })?;
    // SRP 数学全在 core（口令不出编排模块）；桥只递口令与收编排产物
    let outcome = api
        .srp_login(account_id, device_name, password)
        .await
        .map_err(|e| anyhow!("account_login_failed: {e}"))?;
    let db_key = db_path.to_string_lossy().to_string();
    store
        .set_token(&db_key, &outcome.token)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(AccountLoginPayload {
        expires_in_secs: outcome.expires_in_secs,
        session_key_fingerprint: outcome.session_key_fingerprint,
    })
}

pub(super) async fn run_account_status(
    db_path: &Path,
    store: &dyn AccountTokenStore,
) -> Result<AccountStatusPayload> {
    let db_key = db_path.to_string_lossy().to_string();
    let has_session = store
        .get_token(&db_key)?
        .filter(|t| !t.trim().is_empty())
        .is_some();
    let server_configured = read_sync_server_url(db_path).await.is_ok();
    Ok(AccountStatusPayload {
        has_session,
        server_configured,
    })
}

pub(super) async fn run_account_logout(
    db_path: &Path,
    account_id: &str,
    store: &dyn AccountTokenStore,
) -> Result<AccountLogoutPayload> {
    let db_key = db_path.to_string_lossy().to_string();
    let bearer = store.get_token(&db_key)?.filter(|t| !t.trim().is_empty());
    let Some(bearer) = bearer else {
        // 本机已无令牌 = 已退出；幂等成功（与桌面 account_sign_out 同口径）
        return Ok(AccountLogoutPayload {
            revoked_on_server: false,
        });
    };
    let mut revoked_on_server = false;
    if let Ok(server_url) = read_sync_server_url(db_path).await {
        if let Ok(api) =
            persona_core::accounts::remote::AccountsApi::with_bearer(&server_url, &bearer)
        {
            revoked_on_server = api
                .revoke_account_session(account_id, &bearer)
                .await
                .is_ok();
        }
    }
    store.delete_token(&db_key)?;
    Ok(AccountLogoutPayload { revoked_on_server })
}
