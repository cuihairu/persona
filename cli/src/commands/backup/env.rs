use anyhow::{bail, Context, Result};

use crate::utils::prompt::PromptUi;
use persona_core::backup::BackupClient;

/// `PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN` 都非空才构造客户端
/// （fail-closed，与事件上报同一惯例；缺一只直接报错——备份命令没有
/// "静默跳过"的合理降级）。
pub(super) fn client_from_env() -> Result<BackupClient> {
    let url = non_blank_env("PERSONA_SERVER_URL");
    let token = non_blank_env("PERSONA_SERVER_TOKEN");
    match (url, token) {
        (Some(url), Some(token)) => BackupClient::new(&url, token),
        _ => bail!("PERSONA_SERVER_URL and PERSONA_SERVER_TOKEN must both be set"),
    }
}

fn non_blank_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// 备份口令解析：`--passphrase-env VAR`（必须已设且非空——显式指定
/// 变量名后变量缺失是配置错误，不静默回退）→ `PERSONA_PAYLOAD_PASSPHRASE`
/// → 交互提示。push 带确认（新口令要录两遍），restore 不带（口令是既有的）。
pub(super) fn resolve_passphrase(
    env_var: Option<&str>,
    kind: &str,
    ui: &dyn PromptUi,
    confirm: bool,
) -> Result<String> {
    if let Some(var) = env_var {
        return std::env::var(var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| format!("--passphrase-env {var} is not set (or blank)"));
    }
    if let Ok(value) = std::env::var("PERSONA_PAYLOAD_PASSPHRASE") {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    let confirmation = confirm.then_some(("Confirm passphrase", "Passphrases do not match"));
    ui.password(&format!("Enter {kind} passphrase"), false, confirmation)
}
