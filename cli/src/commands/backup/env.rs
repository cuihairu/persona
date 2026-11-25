use anyhow::{bail, Context, Result};

use crate::utils::prompt::PromptUi;
use persona_core::backup::BackupClient;

/// Build the client only when both `PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN`
/// are non-empty (fail-closed, the same convention as event reporting; a missing
/// one errors outright — there is no sensible "silently skip" fallback for the
/// backup commands).
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

/// Backup passphrase resolution: `--passphrase-env VAR` (must already be set and
/// non-empty — a missing variable after an explicit name is a configuration
/// error, no silent fallback) → `PERSONA_PAYLOAD_PASSPHRASE` → interactive prompt.
/// push asks for confirmation (a new passphrase is typed twice); restore does not
/// (the passphrase already exists).
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
