//! Cross-device sync pairing (`persona sync group create|join|cancel|status`):
//! zero-account, short-code enrollment.
//!
//! Mirrors desktop `sync_group_pairing_create`/`sync_group_pairing_poll` (host side) and
//! `sync_group_join_begin`/`sync_group_join_confirm`/`sync_group_join_cancel` (guest side)
//! line by line; the only difference is session lifetime: the desktop keeps the pairing
//! state in App memory across commands (create → poll, two calls), while the CLI is one
//! process per command, so the host's "show code + wait for guest" is merged into one
//! foreground command (a 90s window), and the guest's "begin pairing + confirm" into one
//! (the fingerprint comparison goes through `PromptUi::confirm`).
//! The group key lands in keyring `persona-sync-group` (same key as the desktop sync_group_store).

use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use colored::Colorize;
use persona_core::sync::keys::GroupKey;
use persona_core::sync::pairing::relay::PairingRelayClient;
use persona_core::sync::pairing::{PairingHost, PairingInviteLink};

use super::keyring;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;

/// Whether this vault has joined a cross-device sync group (the keyring group-key entry is
/// the single source of truth; a read failure fails closed and counts as not joined, the
/// same terms as the desktop `sync_group_joined`).
fn group_joined(config: &CliConfig) -> bool {
    keyring::read_entry(keyring::KEYRING_SERVICE_SYNC_GROUP, &db_key(config))
        .ok()
        .flatten()
        .is_some()
}

fn db_key(config: &CliConfig) -> String {
    config.get_database_path().to_string_lossy().to_string()
}

/// Relay address (the pairing mailbox is carried by persona-server/relay, taken from
/// `settings.sync.server_url` — the same deployment surface as the server form).
async fn relay_url_for(config: &CliConfig) -> Result<String> {
    keyring::read_sync_server_url(&config.get_database_path()).await
}

/// Host shows the code: create a pairing session and relay mailbox, display the dynamic
/// password, then drive the handshake in the foreground (90s window). Group key: this
/// machine already in the group = reuse; first time = generated at random.
pub(crate) async fn create(config: &CliConfig) -> Result<()> {
    let db_key = db_key(config);
    // Already in the group → reuse the group key (same semantics as the desktop create: bring the new device into this group)
    let group_key = match keyring::read_entry(keyring::KEYRING_SERVICE_SYNC_GROUP, &db_key)? {
        Some(hex) => {
            let bytes = keyring::group_key_from_hex(&hex).ok_or_else(|| {
                anyhow!("sync_group_key_failed: existing sync-group key entry is corrupted")
            })?;
            GroupKey::from_bytes(bytes)
        }
        None => GroupKey::generate().map_err(|e| anyhow!("sync_group_key_failed: {e}"))?,
    };

    let relay_url = relay_url_for(config).await?;
    let (mut host, invite) =
        PairingHost::new_invite().map_err(|e| anyhow!("sync_pairing_failed: {e}"))?;
    let relay =
        PairingRelayClient::new(&relay_url).map_err(|e| anyhow!("sync_pairing_failed: {e}"))?;
    let (session_id, expires_in_secs) = relay
        .create_session(&invite.salt)
        .await
        .map_err(|e| anyhow!("sync_pairing_failed: cannot create relay mailbox: {e}"))?;
    let invite_link = PairingInviteLink {
        code: invite.code.clone(),
        relay_url: relay_url.clone(),
        session_id: session_id.clone(),
    }
    .encode();

    println!("{}", "🔐 Cross-device sync pairing".cyan().bold());
    println!(
        "  {}  {}",
        "pairing code".bright_black(),
        invite.code.green().bold()
    );
    println!("  {}  {}", "invite link".bright_black(), invite_link);
    println!(
        "  {}  {} (expires in ~{}s)",
        "mailbox".bright_black(),
        session_id.bright_black(),
        expires_in_secs
    );
    println!();
    println!(
        "  {}",
        "⏳ Waiting for the other device… (paste the code or link there)".bright_black()
    );

    let started = Instant::now();
    let fingerprint = relay
        .drive_host(&mut host, group_key.as_bytes(), &session_id)
        .await
        .map_err(|e| anyhow!("sync_pairing_failed: {e}"))?;
    let elapsed = started.elapsed();

    // The group key is stored only on completion (the desktop stores it in the keyring when poll succeeds); an existing entry is not overwritten.
    if keyring::read_entry(keyring::KEYRING_SERVICE_SYNC_GROUP, &db_key)?.is_none() {
        keyring::write_entry(
            keyring::KEYRING_SERVICE_SYNC_GROUP,
            &db_key,
            &keyring::group_key_to_hex(group_key.as_bytes()),
        )
        .map_err(|e| anyhow!("sync_group_key_failed: cannot persist group key: {e}"))?;
    }
    println!();
    println!(
        "{}  added in {:.0}s",
        "✓ Device added".green().bold(),
        elapsed.as_secs_f64()
    );
    println!(
        "  {}  {}",
        "security fingerprint".bright_black(),
        fingerprint.cyan()
    );
    println!(
        "  {} Compare it with the one shown on the added device.",
        "⚠️".yellow()
    );
    Ok(())
}

/// Guest enters the code to join: decode the invite string → begin pairing → show the
/// short fingerprint → only join for real once the user confirms it matches. If the
/// fingerprint comparison fails the group key is never accepted (security boundary: the
/// pairing code may be overheard, and the short fingerprint is the only human-eye check).
pub(crate) async fn join(config: &CliConfig, invite_link: &str, ui: &dyn PromptUi) -> Result<()> {
    let db_key = db_key(config);
    if group_joined(config) {
        bail!("This vault already joined a sync group; leave it before joining another");
    }
    let link = PairingInviteLink::decode(invite_link.trim())
        .map_err(|e| anyhow!("sync_pairing_failed: invalid invite link: {e}"))?;
    let relay = PairingRelayClient::new(&link.relay_url)
        .map_err(|e| anyhow!("sync_pairing_failed: {e}"))?;
    let (mut guest, fingerprint) = relay
        .join_begin(&link)
        .await
        .map_err(|e| anyhow!("sync_pairing_failed: {e}"))?;

    println!("{}", "🔑 Joining cross-device sync group".cyan().bold());
    println!(
        "  {}  {}",
        "pairing code".bright_black(),
        link.code.green().bold()
    );
    println!(
        "  {}  {}",
        "security fingerprint".bright_black(),
        fingerprint.cyan()
    );
    println!();
    if !ui.confirm(
        "Does the fingerprint match the one shown on the host device?",
        false,
    )? {
        // Fingerprint mismatch: never accept the group key. Best-effort clear of the relay mailbox (a failure is left to TTL collection)
        if let Err(e) = relay.delete_session(&link.session_id).await {
            tracing::warn!(
                %e,
                "pairing relay mailbox cleanup failed; TTL will reclaim it"
            );
        }
        println!("{}", "✗ Fingerprint mismatch — not joining".yellow());
        return Ok(());
    }

    relay
        .join_confirm(&mut guest, &link.session_id)
        .await
        .map_err(|e| anyhow!("sync_pairing_failed: {e}"))?;
    let group_key = guest
        .group_key()
        .ok_or_else(|| anyhow!("sync_group_key_failed: pairing completed without a group key"))?;
    keyring::write_entry(
        keyring::KEYRING_SERVICE_SYNC_GROUP,
        &db_key,
        &keyring::group_key_to_hex(group_key),
    )
    .map_err(|e| anyhow!("sync_group_key_failed: joined but cannot persist group key: {e}"))?;
    println!(
        "{}",
        "✓ Joined the sync group (group key stored in the OS keyring)"
            .green()
            .bold()
    );
    Ok(())
}

/// Cancel pairing/joining: best-effort clear of the relay mailbox (idempotent; a missing
/// session also counts as success — same semantics as the desktop
/// `sync_group_pairing_cancel`). There is no local session state (one process per
/// command), so this only handles the relay-side cleanup.
pub(crate) async fn cancel(config: &CliConfig, session_id: &str) -> Result<()> {
    let relay_url = relay_url_for(config).await?;
    let relay =
        PairingRelayClient::new(&relay_url).map_err(|e| anyhow!("sync_pairing_failed: {e}"))?;
    if let Err(e) = relay.delete_session(session_id).await {
        tracing::warn!(
            %e,
            "pairing relay mailbox cleanup failed; TTL will reclaim it"
        );
    }
    println!("{}", "✓ Pairing session cancelled".green().bold());
    Ok(())
}

/// Sync group status (read-only, no unlock needed — same terms as the desktop `sync_group_status`).
pub(crate) fn status(config: &CliConfig) -> Result<()> {
    let joined = group_joined(config);
    println!(
        "  {}",
        if joined {
            "joined".green().to_string()
        } else {
            "not joined".bright_black().to_string()
        }
    );
    Ok(())
}
