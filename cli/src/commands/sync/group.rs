//! 跨设备同步配对（`persona sync group create|join|cancel|status`）：
//! 零账号、短码入组。
//!
//! 逐条镜像 desktop `sync_group_pairing_create`/`sync_group_pairing_poll`
//! （host 侧）与 `sync_group_join_begin`/`sync_group_join_confirm`/
//! `sync_group_join_cancel`（guest 侧），差异只在会话生命周期：桌面把配对
//! 状态放在 App 内存里跨命令传递（create → poll 两次调用），CLI 一进程一
//! 命令，所以 host 的「出码 + 等 guest」合成一条前台命令（90s 窗），
//! guest 的「起配 + 确认」合成一条（指纹比对经 `PromptUi::confirm`）。
//! 组密钥落 keyring `persona-sync-group`（与桌面 sync_group_store 同键）。

use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use colored::Colorize;
use persona_core::sync::keys::GroupKey;
use persona_core::sync::pairing::relay::PairingRelayClient;
use persona_core::sync::pairing::{PairingHost, PairingInviteLink};

use super::keyring;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;

/// 本 vault 是否已入跨设备同步组（keyring 组密钥条目为单一真相源；
/// 读失败 fail-closed 视为未入组，与桌面 `sync_group_joined` 同口径）。
fn group_joined(config: &CliConfig) -> bool {
    keyring::read_entry(keyring::KEYRING_SERVICE_SYNC_GROUP, &db_key(config))
        .ok()
        .flatten()
        .is_some()
}

fn db_key(config: &CliConfig) -> String {
    config.get_database_path().to_string_lossy().to_string()
}

/// 中转地址（配对信箱由 persona-server/relay 承载，取
/// `settings.sync.server_url`——与 server 形态同一部署面）。
async fn relay_url_for(config: &CliConfig) -> Result<String> {
    keyring::read_sync_server_url(&config.get_database_path()).await
}

/// host 出码：新建配对会话与中转信箱，展示动态密码，然后前台驱动握手
/// （90s 窗）。组密钥：本机已在组 = 复用；首次 = 随机生成。
pub(crate) async fn create(config: &CliConfig) -> Result<()> {
    let db_key = db_key(config);
    // 已入组则复用组密钥（桌面 create 同语义：把新设备纳入本组）
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

    // 完成才落组密钥（桌面在 poll 成功时落 keyring）；已有条目不覆写。
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

/// guest 输码入组：解码邀请串 → 起配 → 展示短指纹 → 用户确认一致才
/// 真正入组。指纹比对不通过即不收组密钥（安全边界：配对码可能被偷听，
/// 短指纹是唯一的人眼验证）。
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
        // 指纹不一致：绝不收组密钥。尽力清掉中转信箱（失败靠 TTL 回收）
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

/// 取消配对/加入：尽力清掉中转信箱（幂等；会话不存在也算成功——桌面
/// `sync_group_pairing_cancel` 同语义）。本地无会话状态（一进程一命令），
/// 所以这里只负责中转侧清理。
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

/// 同步组状态（只读，免解锁——同桌面 `sync_group_status` 口径）。
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
