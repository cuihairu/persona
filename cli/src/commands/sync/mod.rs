//! `persona sync …`: the command surface for E2EE oplog sync (the server/relay form).
//!
//! Shares the same core orchestration (`SyncSession::open` → backfill → run_cycle / status)
//! and the same keyring entries with the desktop `sync_*` command family and the
//! browser-extension bridge's `sync_push_now` (the service name is a protocol-level
//! constant, see [`keyring`]). The differences are only three:
//! - the master key follows the CLI unlock convention (`PERSONA_MASTER_PASSWORD` env
//!   takes priority, otherwise an interactive prompt);
//! - the session hangs no capture seam — one process per command, so a seam dying with the
//!   process is meaningless (same reason as the bridge comment);
//! - the server address comes from the vault's `settings.sync.server_url` and the token
//!   from keyring `persona-sync` (same key as the desktop; configure once, effective everywhere).

pub mod devices;
pub mod group;
pub mod keyring;
pub mod rotate;
pub mod session;

use anyhow::Result;
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};

#[derive(Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    command: SyncCommand,
}

#[derive(Subcommand)]
enum SyncCommand {
    /// Push and pull now (manual sync cycle)
    Now,
    /// Show group watermark / local watermark / pending push
    Status,
    /// Register this device with the sync server
    Join {
        /// Device name shown to the other devices in the group
        #[arg(long)]
        name: String,
    },
    /// Remove this device from sync (revoke on server + clear keyring)
    Leave,
    /// List devices in the sync group
    Devices,
    /// Authorize a pending device (deliver the group key to it)
    Authorize {
        /// Target device id (UUID, from `devices`)
        target: String,
    },
    /// Revoke a device on the server (idempotent)
    Revoke {
        /// Target device id (UUID, from `devices`)
        target: String,
    },
    /// Set this device's remark (server locks it to the token owner)
    SetRemark {
        /// Remark text (blank clears it)
        remark: String,
    },

    /// Cross-device sync: zero-account pairing by short code
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },

    /// Rotate the sync group key (re-wrap every credential under it)
    Rotate,

    /// Concurrent-edit conflicts needing a decision
    Conflicts {
        #[command(subcommand)]
        command: ConflictsCommand,
    },
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Host: show a pairing code and wait for the other device (90s window)
    Create,
    /// Guest: join with an invite link or the pairing code
    Join {
        /// Invite link (or the raw pairing code) shown by the host
        invite: String,
    },
    /// Cancel a pairing session (best-effort relay mailbox cleanup)
    Cancel {
        /// Mailbox session id shown by `create`
        session: String,
    },
    /// Whether this vault is in a sync group (unlock-free, read-only)
    Status,
}

#[derive(Subcommand)]
enum ConflictsCommand {
    /// List the pending conflict entries with their versions
    List,
    /// Adopt one version of a conflicted entry
    Resolve {
        /// Conflicted entry id (UUID, from `list`)
        item: String,
        /// Version to adopt (op id, from `list`)
        #[arg(long)]
        adopt: String,
    },
}

pub async fn execute(args: SyncArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: SyncArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        SyncCommand::Now => now(config, ui).await,
        SyncCommand::Status => status(config, ui).await,
        SyncCommand::Join { name } => {
            session::open_unlocked(config, ui).await?;
            devices::join(config, &name).await
        }
        SyncCommand::Leave => {
            session::open_unlocked(config, ui).await?;
            devices::leave(config).await
        }
        SyncCommand::Devices => {
            session::open_unlocked(config, ui).await?;
            devices::list_devices(config).await
        }
        SyncCommand::Authorize { target } => {
            session::open_unlocked(config, ui).await?;
            devices::authorize(config, &target).await
        }
        SyncCommand::Revoke { target } => {
            session::open_unlocked(config, ui).await?;
            devices::revoke(config, &target).await
        }
        SyncCommand::SetRemark { remark } => {
            session::open_unlocked(config, ui).await?;
            devices::set_remark(config, &remark).await
        }
        SyncCommand::Group { command } => match command {
            // Showing the code / joining both require an unlocked vault: the group key is E2EE
            // material that is only trustworthy after unlock, and this matches the desktop's
            // require_unlocked terms (preventing "handing out codes without unlocking").
            GroupCommand::Create => {
                session::open_unlocked(config, ui).await?;
                group::create(config).await
            }
            GroupCommand::Join { invite } => {
                session::open_unlocked(config, ui).await?;
                group::join(config, &invite, ui).await
            }
            GroupCommand::Cancel { session } => group::cancel(config, &session).await,
            GroupCommand::Status => group::status(config),
        },
        SyncCommand::Rotate => rotate::rotate(config, ui).await,
        SyncCommand::Conflicts { command } => match command {
            ConflictsCommand::List => rotate::list_conflicts(config, ui).await,
            ConflictsCommand::Resolve { item, adopt } => {
                rotate::resolve_conflict(config, &item, &adopt, ui).await
            }
        },
    }
}

// -----------------------------------------------------------------------
// Sync cycle / status
// -----------------------------------------------------------------------

/// Sync now: unwrap the local envelope to assemble the session → backfill the backlog → pull/materialize/push cycle.
/// The orchestration runs in exactly the same order as the bridge's `sync_push_now` and the desktop's `sync_now`.
async fn now(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    let (session, service) = session::open_sync_session(config, ui).await?;
    let master = service
        .get_master_encryption_service()
        .map_err(|e| anyhow::anyhow!("locked: master key unavailable: {e}"))?;

    let backfilled = session
        .backfill_existing(master)
        .await
        .map_err(|e| anyhow::anyhow!("sync_cycle_failed: backfill: {e}"))?;
    let report = session
        .run_cycle(master)
        .await
        .map_err(|e| anyhow::anyhow!("sync_cycle_failed: {e}"))?;

    println!("{}", "🔄 Sync cycle complete".cyan().bold());
    println!(
        "  pushed:        {}   pulled: {}   materialized: {}",
        report.pushed, report.pulled, report.materialized
    );
    println!(
        "  backfilled:    {}   pending identity: {}   conflicts: {}",
        report.backfilled, report.pending_identity, report.conflicts
    );
    if backfilled > 0 {
        println!(
            "  {} existing credentials imported into the oplog",
            format!("({backfilled})").bright_black()
        );
    }
    if report.conflicts > 0 {
        println!(
            "  {}",
            "⚠️  concurrent edits need a decision (see the desktop conflict view)".yellow()
        );
    }
    Ok(())
}

/// A sync status snapshot (read-only, no cycle run): the group's latest version / this
/// machine's watermark / entries behind / entries pending push / last sync time.
async fn status(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    let (session, _service) = session::open_sync_session(config, ui).await?;
    let report = session
        .status()
        .await
        .map_err(|e| anyhow::anyhow!("sync_status_failed: {e}"))?;

    println!("{}", "📶 Sync status".cyan().bold());
    println!("  group version:      {}", report.head_seq);
    println!("  local watermark:    {}", report.local_watermark);
    println!(
        "  {}",
        if report.behind == 0 {
            "up to date".green().to_string()
        } else {
            format!("{} commands behind", report.behind)
                .yellow()
                .to_string()
        }
    );
    println!("  pending push:       {}", report.pending_push);
    println!(
        "  last sync:          {}",
        match report.last_sync_at {
            Some(at) => at.to_rfc3339(),
            None => "never".to_string(),
        }
    );
    Ok(())
}
// -----------------------------------------------------------------------
// Tests: early-failure paths + the clap surface (the positive paths over network/real
// keyring are backed by scripts/verify-sync-group-pairing.sh and the core/desktop tests)
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use persona_core::sync::remote::SyncGroupKeyEntry;
    use uuid::Uuid;

    /// The full clap surface (subcommands + positional args + the `--adopt`/`--name` long options).
    #[test]
    fn clap_surface_parses() {
        use crate::Commands;
        use clap::Parser;
        for argv in [
            vec!["persona", "sync", "now"],
            vec!["persona", "sync", "status"],
            vec!["persona", "sync", "join", "--name", "laptop"],
            vec!["persona", "sync", "leave"],
            vec!["persona", "sync", "devices"],
            vec![
                "persona",
                "sync",
                "authorize",
                "3b8a1c2e-0000-0000-0000-000000000000",
            ],
            vec![
                "persona",
                "sync",
                "revoke",
                "3b8a1c2e-0000-0000-0000-000000000000",
            ],
            vec!["persona", "sync", "set-remark", "my home box"],
            vec!["persona", "sync", "group", "create"],
            vec!["persona", "sync", "group", "join", "persona://sync"],
            vec!["persona", "sync", "group", "cancel", "sess-1"],
            vec!["persona", "sync", "group", "status"],
            vec!["persona", "sync", "rotate"],
            vec!["persona", "sync", "conflicts", "list"],
            vec![
                "persona",
                "sync",
                "conflicts",
                "resolve",
                "3b8a1c2e-0000-0000-0000-000000000000",
                "--adopt",
                "3b8a1c2e-0000-0000-0000-000000000001",
            ],
        ] {
            let argv_label = format!("{argv:?}");
            let cli = crate::Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("`{argv_label}` should parse: {e:?}"));
            assert!(
                matches!(cli.command, Commands::Sync(_)),
                "`{argv_label}` should dispatch to sync"
            );
        }
    }

    fn tmp_config() -> (tempfile::TempDir, CliConfig) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        (dir, config)
    }

    /// The device-name gate fires before touching the keyring/server (cheap errors first).
    #[tokio::test]
    async fn join_rejects_bad_device_names_before_any_io() {
        let (_dir, config) = tmp_config();
        for name in ["", "   ", &"x".repeat(129)] {
            let err = devices::join(&config, name).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("Device name must be 1..=128 bytes"),
                "name {name:?} → {err}"
            );
        }
    }

    /// authorize/revoke on a vault that has not joined: the gate fires before resolving the target (fail-closed).
    #[tokio::test]
    async fn device_actions_require_a_joined_vault() {
        let (_dir, config) = tmp_config();
        for err in [
            devices::authorize(&config, "any").await.unwrap_err(),
            devices::revoke(&config, "any").await.unwrap_err(),
            devices::set_remark(&config, "r").await.unwrap_err(),
            devices::leave(&config).await.unwrap_err(),
        ] {
            assert!(
                err.to_string().contains("has not joined sync"),
                "unexpected early error: {err}"
            );
        }
    }

    /// The conflict-resolution UUID parsing happens before session assembly (a malformed format errors without unlocking).
    #[tokio::test]
    async fn conflict_resolve_rejects_malformed_ids() {
        let (_dir, config) = tmp_config();
        for (item, adopt) in [
            ("not-a-uuid", "3b8a1c2e-0000-0000-0000-000000000000"),
            ("3b8a1c2e-0000-0000-0000-000000000000", "oops"),
        ] {
            let err = rotate::resolve_conflict(&config, item, adopt, &TerminalUi)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("Malformed"),
                "{item} / {adopt} → {err}"
            );
        }
    }

    /// Group-key envelope round trip: sealed to this machine's public key → unwrapping yields the original value; no local envelope → awaiting authorization.
    #[test]
    fn own_group_key_round_trips_and_missing_envelope_fails_closed() {
        let identity = persona_core::sync::device::DeviceIdentity::generate("device-a")
            .unwrap()
            .with_device_id(Uuid::new_v4());
        let group_key = [7u8; 32];
        let envelope = persona_core::sync::envelope::seal_group_key(
            &group_key,
            identity.key_pair.public_bytes(),
        )
        .unwrap();
        let entries = vec![SyncGroupKeyEntry {
            device_id: identity.device_id,
            envelope,
            sealed_by: identity.device_id.to_string(),
            created_at: String::new(),
        }];
        assert_eq!(
            keyring::open_own_group_key(&entries, &identity).unwrap(),
            group_key
        );

        // Another device's envelope enters the list: this machine has no envelope of its own →
        // awaiting authorization (fail-closed). The device_ids must all differ (generate gives
        // nil; only after with_device_id fills it back in does it become the server-assigned
        // id — nils would collide and find would mismatch).
        let other = persona_core::sync::device::DeviceIdentity::generate("device-b")
            .unwrap()
            .with_device_id(Uuid::new_v4());
        assert_ne!(identity.device_id, other.device_id);
        let envelope =
            persona_core::sync::envelope::seal_group_key(&group_key, other.key_pair.public_bytes())
                .unwrap();
        let foreign = vec![SyncGroupKeyEntry {
            device_id: other.device_id,
            envelope,
            sealed_by: other.device_id.to_string(),
            created_at: String::new(),
        }];
        let err = keyring::open_own_group_key(&foreign, &identity).unwrap_err();
        assert!(err.to_string().contains("sync_not_authorized"), "{err}");
    }

    /// Group-key hex encode/decode (the keyring value format: 32 bytes ↔ 64 chars).
    #[test]
    fn group_key_hex_round_trips_and_rejects_junk() {
        let key = [0xABu8; 32];
        let hex = keyring::group_key_to_hex(&key);
        assert_eq!(hex.len(), 64);
        assert_eq!(keyring::group_key_from_hex(&hex).unwrap(), key);
        assert_eq!(keyring::group_key_from_hex("zz"), None);
        assert_eq!(keyring::group_key_from_hex(&"a".repeat(63)), None);
        assert_eq!(keyring::group_key_from_hex(&"g".repeat(64)), None);
    }

    /// Group status read without unlocking (no keyring entry → not joined, no error).
    #[test]
    fn group_status_reads_unlock_free() {
        let (_dir, config) = tmp_config();
        group::status(&config).unwrap();
    }
}
