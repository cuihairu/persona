//! A real on-disk round trip for one-click enable/disable: nothing is mocked,
//! the command layer is called directly, HOME points at a temp directory, and
//! ~/.ssh/config is really written and really read back, asserting that the
//! "write action" and the "status fields" always agree.
//!
//! Why a standalone integration test rather than in-process unit tests: HOME
//! is a process-wide global environment variable, so other tests reading home
//! that run in parallel inside the same binary would cross-contaminate;
//! separate test processes each own their own HOME and stay out of each
//! other's way (same argument-injection idea as command_layer_tests).
//!
//! Why it is needed: the root cause of the UI-side "toggle state not linked
//! after one-click enable" defect was trusting the write response snapshot
//! instead of reading the real state back. The read-back path has to be pinned
//! to the real filesystem — pure-function unit tests (upsert/remove) cannot
//! clear this bar, nor can a mocked invoke.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use persona_desktop::commands;
use persona_desktop::ssh_integration as si;
use persona_desktop::types::ApiResponse;

/// Serialize between tests: HOME is shared globally, and parallel tests would
/// overwrite each other's config
fn home_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Guard pointing HOME at a temp directory: creates the `.ssh/` directory,
/// changes HOME and XDG_RUNTIME_DIR, and reclaims the temp directory on drop
/// (still inside the lock).
struct FakeHome {
    _dir: tempfile::TempDir,
}

impl FakeHome {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join(".ssh")).expect("mkdir .ssh");
        std::env::set_var("HOME", dir.path());
        // The socket path comes from XDG_RUNTIME_DIR; point it at the temp
        // directory so nothing gets mkdir'ed on the real machine
        std::env::set_var("XDG_RUNTIME_DIR", dir.path().join("run"));
        Self { _dir: dir }
    }

    fn config_path(&self) -> PathBuf {
        self._dir.path().join(".ssh").join("config")
    }

    fn read_config(&self) -> String {
        std::fs::read_to_string(self.config_path()).unwrap_or_default()
    }

    fn write_config(&self, content: &str) {
        std::fs::write(self.config_path(), content).expect("seed config");
    }
}

/// Unwrap the command layer's response body: on failure, panic (equivalent to
/// an assertion failure inside a test).
fn unwrap_status(
    resp: Result<ApiResponse<si::SshIntegrationStatus>, String>,
) -> si::SshIntegrationStatus {
    let resp = resp.expect("command returned Err");
    assert!(resp.success, "command reported failure: {:?}", resp.error);
    resp.data.expect("success response carried no data")
}

#[test]
fn enable_then_disable_round_trips_through_the_real_config_file() {
    let _lock = home_lock();
    let home = FakeHome::new();
    // The user's pre-existing config: must be preserved verbatim after disable
    home.write_config("Host github.com\n  User git\n");

    // --- one-click enable ---
    let after_enable = unwrap_status(commands::ssh_agent_integration_enable());
    assert!(after_enable.enabled, "enable 后回读仍是未启用");
    assert_eq!(
        after_enable.identity_agent.as_deref(),
        Some(si::identity_agent_value().as_str()),
        "enable 后 IdentityAgent 未指向当前 socket",
    );
    assert!(after_enable.anomaly.is_none(), "enable 后不应报配置异常");
    // On-disk content = anchor block + the user's original config
    let on_disk = home.read_config();
    assert!(
        on_disk.contains("IdentityAgent "),
        "盘上缺 IdentityAgent 行"
    );
    assert!(on_disk.contains("Host github.com"), "盘上丢了用户原配置");

    // Idempotent: enabling again must not duplicate the block
    commands::ssh_agent_integration_enable().expect("second enable");
    let twice = home.read_config();
    assert_eq!(
        twice.matches("persona managed begin").count(),
        1,
        "重复启用产生了多个锚点块",
    );
    // Read back after the idempotent write: still consistent
    assert!(unwrap_status(commands::ssh_agent_integration_enable()).enabled);

    // --- one-click disable ---
    let after_disable = unwrap_status(commands::ssh_agent_integration_disable());
    assert!(!after_disable.enabled, "停用后回读仍是已启用");
    assert!(
        after_disable.identity_agent.is_none(),
        "停用后 IdentityAgent 仍被解析到",
    );
    let disk_after_disable = home.read_config();
    assert!(
        !disk_after_disable.contains("persona managed"),
        "盘上锚点块未移除",
    );
    assert!(
        disk_after_disable.contains("Host github.com") && disk_after_disable.contains("User git"),
        "停用误伤用户原配置",
    );

    // A status query after disabling (the frontend's read-back point) also
    // reports not-enabled — the two sides agree
    let status_resp = commands::ssh_agent_integration_status();
    assert!(status_resp.success);
    let status = status_resp.data.expect("status data");
    assert!(!status.enabled);
    assert_eq!(status.identity_agent, None);
}

#[test]
fn enable_reports_anomaly_until_re_enabled_after_foreign_override() {
    let _lock = home_lock();
    let home = FakeHome::new();

    unwrap_status(commands::ssh_agent_integration_enable());
    // Something external repoints the anchor block elsewhere (equivalent to a
    // user hand-editing the config)
    let hijacked = home
        .read_config()
        .replace(&si::identity_agent_value(), "/tmp/foreign-agent.sock");
    home.write_config(&hijacked);

    // The read-back reports "config anomaly" honestly rather than lying about
    // being enabled
    let hijacked_status = commands::ssh_agent_integration_status();
    let hijacked_status = hijacked_status.data.expect("status data");
    assert!(!hijacked_status.enabled, "指向别处时不应报已启用");
    assert_eq!(
        hijacked_status.anomaly.as_deref(),
        Some("/tmp/foreign-agent.sock"),
        "异常字段未如实带上实际指向值",
    );

    // One-click enable again = the repair path, back to consistency
    let repaired = unwrap_status(commands::ssh_agent_integration_enable());
    assert!(repaired.enabled, "重新启用后仍未生效");
    assert!(repaired.anomaly.is_none());
}

#[test]
fn enable_refuses_to_overwrite_an_unreadable_config() {
    let _lock = home_lock();
    let home = FakeHome::new();
    let path = home.config_path();
    home.write_config("Host github.com\n  User git\n");
    // Make the config path unreadable as real content: substitute a directory
    // (reading a directory yields EISDIR, which is neither NotFound nor a
    // readable file). Does not rely on chmod — permission bits are ignored
    // as root.
    std::fs::remove_file(&path).expect("rm config");
    std::fs::create_dir(&path).expect("mkdir config-as-dir");

    let result = commands::ssh_agent_integration_enable();
    assert!(
        result.is_err(),
        "读不出 config 时应当拒写（否则空串 upsert 会覆盖用户配置）",
    );
    // The write refusal took effect: the directory is left intact, not renamed away
    assert!(path.is_dir(), "拒写路径上仍动了用户的 config 位置");
}
