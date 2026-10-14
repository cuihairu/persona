//! 一键启用/停用的真实落盘往返：不 mock 任何一层，直接调 command 层，
//! 把 HOME 指向临时目录，真写 ~/.ssh/config、真回读，断言「写入动作」与
//! 「状态字段」始终一致。
//!
//! 为什么是独立 integration test 而不是进程内单测：HOME 是进程级全局
//! 环境变量，同二进制里并行跑其它读 home 的测试会被串味；独立 test 进程
//! 各自持有自己的 HOME，互不干扰（同 command_layer_tests 的取参注入思路）。
//!
//! 为什么需要它：UI 侧「一键启用后开关状态联动」的缺陷根因是信任写入响应
//! 的快照而不回读真状态。回读链路必须被钉死在真实文件系统上——纯函数单测
//! （upsert/remove）过不了这一关，mock 的 invoke 也一样。
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use persona_desktop::commands;
use persona_desktop::ssh_integration as si;
use persona_desktop::types::ApiResponse;

/// 测试间串行化：HOME 全局共享，并行会互相覆盖对方的 config。
fn home_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// 指向临时 HOME 的守卫：建 `.ssh/` 目录，改 HOME 与 XDG_RUNTIME_DIR，
/// drop 时（仍在锁内）回收临时目录。
struct FakeHome {
    _dir: tempfile::TempDir,
}

impl FakeHome {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join(".ssh")).expect("mkdir .ssh");
        std::env::set_var("HOME", dir.path());
        // socket 路径来自 XDG_RUNTIME_DIR，指向临时目录免得在真机上 mkdir
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

/// command 层返回体解包：失败直接 panic（测试里等价于断言失败）。
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
    // 用户原有配置：停用后必须原样保留
    home.write_config("Host github.com\n  User git\n");

    // --- 一键启用 ---
    let after_enable = unwrap_status(commands::ssh_agent_integration_enable());
    assert!(after_enable.enabled, "enable 后回读仍是未启用");
    assert_eq!(
        after_enable.identity_agent.as_deref(),
        Some(si::identity_agent_value().as_str()),
        "enable 后 IdentityAgent 未指向当前 socket",
    );
    assert!(after_enable.anomaly.is_none(), "enable 后不应报配置异常");
    // 落盘内容 = 锚点块 + 用户原配置
    let on_disk = home.read_config();
    assert!(
        on_disk.contains("IdentityAgent "),
        "盘上缺 IdentityAgent 行"
    );
    assert!(on_disk.contains("Host github.com"), "盘上丢了用户原配置");

    // 幂等：再点一次启用，块不重复
    commands::ssh_agent_integration_enable().expect("second enable");
    let twice = home.read_config();
    assert_eq!(
        twice.matches("persona managed begin").count(),
        1,
        "重复启用产生了多个锚点块",
    );
    // 幂等写后回读仍一致
    assert!(unwrap_status(commands::ssh_agent_integration_enable()).enabled);

    // --- 一键停用 ---
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

    // 停用后再次状态查询（前端回读点）同样报未启用——两侧一致
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
    // 外部把锚点块改指到别处（等价于用户手改 config）
    let hijacked = home
        .read_config()
        .replace(&si::identity_agent_value(), "/tmp/foreign-agent.sock");
    home.write_config(&hijacked);

    // 回读如实报「配置异常」而不是谎报已启用
    let hijacked_status = commands::ssh_agent_integration_status();
    let hijacked_status = hijacked_status.data.expect("status data");
    assert!(!hijacked_status.enabled, "指向别处时不应报已启用");
    assert_eq!(
        hijacked_status.anomaly.as_deref(),
        Some("/tmp/foreign-agent.sock"),
        "异常字段未如实带上实际指向值",
    );

    // 重新一键启用 = 修复路径，回到一致
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
    // 让 config 路径读不出真内容：用目录顶替（读目录得到 EISDIR，既不是
    // NotFound 也不是可读文件）。不依赖 chmod——root 下权限位不生效。
    std::fs::remove_file(&path).expect("rm config");
    std::fs::create_dir(&path).expect("mkdir config-as-dir");

    let result = commands::ssh_agent_integration_enable();
    assert!(
        result.is_err(),
        "读不出 config 时应当拒写（否则空串 upsert 会覆盖用户配置）",
    );
    // 拒写生效：目录原样保留，没被 rename 掉
    assert!(path.is_dir(), "拒写路径上仍动了用户的 config 位置");
}
