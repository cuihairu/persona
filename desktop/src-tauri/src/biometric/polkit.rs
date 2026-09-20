//! Linux：polkit `CheckAuthorization` 认证弹框。
//!
//! 不依赖 zbus_polkit（<5.1.0 的 CVE-2026-78422：unix-process subject
//! 的 uid 编码错型，可被 PID 复用绕过）——手写一条 D-Bus 调用，subject
//! 用 system-bus-name：polkit 经 bus daemon 自己解析对端凭据，天然免疫
//! PID 复用类缺陷。zbus 5 已因 keyring 在依赖树里，零新增依赖。
//!
//! action 文件（`desktop/src-tauri/polkit/*.policy`）随 deb 安装到
//! `/usr/share/polkit-1/actions/`；rpm/AppImage/dev 构建没装它时
//! `CheckAuthorization` 报 ActionUnknown → availability/ceremony 失败
//! → 功能 fail-closed 降级（文档明示）。

use zbus::blocking::{Connection, Proxy};

/// polkit action id（与应用 identifier 对齐，见 tauri.conf.json）
const ACTION_ID: &str = "com.persona.desktop.biometric-unlock";

const POLKIT_DBUS: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// CheckAuthorizationFlags 的 AllowUserInteraction 位（允许 polkit 弹
/// agent 认证框，而非直接拒绝不可交互的授权）
const ALLOW_USER_INTERACTION: u32 = 1;

pub fn platform_name() -> &'static str {
    "linux-polkit"
}

/// system bus 可达且 polkit daemon 在运行（有属主）。action 文件缺失
/// 不在此处探测——它留给 ceremony 的真实错误暴露，避免两跳 D-Bus。
pub fn available() -> bool {
    let Ok(conn) = Connection::system() else {
        return false;
    };
    let dbus = match Proxy::new(
        &conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    ) {
        Ok(proxy) => proxy,
        Err(_) => return false,
    };
    let has_owner: bool = dbus
        .call_method("NameHasOwner", &(POLKIT_DBUS,))
        .and_then(|reply| reply.body().deserialize())
        .unwrap_or(false);
    has_owner
}

/// 弹出系统 polkit 认证框（本机无指纹设备时 agent 自动回落到密码
/// 认证，同样是合法验证面——auth_self 语义）。
pub fn ceremony(reason: &str) -> Result<(), String> {
    let conn = Connection::system().map_err(|e| format!("system bus unavailable: {e}"))?;
    let authority = Proxy::new(&conn, POLKIT_DBUS, POLKIT_PATH, POLKIT_IFACE)
        .map_err(|e| format!("polkit proxy failed: {e}"))?;

    // system-bus-name subject：值是本连接在 system bus 上的唯一名，
    // polkit 拿它向 bus daemon 查对端凭据（uid/pid），不经调用方自报
    let unique_name = conn
        .unique_name()
        .map(|name| name.to_string())
        .ok_or_else(|| "no unique name on system bus".to_string())?;
    let mut subject_props = std::collections::HashMap::new();
    subject_props.insert("name", zbus::zvariant::Value::from(unique_name));
    let subject = ("system-bus-name", subject_props);

    // CheckAuthorization(Subject, action_id, flags, cancellation_id)
    //   → ((authorized, challenged), details)
    let reply = authority
        .call_method(
            "CheckAuthorization",
            &(&subject, ACTION_ID, ALLOW_USER_INTERACTION, ""),
        )
        .map_err(|e| format!("polkit CheckAuthorization failed: {e}"))?;
    let (outcome, _details): (
        (bool, bool),
        std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    ) = reply
        .body()
        .deserialize()
        .map_err(|e| format!("unexpected polkit reply: {e}"))?;

    if outcome.0 {
        let _ = reason; // polkit 弹框文案由 .policy 文件的 message 提供
        Ok(())
    } else {
        Err("polkit authorization denied".to_string())
    }
}
