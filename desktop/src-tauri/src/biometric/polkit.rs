//! Linux: the polkit `CheckAuthorization` authentication prompt.
//!
//! Deliberately does not depend on zbus_polkit (CVE-2026-78422 in <5.1.0:
//! mistyped uid encoding for unix-process subjects, bypassable via PID reuse)
//! — instead it issues a hand-written D-Bus call using a system-bus-name subject:
//! polkit resolves the peer credentials itself through the bus daemon, which is
//! inherently immune to PID-reuse style defects. zbus 5 is already in the
//! dependency tree via keyring, so there are zero new dependencies.
//!
//! The action file (`desktop/src-tauri/polkit/*.policy`) is installed by the
//! deb into `/usr/share/polkit-1/actions/`; on rpm/AppImage/dev builds where it
//! is not installed, `CheckAuthorization` reports ActionUnknown, availability and
//! ceremony fail, and the feature degrades fail-closed (documented).

use zbus::blocking::{Connection, Proxy};

/// polkit action id (aligned with the app identifier, see tauri.conf.json)
const ACTION_ID: &str = "com.persona.desktop.biometric-unlock";

const POLKIT_DBUS: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// AllowUserInteraction bit of CheckAuthorizationFlags (lets polkit pop the
/// agent authentication dialog instead of immediately denying an
/// authorization that cannot interact)
const ALLOW_USER_INTERACTION: u32 = 1;

pub fn platform_name() -> &'static str {
    "linux-polkit"
}

/// system bus is reachable and the polkit daemon is running (has an owner).
/// A missing action file is not probed here — that is left to surface through
/// the ceremony's real error, avoiding a two-hop D-Bus round trip.
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

/// Pops the system polkit authentication dialog (when the machine has no
/// fingerprint device, the agent automatically falls back to password
/// authentication, which is equally a legitimate verification surface —
/// auth_self semantics).
pub fn ceremony(reason: &str) -> Result<(), String> {
    let conn = Connection::system().map_err(|e| format!("system bus unavailable: {e}"))?;
    let authority = Proxy::new(&conn, POLKIT_DBUS, POLKIT_PATH, POLKIT_IFACE)
        .map_err(|e| format!("polkit proxy failed: {e}"))?;

    // system-bus-name subject: the value is this connection's unique name on
    // the system bus; polkit uses it to ask the bus daemon for the peer
    // credentials (uid/pid), rather than trusting a caller-supplied claim
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
        let _ = reason; // the polkit dialog wording is provided by the .policy file's message
        Ok(())
    } else {
        Err("polkit authorization denied".to_string())
    }
}
