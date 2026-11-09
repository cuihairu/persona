use super::*;

/// Overall deadline for one approval round-trip. The desktop side denies on
/// its own after 120s; this only guards against a hung server.
/// Everything in the desktop-approval mechanism rides a Unix socket —
/// definitions are cfg(unix) so Windows builds don't carry dead code.
#[cfg(unix)]
pub(super) const DESKTOP_APPROVAL_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DesktopApprovalMode {
    /// Consult the desktop when its approval socket exists (default).
    Auto,
    /// Always require desktop approval; fail closed when unreachable.
    Require,
    /// Never ask the desktop.
    Off,
}

pub(super) fn desktop_approval_mode() -> DesktopApprovalMode {
    match std::env::var("PERSONA_BRIDGE_DESKTOP_APPROVAL") {
        Ok(v) if v.eq_ignore_ascii_case("require") => DesktopApprovalMode::Require,
        Ok(v) if v.eq_ignore_ascii_case("off") || v == "0" || v.eq_ignore_ascii_case("false") => {
            DesktopApprovalMode::Off
        }
        _ => DesktopApprovalMode::Auto,
    }
}

/// Approval socket next to the SSH agent state dir (`~/.persona/` by
/// default); `PERSONA_PASSKEY_APPROVAL_SOCKET` overrides (tests).
#[cfg(unix)]
pub(super) fn desktop_approval_socket_path() -> PathBuf {
    std::env::var("PERSONA_PASSKEY_APPROVAL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let dir = std::env::var("PERSONA_AGENT_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(".persona")
                });
            dir.join("passkey-approval.sock")
        })
}

/// What the desktop answered for one passkey request. `Approved`/`Denied`
/// only exist where the socket mechanism does (unix); on other platforms the
/// gate can only answer `Unavailable`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum DesktopApproval {
    #[cfg(unix)]
    Approved,
    #[cfg(unix)]
    Denied(String),
    /// No desktop to ask (socket missing/unreachable, or a platform without
    /// Unix sockets): the caller falls back to the existing gesture gate.
    Unavailable,
}

#[derive(Debug, Serialize)]
#[cfg(unix)]
pub(super) struct DesktopApprovalRequest<'a> {
    pub(super) v: u8,
    pub(super) op: &'a str,
    pub(super) rp_id: Option<&'a str>,
    pub(super) origin: &'a str,
    pub(super) user_name: Option<&'a str>,
    pub(super) item_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[cfg(unix)]
pub(super) struct DesktopApprovalResponse {
    #[serde(default)]
    pub(super) approved: bool,
    #[serde(default)]
    pub(super) reason: Option<String>,
}

/// Ask the running desktop app to confirm one passkey request.
///
/// `PERSONA_BRIDGE_DESKTOP_APPROVAL` controls the policy: `auto` (default)
/// consults the desktop when its socket exists and falls back to the plain
/// gesture gate otherwise; `require` fails the request when the desktop
/// cannot be reached; `off` skips the gate entirely.
pub(super) async fn desktop_approval_gate(
    op: &str,
    rp_id: Option<&str>,
    origin: &str,
    user_name: Option<&str>,
    item_id: Option<&str>,
) -> Result<DesktopApproval> {
    let mode = desktop_approval_mode();
    if mode == DesktopApprovalMode::Off {
        return Ok(DesktopApproval::Unavailable);
    }

    #[cfg(unix)]
    {
        let request = DesktopApprovalRequest {
            v: 1,
            op,
            rp_id,
            origin,
            user_name,
            item_id,
        };
        match ask_desktop_approval(&request, &desktop_approval_socket_path()).await {
            Ok(resp) if resp.approved => Ok(DesktopApproval::Approved),
            Ok(resp) => Ok(DesktopApproval::Denied(
                resp.reason.unwrap_or_else(|| "denied".to_string()),
            )),
            Err(e) => {
                warn!(op, error = %e, "desktop approval unavailable");
                if mode == DesktopApprovalMode::Require {
                    Err(anyhow!(
                        "passkey_desktop_approval_required: desktop approval is mandatory but the desktop app is unreachable"
                    ))
                } else {
                    Ok(DesktopApproval::Unavailable)
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (op, rp_id, origin, user_name, item_id);
        if mode == DesktopApprovalMode::Require {
            return Err(anyhow!(
                "passkey_desktop_approval_required: desktop approval is mandatory but unavailable on this platform"
            ));
        }
        Ok(DesktopApproval::Unavailable)
    }
}

/// One request, one connection: send the JSON line, read the answer.
#[cfg(unix)]
pub(super) async fn ask_desktop_approval(
    request: &DesktopApprovalRequest<'_>,
    socket_path: &Path,
) -> Result<DesktopApprovalResponse> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut line = serde_json::to_string(request)?;
    line.push('\n');

    let io = async {
        let stream = tokio::net::UnixStream::connect(socket_path).await?;
        let mut stream = stream;
        stream.write_all(line.as_bytes()).await?;
        let mut reader = BufReader::new(stream);
        let mut answer = String::new();
        reader.read_line(&mut answer).await?;
        Ok::<_, std::io::Error>(answer)
    };
    let answer = tokio::time::timeout(DESKTOP_APPROVAL_TIMEOUT, io)
        .await
        .map_err(|_| anyhow!("desktop approval timed out"))??;

    if answer.trim().is_empty() {
        return Err(anyhow!("desktop approval closed the connection"));
    }
    serde_json::from_str(&answer).with_context(|| format!("invalid approval response: {answer}"))
}
