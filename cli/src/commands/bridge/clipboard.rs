use super::*;

/// Log a successful copy and build the wire response. Split out so the
/// success tail stays reachable on headless machines without a clipboard.
pub(super) fn copy_success_response(
    request_id: Option<String>,
    origin: &str,
    host: &str,
    item_id: &str,
    item_name: &str,
    field: &str,
) -> Result<BridgeResponse<serde_json::Value>> {
    info!(
        event = "bridge_copy_success",
        origin = %origin,
        host = %host,
        item_id = %item_id,
        item_name = %item_name,
        field = %field,
        "copied to clipboard"
    );

    Ok(ok(
        request_id,
        "copy_response",
        serde_json::to_value(CopyResponse {
            copied: true,
            clear_after_seconds: None,
        })?,
    ))
}

#[cfg(target_os = "macos")]
pub(super) fn copy_text_to_clipboard(text: &str) -> Result<()> {
    pipe_to_command("pbcopy", &[], text)
}

#[cfg(target_os = "windows")]
pub(super) fn copy_text_to_clipboard(text: &str) -> Result<()> {
    if pipe_to_command("cmd", &["/C", "clip"], text).is_ok() {
        return Ok(());
    }
    pipe_to_command(
        "powershell",
        &["-NoProfile", "-Command", "Set-Clipboard"],
        text,
    )
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(super) fn copy_text_to_clipboard(text: &str) -> Result<()> {
    // Linux / other unix: try wl-copy (Wayland), then xclip/xsel (X11).
    if pipe_to_command("wl-copy", &[], text).is_ok() {
        return Ok(());
    }
    if pipe_to_command("xclip", &["-selection", "clipboard"], text).is_ok() {
        return Ok(());
    }
    if pipe_to_command("xsel", &["--clipboard", "--input"], text).is_ok() {
        return Ok(());
    }

    Err(anyhow!(
        "copy_failed: no supported clipboard command found (try installing wl-clipboard or xclip)"
    ))
}

pub(super) fn pipe_to_command(cmd: &str, args: &[&str], text: &str) -> Result<()> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("copy_failed: failed to start {cmd}: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| anyhow!("copy_failed: failed to write stdin for {cmd}: {e}"))?;
    }

    let status = child
        .wait()
        .map_err(|e| anyhow!("copy_failed: failed to wait for {cmd}: {e}"))?;
    if !status.success() {
        return Err(anyhow!("copy_failed: {cmd} exited with {status}"));
    }
    Ok(())
}
