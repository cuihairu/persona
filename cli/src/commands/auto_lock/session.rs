//! Session lock operations: manually lock/unlock a session by ID.

use anyhow::Result;
use persona_core::auth::session::SessionManager;

use super::display::OutputFormatter;

pub(super) async fn lock(formatter: &OutputFormatter, session_id: Option<String>) -> Result<()> {
    let session_manager = SessionManager::new();

    if let Some(sid) = session_id {
        // Lock specific session
        match session_manager.lock_session(&sid).await {
            Ok(()) => {
                formatter.print_success(&format!("🔒 Session {} locked successfully", sid));
            }
            Err(e) => {
                formatter.print_error(&format!("Failed to lock session {}: {}", sid, e));
            }
        }
    } else {
        // In a real implementation, you'd lock the current user's session
        // For now, we show information about manual session locking
        formatter.print_info("🔒 Manual Session Lock");
        formatter.print_info("To lock a specific session, provide --session-id");
        formatter.print_info("Example: persona auto-lock lock --session-id <session-uuid>");
        formatter.print_info("Note: In a production setup, this would lock your current session");
    }
    Ok(())
}

pub(super) async fn unlock(formatter: &OutputFormatter, session_id: String) -> Result<()> {
    let session_manager = SessionManager::new();

    match session_manager.unlock_session(&session_id).await {
        Ok(()) => {
            formatter.print_success(&format!("🔓 Session {} unlocked successfully", session_id));
            formatter.print_info("Session timers have been reset and activity updated");
        }
        Err(e) => {
            formatter.print_error(&format!("Failed to unlock session {}: {}", session_id, e));
            formatter.print_info("Make sure the session ID is correct and exists");
        }
    }
    Ok(())
}
