use anyhow::{Context, Result};
use std::path::Path;
use tracing::{debug, warn};

pub mod core_ext;
pub mod file_crypto;
pub mod progress;
/// Create directory if it doesn't exist
pub fn create_directory<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();

    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
        debug!("Created directory: {}", path.display());
    }

    Ok(())
}

/// Validate workspace path
pub fn validate_workspace_path<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();

    // Check if path is absolute
    if !path.is_absolute() {
        anyhow::bail!("Workspace path must be absolute: {}", path.display());
    }

    // Check if parent directory exists and is writable
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            anyhow::bail!(
                "Parent directory does not exist: {} (create it first)",
                parent.display()
            );
        }
        if parent.exists() {
            // Check if parent is writable
            let test_file = parent.join(".persona_write_test");
            match std::fs::write(&test_file, "test") {
                Ok(_) => {
                    let _ = std::fs::remove_file(&test_file);
                }
                Err(e) => {
                    anyhow::bail!(
                        "Parent directory is not writable: {} ({})",
                        parent.display(),
                        e
                    );
                }
            }
        }
    }

    // Check if path already exists and is not empty
    if path.exists() {
        if path.is_file() {
            anyhow::bail!(
                "Workspace path points to a file, not a directory: {}",
                path.display()
            );
        }

        if let Ok(entries) = std::fs::read_dir(path) {
            let count = entries.count();
            if count > 0 {
                warn!(
                    "Workspace directory is not empty: {} ({} items)",
                    path.display(),
                    count
                );
            }
        }
    }

    Ok(())
}

/// Format file size in human readable format
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// File system utilities
pub mod fs {}
