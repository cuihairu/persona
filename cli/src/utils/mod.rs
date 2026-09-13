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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    #[test]
    fn create_directory_creates_missing_dirs() {
        let dir = temp_dir();
        let nested = dir.path().join("a/b/c");

        assert!(!nested.exists());
        create_directory(&nested).unwrap();
        assert!(nested.is_dir());

        // Creating an existing directory is a no-op success.
        create_directory(&nested).unwrap();
        assert!(nested.is_dir());
    }

    #[test]
    fn create_directory_errors_on_invalid_path() {
        // Parent is a regular file, so create_dir_all must fail.
        let dir = temp_dir();
        let file = dir.path().join("plain.txt");
        std::fs::write(&file, "content").unwrap();

        let err = create_directory(file.join("subdir")).unwrap_err();
        assert!(err.to_string().contains("Failed to create directory"));
    }

    #[test]
    fn validate_workspace_path_rejects_relative_paths() {
        let err = validate_workspace_path("relative/path").unwrap_err();
        assert!(err.to_string().contains("Workspace path must be absolute"));
    }

    #[test]
    fn validate_workspace_path_rejects_missing_parent() {
        let dir = temp_dir();
        let parent = dir.path().join("not-created-yet");
        let workspace = parent.join("workspace");

        let err = validate_workspace_path(&workspace).unwrap_err();
        assert!(err.to_string().contains("Parent directory does not exist"));
    }

    #[test]
    fn validate_workspace_path_rejects_unwritable_parent() {
        let dir = temp_dir();
        // The "parent" is a regular file: exists, but nothing can be written
        // inside it, which exercises the not-writable branch portably.
        let parent_file = dir.path().join("plain.txt");
        std::fs::write(&parent_file, "content").unwrap();
        let workspace = parent_file.join("workspace");

        let err = validate_workspace_path(&workspace).unwrap_err();
        assert!(err.to_string().contains("Parent directory is not writable"));
    }

    #[test]
    fn validate_workspace_path_accepts_missing_dir_with_writable_parent() {
        let dir = temp_dir();
        let workspace = dir.path().join("workspace");

        validate_workspace_path(&workspace).unwrap();
    }

    #[test]
    fn validate_workspace_path_rejects_file_target() {
        let dir = temp_dir();
        let file = dir.path().join("plain.txt");
        std::fs::write(&file, "content").unwrap();

        let err = validate_workspace_path(&file).unwrap_err();
        assert!(err
            .to_string()
            .contains("points to a file, not a directory"));
    }

    #[test]
    fn validate_workspace_path_accepts_non_empty_directory() {
        let dir = temp_dir();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("existing.txt"), "data").unwrap();

        // Non-empty directories only warn; validation still succeeds.
        validate_workspace_path(&workspace).unwrap();
    }

    #[test]
    fn validate_workspace_path_accepts_empty_directory() {
        let dir = temp_dir();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();

        validate_workspace_path(&workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn validate_workspace_path_tolerates_unreadable_entry_target() {
        let dir = temp_dir();
        let workspace = dir.path().join("workspace");

        // A Unix socket exists and is not a regular file, but read_dir on it
        // fails: the not-empty probe must treat this as "no entries" instead
        // of erroring out.
        std::os::unix::net::UnixListener::bind(&workspace).unwrap();
        assert!(workspace.exists());
        assert!(!workspace.is_file());

        validate_workspace_path(&workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn validate_workspace_path_accepts_root_path_without_parent() {
        // "/" has no parent directory, so the writability probe must be
        // skipped and validation falls through to the exists checks only.
        validate_workspace_path("/").unwrap();
    }

    #[test]
    fn validate_workspace_path_warns_through_a_live_subscriber() {
        let dir = temp_dir();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("existing.txt"), "data").unwrap();

        // Drive the warn! through a real subscriber (discarding output) so
        // the full event-dispatch path runs, not just the disabled fast path.
        let subscriber = tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            validate_workspace_path(&workspace).unwrap();
        });
    }

    #[test]
    fn format_file_size_stays_in_bytes_below_1k() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(1), "1 B");
        assert_eq!(format_file_size(1023), "1023 B");
    }

    #[test]
    fn format_file_size_scales_through_units() {
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_file_size(3 * 1024 * 1024 + 145), "3.0 MB");
        assert_eq!(format_file_size(2u64 * 1024 * 1024 * 1024), "2.0 GB");
        assert_eq!(format_file_size(5u64 * 1024u64.pow(3)), "5.0 GB");
    }

    #[test]
    fn format_file_size_caps_at_tb() {
        // Beyond TB the loop stops at the last unit instead of panicking.
        assert_eq!(format_file_size(7 * 1024u64.pow(4)), "7.0 TB");
        assert_eq!(format_file_size(1024u64.pow(5)), "1024.0 TB");
    }
}
