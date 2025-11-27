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

/// Format duration in human readable format
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    } else {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}

/// Sanitize filename by removing invalid characters
pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Check if a string is a valid email address
pub fn is_valid_email(email: &str) -> bool {
    email.contains('@')
        && email.contains('.')
        && email.len() > 5
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.starts_with('.')
        && !email.ends_with('.')
}

/// Check if a string is a valid phone number
pub fn is_valid_phone(phone: &str) -> bool {
    let cleaned = phone
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();
    cleaned.len() >= 10 && cleaned.len() <= 15
}

/// Generate a secure random string
pub fn generate_random_string(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Get current timestamp as ISO 8601 string
pub fn current_timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

/// Parse timestamp from ISO 8601 string
pub fn parse_timestamp(timestamp: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S UTC")
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .with_context(|| format!("Failed to parse timestamp: {}", timestamp))
}

/// Truncate string to specified length with ellipsis
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Check if running in CI environment
pub fn is_ci_environment() -> bool {
    std::env::var("CI").is_ok()
        || std::env::var("CONTINUOUS_INTEGRATION").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("JENKINS_URL").is_ok()
}

/// Check if running in interactive terminal
pub fn is_interactive_terminal() -> bool {
    atty::is(atty::Stream::Stdout) && !is_ci_environment()
}

/// Get terminal width
pub fn get_terminal_width() -> usize {
    crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(80)
}

/// Confirm action with user
pub fn confirm_action(message: &str, default: bool) -> Result<bool> {
    if !is_interactive_terminal() {
        return Ok(default);
    }

    use dialoguer::Confirm;
    Ok(Confirm::new()
        .with_prompt(message)
        .default(default)
        .interact()?)
}

/// File system utilities
pub mod fs {
    use super::*;
    use std::path::PathBuf;

    /// Get file size
    pub fn get_file_size<P: AsRef<Path>>(path: P) -> Result<u64> {
        let metadata = std::fs::metadata(path.as_ref())
            .with_context(|| format!("Failed to get file metadata: {}", path.as_ref().display()))?;
        Ok(metadata.len())
    }

    /// Get directory size recursively
    pub fn get_directory_size<P: AsRef<Path>>(path: P) -> Result<u64> {
        let path = path.as_ref();
        let mut total_size = 0;

        if path.is_file() {
            return get_file_size(path);
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            if entry_path.is_file() {
                total_size += get_file_size(&entry_path)?;
            } else if entry_path.is_dir() {
                total_size += get_directory_size(&entry_path)?;
            }
        }

        Ok(total_size)
    }

    /// Copy file with progress
    pub fn copy_file_with_progress<P: AsRef<Path>>(
        from: P,
        to: P,
        progress_callback: Option<Box<dyn Fn(u64, u64)>>,
    ) -> Result<()> {
        let from = from.as_ref();
        let to = to.as_ref();

        let file_size = get_file_size(from)?;
        let mut source = std::fs::File::open(from)?;
        let mut dest = std::fs::File::create(to)?;

        let mut buffer = vec![0; 8192];
        let mut copied = 0;

        loop {
            let bytes_read = std::io::Read::read(&mut source, &mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            std::io::Write::write_all(&mut dest, &buffer[..bytes_read])?;
            copied += bytes_read as u64;

            if let Some(ref callback) = progress_callback {
                callback(copied, file_size);
            }
        }

        Ok(())
    }

    /// Find files matching pattern
    pub fn find_files<P: AsRef<Path>>(
        directory: P,
        pattern: &str,
        recursive: bool,
    ) -> Result<Vec<PathBuf>> {
        let directory = directory.as_ref();
        let mut files = Vec::new();

        find_files_recursive(directory, pattern, recursive, &mut files)?;

        Ok(files)
    }

    fn find_files_recursive<P: AsRef<Path>>(
        directory: P,
        pattern: &str,
        recursive: bool,
        files: &mut Vec<PathBuf>,
    ) -> Result<()> {
        let directory = directory.as_ref();

        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(filename) = path.file_name() {
                    if filename.to_string_lossy().contains(pattern) {
                        files.push(path);
                    }
                }
            } else if path.is_dir() && recursive {
                find_files_recursive(&path, pattern, recursive, files)?;
            }
        }

        Ok(())
    }
}
