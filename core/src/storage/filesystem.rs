use crate::{PersonaError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs as async_fs;

/// File system operations
pub struct FileSystem;

impl FileSystem {
    /// Create a directory and all parent directories
    pub async fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
        Ok(async_fs::create_dir_all(path)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Read file contents as string
    pub async fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String> {
        Ok(async_fs::read_to_string(path)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Read file contents as bytes
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
        Ok(async_fs::read(path)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Write string to file
    pub async fn write_string<P: AsRef<Path>>(path: P, contents: &str) -> Result<()> {
        Ok(async_fs::write(path, contents)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Write bytes to file
    pub async fn write<P: AsRef<Path>>(path: P, contents: &[u8]) -> Result<()> {
        Ok(async_fs::write(path, contents)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Check if path exists
    pub async fn exists<P: AsRef<Path>>(path: P) -> bool {
        async_fs::metadata(path).await.is_ok()
    }

    /// Check if path is a file
    pub async fn is_file<P: AsRef<Path>>(path: P) -> Result<bool> {
        let metadata = async_fs::metadata(path).await.map_err(|e| {
            Box::new(PersonaError::Io(e.to_string())) as Box<dyn std::error::Error + Send + Sync + 'static>
        })?;
        Ok(metadata.is_file())
    }

    /// Check if path is a directory
    pub async fn is_dir<P: AsRef<Path>>(path: P) -> Result<bool> {
        let metadata = async_fs::metadata(path).await.map_err(|e| {
            Box::new(PersonaError::Io(e.to_string())) as Box<dyn std::error::Error + Send + Sync + 'static>
        })?;
        Ok(metadata.is_dir())
    }

    /// Remove a file
    pub async fn remove_file<P: AsRef<Path>>(path: P) -> Result<()> {
        Ok(async_fs::remove_file(path)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Remove a directory and all its contents
    pub async fn remove_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
        Ok(async_fs::remove_dir_all(path)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Copy a file
    pub async fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<u64> {
        Ok(async_fs::copy(from, to)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Rename/move a file or directory
    pub async fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<()> {
        Ok(async_fs::rename(from, to)
            .await
            .map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// List directory contents
    pub async fn read_dir<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>> {
        let mut entries = async_fs::read_dir(path).await.map_err(|e| {
            Box::new(PersonaError::Io(e.to_string())) as Box<dyn std::error::Error + Send + Sync + 'static>
        })?;

        let mut paths = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            Box::new(PersonaError::Io(e.to_string())) as Box<dyn std::error::Error + Send + Sync + 'static>
        })? {
            paths.push(entry.path());
        }

        Ok(paths)
    }

    /// Get file size
    pub async fn file_size<P: AsRef<Path>>(path: P) -> Result<u64> {
        let metadata = async_fs::metadata(path).await.map_err(|e| {
            Box::new(PersonaError::Io(e.to_string())) as Box<dyn std::error::Error + Send + Sync + 'static>
        })?;
        Ok(metadata.len())
    }
}

/// Synchronous file system operations
pub struct SyncFileSystem;

impl SyncFileSystem {
    /// Create directory and all parent directories
    pub fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
        Ok(fs::create_dir_all(path).map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Read file contents as string
    pub fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String> {
        Ok(fs::read_to_string(path).map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Write string to file
    pub fn write_string<P: AsRef<Path>>(path: P, contents: &str) -> Result<()> {
        Ok(fs::write(path, contents).map_err(|e| PersonaError::Io(e.to_string()))?)
    }

    /// Check if path exists
    pub fn exists<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().exists()
    }

    /// Check if path is a file
    pub fn is_file<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().is_file()
    }

    /// Check if path is a directory
    pub fn is_dir<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().is_dir()
    }
}

/// Path utilities
pub struct PathUtils;

impl PathUtils {
    /// Get the home directory
    pub fn home_dir() -> Option<PathBuf> {
        dirs::home_dir()
    }

    /// Get the config directory
    pub fn config_dir() -> Option<PathBuf> {
        dirs::config_dir()
    }

    /// Get the data directory
    pub fn data_dir() -> Option<PathBuf> {
        dirs::data_dir()
    }

    /// Get the cache directory
    pub fn cache_dir() -> Option<PathBuf> {
        dirs::cache_dir()
    }

    /// Join paths safely
    pub fn join<P: AsRef<Path>>(base: P, path: &str) -> PathBuf {
        base.as_ref().join(path)
    }

    /// Ensure path is absolute
    pub fn ensure_absolute<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path = path.as_ref();
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .map_err(|e| PersonaError::Io(e.to_string()))?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_file_operations() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Write file
        FileSystem::write_string(&file_path, "Hello, World!")
            .await
            .unwrap();

        // Check if file exists
        assert!(FileSystem::exists(&file_path).await);
        assert!(FileSystem::is_file(&file_path).await.unwrap());

        // Read file
        let content = FileSystem::read_to_string(&file_path).await.unwrap();
        assert_eq!(content, "Hello, World!");

        // Get file size
        let size = FileSystem::file_size(&file_path).await.unwrap();
        assert_eq!(size, 13);

        // Remove file
        FileSystem::remove_file(&file_path).await.unwrap();
        assert!(!FileSystem::exists(&file_path).await);
    }

    #[tokio::test]
    async fn test_directory_operations() {
        let temp_dir = tempdir().unwrap();
        let sub_dir = temp_dir.path().join("subdir");

        // Create directory
        FileSystem::create_dir_all(&sub_dir).await.unwrap();

        // Check if directory exists
        assert!(FileSystem::exists(&sub_dir).await);
        assert!(FileSystem::is_dir(&sub_dir).await.unwrap());

        // List directory contents
        let contents = FileSystem::read_dir(temp_dir.path()).await.unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0], sub_dir);
    }
}
