// Windows named pipe support for SSH Agent
//! Cross-platform transport layer for SSH Agent communication

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(windows)]
use tokio::net::windows::named_pipe;
#[cfg(unix)]
use tokio::net::UnixStream;

/// Cross-platform stream abstraction
pub enum AgentStream {
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(windows)]
    NamedPipe(named_pipe::NamedPipeServer),
}

impl AgentStream {
    /// Read exact number of bytes
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        match self {
            #[cfg(unix)]
            AgentStream::Unix(stream) => {
                stream.read_exact(buf).await?;
            }
            #[cfg(windows)]
            AgentStream::NamedPipe(pipe) => {
                pipe.read_exact(buf).await?;
            }
        }
        Ok(())
    }

    /// Write all bytes
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            #[cfg(unix)]
            AgentStream::Unix(stream) => {
                stream.write_all(buf).await?;
            }
            #[cfg(windows)]
            AgentStream::NamedPipe(pipe) => {
                pipe.write_all(buf).await?;
            }
        }
        Ok(())
    }

    /// Flush the stream
    pub async fn flush(&mut self) -> Result<()> {
        match self {
            #[cfg(unix)]
            AgentStream::Unix(stream) => {
                stream.flush().await?;
            }
            #[cfg(windows)]
            AgentStream::NamedPipe(pipe) => {
                pipe.flush().await?;
            }
        }
        Ok(())
    }
}

/// Cross-platform listener abstraction
pub enum AgentListener {
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    #[cfg(windows)]
    NamedPipe {
        path: String,
        first_instance: Option<named_pipe::NamedPipeServer>,
    },
}

impl AgentListener {
    /// Create a new listener
    #[cfg(unix)]
    pub async fn bind(path: &std::path::Path) -> Result<Self> {
        // Remove existing socket if present
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        let listener = tokio::net::UnixListener::bind(path)?;
        Ok(AgentListener::Unix(listener))
    }

    /// Create a new named pipe listener on Windows
    #[cfg(windows)]
    pub async fn bind(path: &std::path::Path) -> Result<Self> {
        let pipe_name = format!(r"\\.\pipe\{}", path.file_name().unwrap().to_string_lossy());

        let server = named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)?;

        Ok(AgentListener::NamedPipe {
            path: pipe_name,
            first_instance: Some(server),
        })
    }

    /// Accept a new connection
    pub async fn accept(&mut self) -> Result<AgentStream> {
        match self {
            #[cfg(unix)]
            AgentListener::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                Ok(AgentStream::Unix(stream))
            }
            #[cfg(windows)]
            AgentListener::NamedPipe {
                path,
                first_instance,
            } => {
                let server = if let Some(instance) = first_instance.take() {
                    // Use the first instance
                    instance
                } else {
                    // Create a new instance
                    named_pipe::ServerOptions::new().create(path)?
                };

                // Wait for client connection
                server.connect().await?;

                Ok(AgentStream::NamedPipe(server))
            }
        }
    }

    /// Get the address string for this listener
    pub fn address(&self) -> String {
        match self {
            #[cfg(unix)]
            AgentListener::Unix(listener) => listener
                .local_addr()
                .ok()
                .and_then(|addr| addr.as_pathname().map(|p| p.display().to_string()))
                .unwrap_or_else(|| "unknown".to_string()),
            #[cfg(windows)]
            AgentListener::NamedPipe { path, .. } => path.clone(),
        }
    }
}

/// Get default agent socket path for the current platform
pub fn default_agent_path() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::env::var("SSH_AUTH_SOCK")
            .ok()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                let mut p = std::env::temp_dir();
                p.push(format!("persona-ssh-agent-{}.sock", std::process::id()));
                p
            })
    }

    #[cfg(windows)]
    {
        // Windows uses named pipes
        let pipe_name = format!("persona-ssh-agent-{}", std::process::id());
        std::path::PathBuf::from(pipe_name)
    }
}

/// Get environment variable name for agent socket
pub fn agent_socket_env_var() -> &'static str {
    #[cfg(unix)]
    {
        "SSH_AUTH_SOCK"
    }

    #[cfg(windows)]
    {
        "SSH_AUTH_SOCK" // Windows SSH clients also use this
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_path() {
        let path = default_agent_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_env_var_name() {
        let var = agent_socket_env_var();
        assert_eq!(var, "SSH_AUTH_SOCK");
    }
}
