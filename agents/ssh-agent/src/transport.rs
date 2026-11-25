// Windows named pipe support for SSH Agent
//! Cross-platform transport layer for SSH Agent communication

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    #[allow(dead_code)]
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

/// Whether the old file at the socket path is a stale remnant that can be
/// taken over.
///
/// The implementation is consolidated in core (`persona_core::socket`), shared
/// by the connect server and ssh-agent; the re-export is kept here to preserve
/// the `transport::is_stale_socket` call surface.
#[cfg(unix)]
pub use persona_core::socket::is_stale_socket;

impl AgentListener {
    /// Create a new listener
    #[cfg(unix)]
    pub async fn bind(path: &std::path::Path) -> Result<Self> {
        // Bind directly first, without removing anything up front (TOCTOU: the
        // path could be swapped between exists->remove->bind). Only take over
        // once the old path is confirmed to be a stale remnant (not a socket, or
        // no one listening); a live agent always errors out instead of silently
        // hijacking the path (unconditional removal would delete a live socket
        // too).
        match tokio::net::UnixListener::bind(path) {
            Ok(listener) => Ok(AgentListener::Unix(listener)),
            Err(err) if path.exists() => {
                if !is_stale_socket(path) {
                    return Err(anyhow::anyhow!(
                        "socket {} already bound by a live agent: {err}",
                        path.display()
                    ));
                }
                // Stale remnant: remove it and retry once.
                std::fs::remove_file(path)?;
                let listener = tokio::net::UnixListener::bind(path)?;
                Ok(AgentListener::Unix(listener))
            }
            Err(err) => Err(anyhow::anyhow!(
                "failed to bind agent socket {}: {err}",
                path.display()
            )),
        }
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
    #[allow(dead_code)]
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
///
/// The host shell (desktop) injects a stable path via
/// `PERSONA_AGENT_SOCKET_PATH` — the value written into `IdentityAgent` in
/// `~/.ssh/config` must survive restarts; the default pid-based path only
/// suits one-shot CLI use. On Windows the value is a stable pipe name (bind
/// takes `file_name` to build `\\.\pipe\{name}`), independent of pid.
pub fn default_agent_path() -> std::path::PathBuf {
    if let Some(p) = std::env::var("PERSONA_AGENT_SOCKET_PATH")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
    {
        return p;
    }

    #[cfg(unix)]
    {
        let mut p = std::env::temp_dir();
        p.push(format!("persona-ssh-agent-{}.sock", std::process::id()));
        p
    }

    #[cfg(windows)]
    {
        // Windows uses named pipes
        let pipe_name = format!("persona-ssh-agent-{}", std::process::id());
        std::path::PathBuf::from(pipe_name)
    }
}

/// Get environment variable name for agent socket
#[allow(dead_code)]
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

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_bind_removes_existing_path_and_accepts_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("persona-ssh-agent-test.sock");

        // Pre-create a file to ensure bind removes it.
        std::fs::write(&sock_path, b"not a socket").unwrap();

        let mut listener = AgentListener::bind(&sock_path).await.unwrap();
        let addr = listener.address();
        assert!(addr.ends_with("persona-ssh-agent-test.sock"));

        let client_task = tokio::spawn(async move {
            let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
            client.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await.unwrap();
            buf
        });

        let mut stream = listener.accept().await.unwrap();
        let mut in_buf = [0u8; 4];
        stream.read_exact(&mut in_buf).await.unwrap();
        assert_eq!(&in_buf, b"ping");

        stream.write_all(b"pong").await.unwrap();

        let out_buf = client_task.await.unwrap();
        assert_eq!(&out_buf, b"pong");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_bind_rejects_live_socket_instead_of_hijacking() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("live.sock");

        // The first listener is still listening after binding (a live agent).
        let first = AgentListener::bind(&sock_path).await.unwrap();

        // The second bind must fail rather than delete the live socket and hijack it.
        let err = AgentListener::bind(&sock_path)
            .await
            .err()
            .expect("bind to a live socket must fail");
        assert!(err.to_string().contains("live agent"), "{err}");

        // The first listener is still usable.
        assert!(first.address().ends_with("live.sock"));
        drop(first);
        // Clean up so tempdir removal does not trip over a leftover socket
        // (harmless either way, but explicit).
        let _ = std::fs::remove_file(&sock_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_bind_takes_over_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("stale.sock");

        {
            // Bind then drop without cleaning up the file: leaves a socket
            // remnant with no one listening.
            let _listener = AgentListener::bind(&sock_path).await.unwrap();
        }

        // The stale remnant should be taken over and bind should succeed.
        let listener = AgentListener::bind(&sock_path).await.unwrap();
        assert!(listener.address().ends_with("stale.sock"));
        drop(listener);
        let _ = std::fs::remove_file(&sock_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_stream_flush_succeeds_on_connected_pair() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("persona-flush-test.sock");
        let mut listener = AgentListener::bind(&sock_path).await.unwrap();

        let client_task =
            tokio::spawn(async move { tokio::net::UnixStream::connect(&sock_path).await.unwrap() });

        let mut stream = listener.accept().await.unwrap();
        let _client = client_task.await.unwrap();
        stream.flush().await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_bind_and_accept_named_pipe() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::ClientOptions;

        let name = format!("persona-ssh-agent-test-{}", std::process::id());
        let path = std::path::PathBuf::from(&name);
        let mut listener = AgentListener::bind(&path).await.unwrap();
        let pipe_name = listener.address();
        assert!(pipe_name.starts_with(r"\\.\pipe\"));

        let client_task = tokio::spawn({
            let pipe_name = pipe_name.clone();
            async move {
                let mut client = ClientOptions::new().open(&pipe_name).unwrap();
                client.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                client.read_exact(&mut buf).await.unwrap();
                buf
            }
        });

        let mut stream = listener.accept().await.unwrap();
        let mut in_buf = [0u8; 4];
        stream.read_exact(&mut in_buf).await.unwrap();
        assert_eq!(&in_buf, b"ping");

        stream.write_all(b"pong").await.unwrap();

        let out_buf = client_task.await.unwrap();
        assert_eq!(&out_buf, b"pong");
    }
}
