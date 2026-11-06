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

/// socket 路径上的旧文件是否是可接管的陈旧残骸。
///
/// - 不存在 / 非 socket 文件（崩溃残留的普通文件、symlink 等）→ 陈旧；
/// - 是 socket 但 connect 不上（ECONNREFUSED）→ 上一进程死了没清理 → 陈旧；
/// - 是 socket 且能连上 → 有活 agent 在监听 → 非陈旧。
#[cfg(unix)]
pub fn is_stale_socket(path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            // 探测连接：连上即有人监听。连接被立刻关闭，agent 侧按 EOF 处理。
            std::os::unix::net::UnixStream::connect(path).is_err()
        }
        Ok(_) => true,
        Err(_) => true,
    }
}

impl AgentListener {
    /// Create a new listener
    #[cfg(unix)]
    pub async fn bind(path: &std::path::Path) -> Result<Self> {
        // 先直接 bind，不预先删除（TOCTOU：exists→remove→bind 之间路径可能
        // 被换掉）。只有确认旧路径是陈旧残骸（非 socket 或无人监听）才接管，
        // 活着的 agent 一律报错而非静默劫持路径（无条件删除会连活 socket 一起删）。
        match tokio::net::UnixListener::bind(path) {
            Ok(listener) => Ok(AgentListener::Unix(listener)),
            Err(err) if path.exists() => {
                if !is_stale_socket(path) {
                    return Err(anyhow::anyhow!(
                        "socket {} already bound by a live agent: {err}",
                        path.display()
                    ));
                }
                // 陈旧残骸：删掉重试一次。
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
/// 宿主壳（desktop）通过 `PERSONA_AGENT_SOCKET_PATH` 注入稳定路径——写进
/// `~/.ssh/config` 的 `IdentityAgent` 必须跨重启不变；缺省的 pid 化路径只
/// 适合一次性 CLI 场景。Windows 的值是稳定管道名（bind 取 `file_name`
/// 造 `\\.\pipe\{name}`），与 pid 无关。
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

        // 第一个 listener 绑定后仍在监听（活 agent）。
        let first = AgentListener::bind(&sock_path).await.unwrap();

        // 第二个 bind 必须失败，而不是把活 socket 删掉劫持。
        let err = AgentListener::bind(&sock_path)
            .await
            .err()
            .expect("bind to a live socket must fail");
        assert!(err.to_string().contains("live agent"), "{err}");

        // 第一个 listener 依旧可用。
        assert!(first.address().ends_with("live.sock"));
        drop(first);
        // 清理，避免 tempdir 删除残留 socket 时出问题（无妨，但仍显式清）。
        let _ = std::fs::remove_file(&sock_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_bind_takes_over_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("stale.sock");

        {
            // 绑定后丢弃，不清理文件：留下一个无人监听的 socket 残骸。
            let _listener = AgentListener::bind(&sock_path).await.unwrap();
        }

        // 陈旧残骸应被接管，bind 成功。
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
