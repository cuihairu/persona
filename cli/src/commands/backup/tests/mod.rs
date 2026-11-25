use super::*;
use persona_core::models::{Identity, IdentityType};
use persona_core::storage::repository::{IdentityRepository, Repository};
use std::io::{BufRead, Read, Write};
use std::sync::{Arc, Mutex};

/// Single process-env slot (PERSONA_* is a global namespace): serialize with the
/// bridge tests' global lock, shared with the env tests of bridge/switch/ssh/travel.
fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    crate::commands::bridge::tests::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn config_for(dir: &tempfile::TempDir) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    config
}

/// Build a database with a single identity and return (db, identity id).
async fn seeded_db(path: &std::path::Path) -> Database {
    let db = Database::from_file(path).await.unwrap();
    db.migrate().await.unwrap();
    let repo = IdentityRepository::new(db.clone());
    repo.create(&Identity::new("Seed".to_owned(), IdentityType::Personal))
        .await
        .unwrap();
    db
}

async fn identity_count(path: &std::path::Path) -> usize {
    let db = Database::from_file(path).await.unwrap();
    let repo = IdentityRepository::new(db.clone());
    let count = repo.find_all().await.unwrap().len();
    // Close explicitly: drop merely hands the pool to background reclamation, and on
    // Windows handles can still be held briefly, so the restore rename right after
    // would hit os error 5 (Access denied).
    db.close().await;
    count
}

// ------------------------------------------------------------------
// Server-side branches (push/list/pull/restore-from-id/delete).
//
// The interesting paths of this code are all about "what the request looks like"
// and "how the response is interpreted, written to disk, and swapped into the
// database", with nothing local to stub against. So spin up a minimal HTTP/1.1
// stub server on loopback (same convention as the event-reporting tests in
// cli/tests/integration_test.rs): every response carries `Connection: close`,
// so reqwest disconnects once it has finished reading and does not wait for
// keep-alive → requests are serialized one by one and results are deterministic.
// ------------------------------------------------------------------

/// Stub reply: (status code, extra response headers, body).
type StubReply = (u16, Vec<(&'static str, String)>, Vec<u8>);
type StubHandler = dyn Fn(&str, &str, &[u8]) -> StubReply + Send + Sync;

/// One request received by the stub server (the body is kept in full: we must assert what got pushed really is ciphertext).
struct Served {
    method: String,
    path: String,
    auth: Option<String>,
    body: Vec<u8>,
}

/// Environment variable RAII: cleaned up even when an assertion panics, so no
/// residue pollutes other tests in the same process that read `PERSONA_*`.
struct TempEnv {
    key: &'static str,
}

impl TempEnv {
    fn set(key: &'static str, value: &str) -> Self {
        std::env::set_var(key, value);
        Self { key }
    }
}

impl Drop for TempEnv {
    fn drop(&mut self) {
        std::env::remove_var(self.key);
    }
}

/// Point the client at the stub (`PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN`).
fn server_env(addr: std::net::SocketAddr) -> (TempEnv, TempEnv) {
    (
        TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}")),
        TempEnv::set("PERSONA_SERVER_TOKEN", "test-token"),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn json_response(status: u16, value: &serde_json::Value) -> StubReply {
    (
        status,
        vec![("Content-Type", "application/json".to_owned())],
        value.to_string().into_bytes(),
    )
}

/// Start the stub: accept one connection at a time (the test sends requests in
/// order), replay `handler`'s canned responses, and record each request in the
/// shared log it returns. The thread is reaped when the test process ends.
fn spawn_stub(handler: Box<StubHandler>) -> (std::net::SocketAddr, Arc<Mutex<Vec<Served>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Arc<Mutex<Vec<Served>>> = Arc::new(Mutex::new(Vec::new()));
    let served_log = Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = std::io::BufReader::new(stream);
            let Ok((method, path, headers, body)) = read_request(&mut reader) else {
                continue;
            };
            let auth = headers.iter().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("authorization")
                    .then(|| value.trim().to_owned())
            });
            served_log.lock().unwrap().push(Served {
                method: method.clone(),
                path: path.clone(),
                auth,
                body: body.clone(),
            });
            let (status, extra, reply) = handler(&method, &path, &body);
            let mut stream = reader.into_inner();
            let _ = stream.write_all(&stub_http(status, &extra, &reply));
            let _ = stream.flush();
        }
    });
    (addr, log)
}

fn read_request<R: std::io::Read>(
    reader: &mut std::io::BufReader<R>,
) -> std::io::Result<(String, String, Vec<String>, Vec<u8>)> {
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        headers.push(line.to_owned());
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok((method, path, headers, body))
}

fn stub_http(status: u16, extra: &[(&'static str, String)], body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Response",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    let mut out = head.into_bytes();
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

async fn vault_ready(dir: &tempfile::TempDir) -> CliConfig {
    let config = config_for(dir);
    let db = seeded_db(&config.get_database_path()).await;
    db.close().await;
    config
}

fn push_args() -> BackupArgs {
    BackupArgs {
        command: BackupCommand::Push {
            passphrase_env: Some("PERSONA_BACKUP_TEST_PW".to_owned()),
        },
    }
}

fn list_args(limit: u32, cursor: Option<&str>) -> BackupArgs {
    BackupArgs {
        command: BackupCommand::List {
            limit,
            cursor: cursor.map(ToOwned::to_owned),
        },
    }
}

fn pull_args(id: &str, out: PathBuf) -> BackupArgs {
    BackupArgs {
        command: BackupCommand::Pull {
            id: id.to_owned(),
            out,
        },
    }
}

fn restore_args(id: Option<&str>, file: Option<PathBuf>) -> BackupArgs {
    BackupArgs {
        command: BackupCommand::Restore {
            id: id.map(ToOwned::to_owned),
            file,
            passphrase_env: None,
            yes: false,
        },
    }
}

fn delete_args(id: &str, yes: bool) -> BackupArgs {
    BackupArgs {
        command: BackupCommand::Delete {
            id: id.to_owned(),
            yes,
        },
    }
}

mod local;
mod remote;
