use super::*;
use persona_core::models::{Identity, IdentityType};
use persona_core::storage::repository::{IdentityRepository, Repository};
use std::io::{BufRead, Read, Write};
use std::sync::{Arc, Mutex};

/// 进程 env 单槽（PERSONA_* 全局名空间）：与 bridge/switch/ssh/travel
/// 的 env 测试共用 bridge 测试的全局锁串行。
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

/// 建一个带单个 identity 的库并返回 (库, identity id)。
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
    // 显式关闭：drop 只把池交给后台回收，Windows 上句柄可能仍短暂
    // 持有，紧随其后的 restore rename 会撞 os error 5（Access denied）。
    db.close().await;
    count
}

// ------------------------------------------------------------------
// 服务器侧分支（push/list/pull/restore-from-id/delete）。
//
// 这些代码的有趣路径全在「请求长什么样」与「响应怎么被解释、落盘、
// 换库」上，本地没有可替身的对象，所以起一个 loopback 上的极简
// HTTP/1.1 桩服务（与 cli/tests/integration_test.rs 的事件上报测试
// 同一惯例）：每个响应都带 `Connection: close`，reqwest 读完即断，
// 不等 keep-alive → 逐请求串行、结果确定。
// ------------------------------------------------------------------

/// 桩响应：(状态码, 附加响应头, 响应体)。
type StubReply = (u16, Vec<(&'static str, String)>, Vec<u8>);
type StubHandler = dyn Fn(&str, &str, &[u8]) -> StubReply + Send + Sync;

/// 桩服务器收到的一条请求（body 全留：要断言推上去的确实是密文）。
struct Served {
    method: String,
    path: String,
    auth: Option<String>,
    body: Vec<u8>,
}

/// 环境变量 RAII：断言失败 panic 时也会清理，不留残留污染同进程里
/// 其他读 `PERSONA_*` 的测试。
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

/// 把客户端指向桩（`PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN`）。
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

/// 起桩：逐条 accept（测试内按序发请求），回 `handler` 的罐头响应，
/// 并把每条请求记进返回的共享日志。线程随测试进程结束回收。
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
