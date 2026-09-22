//! persona-server 备份保管端点的客户端（`/api/v1/backups`，契约见
//! server/src/api/backups.rs）。仿 [`crate::events::ServerEventSink`]：
//! token 由宿主注入（core 不读环境变量、不落盘）、尾斜杠容错。
//!
//! 大库传输：超时 300s（默认 reqwest 无超时不可用；备份以十 MB 计，
//! 事件上报的 10s 量级不适用）。下载后本地复算 sha256 与服务器 ETag
//! 比对——传输完整性自检，非新鲜度/防回滚保证（THREAT_MODEL 已明示）。

use anyhow::{anyhow, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// 服务器侧备份元数据（列表/推送响应的镜像）。
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BackupMeta {
    pub id: String,
    pub device_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: String,
}

/// 列表响应镜像。
#[derive(Debug, Deserialize)]
pub struct BackupPage {
    pub backups: Vec<BackupMeta>,
    pub next_cursor: Option<String>,
}

/// 推送响应镜像（201 新版本 / 200 去重）。
#[derive(Debug, Deserialize)]
pub struct PushResult {
    pub id: String,
    pub device_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: String,
    pub deduplicated: bool,
}

/// 下载产物：密文字节 + 本地复算的摘要。
#[derive(Debug)]
pub struct DownloadedBackup {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

pub struct BackupClient {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl BackupClient {
    /// `base_url` 形如 `http://127.0.0.1:3000`（尾斜杠容错，可带反代前缀）。
    pub fn new(base_url: &str, token: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .user_agent("persona-backup/0.1")
            .build()?;
        Ok(Self {
            http,
            base: base_url.trim_end_matches('/').to_owned(),
            token: token.into(),
        })
    }

    /// 推送加密备份字节（201 新版本；同设备最新版本 sha256 相同则 200 去重）。
    pub async fn push(&self, bytes: &[u8]) -> Result<PushResult> {
        let response = self
            .http
            .post(format!("{}/api/v1/backups", self.base))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(server_error("push backup", status, response).await);
        }
        Ok(response.json().await?)
    }

    /// 列出备份版本（倒序：新→旧）。
    pub async fn list(&self, limit: u32, cursor: Option<&str>) -> Result<BackupPage> {
        let mut url = format!("{}/api/v1/backups?limit={limit}", self.base);
        if let Some(cursor) = cursor {
            url.push_str(&format!("&cursor={}", urlencoding(cursor)));
        }
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(server_error("list backups", status, response).await);
        }
        Ok(response.json().await?)
    }

    /// 下载备份密文，本地复算 sha256 并与服务器 ETag 比对。
    pub async fn download(&self, id: &str) -> Result<DownloadedBackup> {
        let response = self
            .http
            .get(format!("{}/api/v1/backups/{id}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(server_error("download backup", status, response).await);
        }
        let expected = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(|etag| etag.trim_matches('"').to_owned())
            .ok_or_else(|| anyhow!("server did not return an ETag for backup {id}"))?;
        let bytes = response.bytes().await?;
        let actual = {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest = hasher.finalize();
            let mut out = String::with_capacity(64);
            for byte in digest {
                use std::fmt::Write as _;
                let _ = write!(out, "{byte:02x}");
            }
            out
        };
        if actual != expected {
            return Err(anyhow!(
                "backup {id} integrity check failed: server sha256 {expected} != downloaded {actual}"
            ));
        }
        Ok(DownloadedBackup {
            bytes: bytes.to_vec(),
            sha256: actual,
        })
    }

    /// 删除服务器上的备份版本（幂等：已删除时 404 视为成功）。
    pub async fn delete(&self, id: &str) -> Result<()> {
        let response = self
            .http
            .delete(format!("{}/api/v1/backups/{id}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?;
        let status = response.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(server_error("delete backup", status, response).await)
        }
    }
}

/// 统一错误形状 `{"error":{code,message}}` 的提取；body 非 JSON 时给状态码。
async fn server_error(
    action: &str,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> anyhow::Error {
    let body = response.text().await.unwrap_or_default();
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(message) = parsed["error"]["message"].as_str() {
            return anyhow!("{action} failed: {} ({status})", message);
        }
    }
    anyhow!("{action} failed: {status}")
}

/// 游标是 base64url（无 padding），仅 `/`/`+`/`=`/`+` 需转义；保守做
/// 百分号编码（除未保留字符外全转），不引 urlencoding 依赖。
fn urlencoding(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// 请求是否已收满（headers + Content-Length 的 body）。
    fn request_complete(buf: &[u8]) -> bool {
        let Some(head_end) = find_subsequence(buf, b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&buf[..head_end]);
        let content_length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        buf.len() >= head_end + 4 + content_length
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// 与 events::server_sink 测试同型：手写 TCP 假服务器（core 不引
    /// axum 测试依赖）。四端点最小契约，`/api/v1/backups/b-1` 的上传
    /// 内容与删除状态留在共享状态里供断言。
    #[derive(Default)]
    struct Shared {
        uploaded: Option<Vec<u8>>,
        deleted: bool,
    }

    async fn spawn_fake_backup_server() -> (String, Arc<Mutex<Shared>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let state = shared.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    continue;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if request_complete(&buf) {
                            break;
                        }
                    }
                    let response = route(&buf, &state);
                    let _ = socket.write_all(&response).await;
                });
            }
        });
        (format!("http://{addr}"), shared)
    }

    fn route(raw: &[u8], state: &Arc<Mutex<Shared>>) -> Vec<u8> {
        let head_end = find_subsequence(raw, b"\r\n\r\n").unwrap_or(raw.len());
        let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
        let body = raw[(head_end + 4).min(raw.len())..].to_vec();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        let (status, headers, out_body): (&str, String, Vec<u8>) =
            match (method, path.split('?').next().unwrap_or("")) {
                ("POST", "/api/v1/backups") => {
                    let digest = sha256_hex(&body);
                    state.lock().unwrap().uploaded = Some(body.clone());
                    let json = format!(
                        "{{\"id\":\"b-1\",\"device_name\":\"test\",\"size_bytes\":{},\
                         \"sha256\":\"{digest}\",\"created_at\":\"2026-09-21T00:00:00Z\",\
                         \"deduplicated\":false}}",
                        body.len()
                    );
                    (
                        "HTTP/1.1 201 Created",
                        "Content-Type: application/json".into(),
                        json.into_bytes(),
                    )
                }
                ("GET", "/api/v1/backups") => {
                    let shared = state.lock().unwrap();
                    let json = match &shared.uploaded {
                        Some(bytes) => format!(
                            "{{\"backups\":[{{\"id\":\"b-1\",\"device_name\":\"test\",\
                             \"size_bytes\":{},\"sha256\":\"{}\",\
                             \"created_at\":\"2026-09-21T00:00:00Z\"}}],\"next_cursor\":null}}",
                            bytes.len(),
                            sha256_hex(bytes)
                        ),
                        None => "{\"backups\":[],\"next_cursor\":null}".to_owned(),
                    };
                    (
                        "HTTP/1.1 200 OK",
                        "Content-Type: application/json".into(),
                        json.into_bytes(),
                    )
                }
                ("GET", "/api/v1/backups/b-1") => {
                    let shared = state.lock().unwrap();
                    match (&shared.uploaded, shared.deleted) {
                        (Some(bytes), false) => {
                            let digest = sha256_hex(bytes);
                            (
                                "HTTP/1.1 200 OK",
                                format!(
                                    "ETag: \"{digest}\"\r\nContent-Type: application/octet-stream"
                                ),
                                bytes.clone(),
                            )
                        }
                        _ => (
                            "HTTP/1.1 404 Not Found",
                            "Content-Type: application/json".into(),
                            b"{\"error\":{\"code\":\"not_found\",\"message\":\"no such route\"}}"
                                .to_vec(),
                        ),
                    }
                }
                ("DELETE", "/api/v1/backups/b-1") => {
                    let mut shared = state.lock().unwrap();
                    if shared.deleted {
                        (
                            "HTTP/1.1 404 Not Found",
                            "Content-Type: application/json".into(),
                            b"{\"error\":{\"code\":\"not_found\",\"message\":\"no such route\"}}"
                                .to_vec(),
                        )
                    } else {
                        shared.deleted = true;
                        shared.uploaded = None;
                        ("HTTP/1.1 204 No Content", String::new(), Vec::new())
                    }
                }
                _ => (
                    "HTTP/1.1 404 Not Found",
                    "Content-Type: application/json".into(),
                    b"{\"error\":{\"code\":\"not_found\",\"message\":\"no such route\"}}".to_vec(),
                ),
            };

        let mut response = format!("{status}\r\n{headers}\r\nConnection: close\r\n");
        if !out_body.is_empty() {
            response.push_str(&format!("Content-Length: {}\r\n", out_body.len()));
        }
        response.push_str("\r\n");
        let mut raw = response.into_bytes();
        raw.extend_from_slice(&out_body);
        raw
    }

    #[tokio::test]
    async fn push_list_download_delete_against_fake_server() {
        let (base, _shared) = spawn_fake_backup_server().await;
        let client = BackupClient::new(&base, "token").unwrap();
        let payload = b"encrypted-backup-bytes";

        let pushed = client.push(payload).await.unwrap();
        assert_eq!(pushed.id, "b-1");
        assert!(!pushed.deduplicated);
        assert_eq!(pushed.sha256, sha256_hex(payload));

        let page = client.list(20, None).await.unwrap();
        assert_eq!(page.backups.len(), 1);
        assert_eq!(page.backups[0].id, "b-1");
        assert_eq!(page.next_cursor, None);

        let downloaded = client.download("b-1").await.unwrap();
        assert_eq!(downloaded.bytes, payload.to_vec());
        assert_eq!(downloaded.sha256, sha256_hex(payload));

        client.delete("b-1").await.unwrap();
        // 幂等：已删除（404）视为成功；下载也随之 404
        client.delete("b-1").await.unwrap();
        let err = client.download("b-1").await.unwrap_err();
        assert!(err.to_string().contains("404"), "{err}");
    }

    /// 单响应小服务器（固定状态行 + 头 + 体），供负路径用。
    async fn spawn_raw_server(
        status: &'static str,
        headers: &'static str,
        body: &'static [u8],
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    continue;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if request_complete(&buf) {
                        break;
                    }
                }
                let _ = buf;
                let mut response = format!(
                    "{status}\r\n{headers}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                response.extend_from_slice(body);
                let _ = socket.write_all(&response).await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn download_detects_etag_mismatch() {
        let base = spawn_raw_server(
            "HTTP/1.1 200 OK",
            "ETag: \"deadbeef\"\r\nContent-Type: application/octet-stream",
            b"payload",
        )
        .await;
        let client = BackupClient::new(&format!("{base}/"), "token").unwrap();
        let err = client.download("b-1").await.unwrap_err();
        assert!(err.to_string().contains("integrity check failed"), "{err}");
    }

    #[tokio::test]
    async fn server_error_shape_is_surfaced() {
        let base = spawn_raw_server(
            "HTTP/1.1 401 Unauthorized",
            "Content-Type: application/json",
            b"{\"error\":{\"code\":\"unauthorized\",\"message\":\"missing or invalid bearer token\"}}",
        )
        .await;
        let client = BackupClient::new(&base, "bad").unwrap();
        let err = client.push(b"x").await.unwrap_err();
        assert!(
            err.to_string().contains("missing or invalid bearer token"),
            "{err}"
        );
    }

    #[test]
    fn urlencoding_keeps_unreserved_and_escapes_others() {
        assert_eq!(urlencoding("abcXYZ09-_."), "abcXYZ09-_.");
        assert_eq!(urlencoding("a+b/c="), "a%2Bb%2Fc%3D");
    }
}
