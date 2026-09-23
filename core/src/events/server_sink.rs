//! `events-server` feature：把事件批 POST 到 persona-server 的
//! `/api/v1/events`（Bearer 认证，契约见 server/src/api/events.rs）。

use crate::events::emitter::{EventSink, SendReport};
use crate::events::wire::WireEvent;
use crate::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use std::time::Duration;

/// 明文 body 超过该阈值才 gzip：审计事件是重复结构的 JSON，百条批次
/// 体积可观；小批次（单事件约 200 B）压缩比常为负，头开销 + CPU 白花。
const GZIP_THRESHOLD_BYTES: usize = 1024;

/// persona-server 事件上报端。token 由调用方注入（宿主负责安全存储），
/// core 不读环境变量、不落盘。
pub struct ServerEventSink {
    http: reqwest::Client,
    endpoint: String,
    token: String,
}

/// server 202 响应体 `{"accepted": u64, "duplicates": u64}` 的镜像
/// （id 幂等去重后：accepted = 新收，duplicates = 重复）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub struct IngestResponse {
    pub accepted: u64,
    pub duplicates: u64,
}

/// gzip 压缩（默认等级）。内存 `Vec` writer 的 `io::Error` 实际不可达。
fn gzip_payload(payload: Vec<u8>) -> Vec<u8> {
    let mut encoder = GzEncoder::new(
        Vec::with_capacity(payload.len() / 2),
        Compression::default(),
    );
    encoder
        .write_all(&payload)
        .and_then(|()| encoder.finish())
        .expect("in-memory gzip cannot fail")
}

impl ServerEventSink {
    /// `base_url` 形如 `http://127.0.0.1:3000`（尾斜杠容错，可带反代前缀）。
    pub fn new(base_url: &str, token: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("persona-emitter/0.1")
            .build()?;
        let base = base_url.trim_end_matches('/');
        Ok(Self {
            http,
            endpoint: format!("{base}/api/v1/events"),
            token: token.into(),
        })
    }
}

#[async_trait::async_trait]
impl EventSink for ServerEventSink {
    async fn send(&self, events: Vec<WireEvent>) -> Result<SendReport> {
        // 序列化后按阈值二选一：大批发 gzip（server 侧
        // RequestDecompressionLayer 解压），小批明文直发。
        let payload = serde_json::to_vec(&serde_json::json!({ "events": events }))?;
        let gzipped = payload.len() > GZIP_THRESHOLD_BYTES;
        let body = if gzipped {
            gzip_payload(payload)
        } else {
            payload
        };

        let mut request = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.token)
            // .body(bytes) 不再自动设 Content-Type，必须显式
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if gzipped {
            request = request.header(reqwest::header::CONTENT_ENCODING, "gzip");
        }
        let response = request.body(body).send().await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status != reqwest::StatusCode::ACCEPTED {
            anyhow::bail!(
                "event ingest failed: HTTP {}: {}",
                status,
                truncate_preview(&body, 200)
            );
        }
        let parsed: IngestResponse = serde_json::from_str(&body)?;
        Ok(SendReport {
            accepted: parsed.accepted,
            duplicates: parsed.duplicates,
        })
    }
}

/// 错误消息里的响应体预览；按字符截断（字节截断会切在多字节字符中间 panic）。
fn truncate_preview(body: &str, max_chars: usize) -> String {
    if body.chars().count() <= max_chars {
        body.to_string()
    } else {
        let mut preview: String = body.chars().take(max_chars).collect();
        preview.push('…');
        preview
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::wire::to_wire;
    use crate::models::{AuditAction, AuditLog, ResourceType};
    use std::io::Read as _;
    use std::sync::{Arc, Mutex};

    struct Captured {
        request_line: String,
        authorization: String,
        content_type: String,
        content_encoding: String,
        user_agent: String,
        body: String,
    }

    /// 与 breach.rs `spawn_fake_hibp` 同型：收一个请求、捕获、回固定响应。
    /// 读循环按 Content-Length 收满整个请求体（JSON body 比 GET 大，不能
    /// 假设单次 read 收全）。body 若声明 gzip 则解压回明文再存——测试
    /// 断言的是解密后的 JSON 形状，与 server 端 RequestDecompressionLayer
    /// 的行为对齐。
    async fn spawn_fake_server(
        status: &'static str,
        response_body: &'static str,
    ) -> (String, Arc<Mutex<Option<Captured>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let log = captured.clone();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
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
            let raw = String::from_utf8_lossy(&buf).to_string();
            let mut lines = raw.split("\r\n");
            let request_line = lines.next().unwrap_or("").to_string();
            let (mut authorization, mut content_type, mut content_encoding, mut user_agent) =
                (String::new(), String::new(), String::new(), String::new());
            for line in lines {
                let Some((k, v)) = line.split_once(':') else {
                    continue;
                };
                if k.eq_ignore_ascii_case("authorization") {
                    authorization = v.trim().to_string();
                } else if k.eq_ignore_ascii_case("content-type") {
                    content_type = v.trim().to_string();
                } else if k.eq_ignore_ascii_case("content-encoding") {
                    content_encoding = v.trim().to_string();
                } else if k.eq_ignore_ascii_case("user-agent") {
                    user_agent = v.trim().to_string();
                }
            }
            // body 是字节安全切片（gzip 是二进制），头部才走 lossy 文本
            let body_start = raw.find("\r\n\r\n").map_or(raw.len(), |i| i + 4);
            let body_bytes = buf[body_start.min(buf.len())..].to_vec();
            let body = if content_encoding.eq_ignore_ascii_case("gzip") {
                let mut decoder = flate2::read::GzDecoder::new(&body_bytes[..]);
                let mut plain = Vec::new();
                decoder.read_to_end(&mut plain).unwrap();
                String::from_utf8(plain).unwrap()
            } else {
                String::from_utf8_lossy(&body_bytes).to_string()
            };
            *log.lock().unwrap() = Some(Captured {
                request_line,
                authorization,
                content_type,
                content_encoding,
                user_agent,
                body,
            });
            let response = format!(
                "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        (format!("http://{addr}"), captured)
    }

    /// 头部完整且 body 读满 Content-Length 即收全。
    fn request_complete(buf: &[u8]) -> bool {
        let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&buf[..pos]);
        let content_length = head.lines().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if !k.trim().eq_ignore_ascii_case("content-length") {
                return None;
            }
            v.trim().parse::<usize>().ok()
        });
        match content_length {
            Some(len) => buf.len() >= pos + 4 + len,
            None => true,
        }
    }

    fn wire_events(count: usize) -> Vec<WireEvent> {
        (0..count)
            .map(|_| to_wire(&AuditLog::new(AuditAction::Login, ResourceType::User, true)).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn send_posts_json_with_auth_and_parses_202() {
        let (base_url, captured) =
            spawn_fake_server("HTTP/1.1 202 Accepted", r#"{"accepted":2,"duplicates":1}"#).await;
        let sink = ServerEventSink::new(&base_url, "s3cret").unwrap();

        let report = sink.send(wire_events(2)).await.unwrap();

        assert_eq!(
            report,
            SendReport {
                accepted: 2,
                duplicates: 1
            }
        );
        let captured = captured.lock().unwrap().take().unwrap();
        assert!(captured
            .request_line
            .starts_with("POST /api/v1/events HTTP/1.1"));
        assert_eq!(captured.authorization, "Bearer s3cret");
        assert!(captured.content_type.starts_with("application/json"));
        assert!(captured.user_agent.starts_with("persona-emitter/"));
        // 小批（2 条 ≈ 200 B < 1 KiB 阈值）直发明文，无压缩头
        assert!(captured.content_encoding.is_empty());
        // body 形状对齐 server 契约：{"events": [IngestEvent, ...]}
        let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["action"], "login");
        assert!(events[0]["id"].is_string());
    }

    #[tokio::test]
    async fn large_batch_is_sent_gzipped() {
        let (base_url, captured) =
            spawn_fake_server("HTTP/1.1 202 Accepted", r#"{"accepted":50,"duplicates":0}"#).await;
        let sink = ServerEventSink::new(&base_url, "s3cret").unwrap();

        let events = wire_events(50); // ≈ 5.5 KiB 明文，远超 1 KiB 阈值
        let report = sink.send(events).await.unwrap();
        assert_eq!(report.accepted, 50);

        let captured = captured.lock().unwrap().take().unwrap();
        assert_eq!(captured.content_encoding, "gzip");
        assert!(captured.content_type.starts_with("application/json"));
        // 假服务器已按 gzip 解压：JSON 与发送内容一致
        let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 50);
    }

    #[tokio::test]
    async fn non_202_becomes_error_with_body_preview() {
        let (base_url, _captured) =
            spawn_fake_server("HTTP/1.1 401 Unauthorized", r#"{"error":"bad token"}"#).await;
        let sink = ServerEventSink::new(&base_url, "s3cret").unwrap();

        let error = sink.send(wire_events(1)).await.unwrap_err().to_string();
        assert!(error.contains("401"), "missing status: {error}");
        assert!(error.contains("bad token"), "missing body: {error}");
    }

    #[tokio::test]
    async fn malformed_202_body_is_an_error() {
        let (base_url, _captured) = spawn_fake_server("HTTP/1.1 202 Accepted", "not-json").await;
        let sink = ServerEventSink::new(&base_url, "s3cret").unwrap();

        assert!(sink.send(wire_events(1)).await.is_err());
    }

    #[tokio::test]
    async fn connection_refused_is_an_error() {
        // 先拿一个已关闭的端口：bind 后立刻 drop
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let sink = ServerEventSink::new(&format!("http://{addr}"), "s3cret").unwrap();
        assert!(sink.send(wire_events(1)).await.is_err());
    }

    // 401 响应体超长（>200 字符）：预览按字符截断并以 … 结尾——按字节
    // 截断会切在多字节字符中间 panic，这里连同多字节字符一起验证。
    #[tokio::test]
    async fn oversized_error_body_is_truncated_in_preview() {
        let long_body: &'static str = Box::leak(format!("{}世", "x".repeat(300)).into_boxed_str());
        let (base_url, _captured) = spawn_fake_server("HTTP/1.1 401 Unauthorized", long_body).await;
        let sink = ServerEventSink::new(&base_url, "s3cret").unwrap();

        let error = sink.send(wire_events(1)).await.unwrap_err().to_string();
        assert!(error.contains('…'), "preview must be truncated: {error}");
        assert!(
            !error.contains(long_body),
            "full body must not leak: {error}"
        );
    }

    // request_complete 直接单测：头部未收全/Content-Length 未读满都
    // 不算完成；无 Content-Length 时头部收全即放行。
    #[test]
    fn request_complete_rejects_partial_and_headerless_requests() {
        assert!(!request_complete(b""));
        assert!(!request_complete(b"POST /x HTTP/1.1\r\n"));
        assert!(!request_complete(
            b"POST /x HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort"
        ));

        let full = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert!(request_complete(full));
        assert!(request_complete(b"GET /x HTTP/1.1\r\n\r\n"));
    }
}
