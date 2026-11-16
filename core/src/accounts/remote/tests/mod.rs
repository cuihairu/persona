use std::io::{Read, Write};
use std::net::TcpListener;

struct CapturedRequest {
    method: String,
    path: String,
    auth: Option<String>,
    body: String,
}

/// 起一个一次性 TCP 假服务器：读请求（head + Content-Length 体），
/// 调 handler 得 (状态码, 响应体)，回写极简 HTTP/1.1 响应。
fn spawn_mock<F>(handler: F) -> String
where
    F: Fn(&CapturedRequest) -> (u16, String) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            // head 到 \r\n\r\n
            while !buf.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                buf.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&buf).into_owned();
            let request_line = head.lines().next().unwrap_or_default().to_string();
            let auth = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .map(|l| {
                    l.split_once(':')
                        .map(|x| x.1)
                        .unwrap_or_default()
                        .trim()
                        .to_string()
                });
            let content_length: usize = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split_once(':')?.1.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                let _ = stream.read_exact(&mut body);
            }
            let (status, resp_body) = handler(&CapturedRequest {
                method: request_line
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                path: request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string(),
                auth,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
            let reason = if status == 204 { "" } else { "OK" };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                resp_body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn b64v(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn empty_json() -> String {
    "{}".to_string()
}

mod client;
mod devices;
mod passkey;
mod recovery;
mod register;
mod sessions;
mod srp;
