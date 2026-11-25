use super::wire::{kind_from_wire, op_from_wire, op_to_wire, WireOp, WireOpOut, WirePayloadOut};
use super::*;
use crate::sync::engine::SyncRemote;
use crate::sync::oplog::{ItemKind, OpType, SyncOp, SyncPayload};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use uuid::Uuid;

fn sample_put() -> SyncOp {
    SyncOp {
        op_id: Uuid::new_v4(),
        item_id: Uuid::new_v4(),
        kind: ItemKind::Credential,
        op: OpType::Put,
        lamport: 7,
        device_id: Uuid::new_v4(),
        timestamp: Some(
            DateTime::parse_from_rfc3339("2026-09-22T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        ),
        payload: Some(SyncPayload {
            ciphertext: vec![1, 2, 3, 4],
            wrapped_item_key: vec![5; 32],
        }),
    }
}

fn sample_delete() -> SyncOp {
    SyncOp {
        op: OpType::Delete,
        payload: None,
        ..sample_put()
    }
}

fn wire_to_op(wire: WireOpOut) -> Option<SyncOp> {
    // WireOpOut has the same shape as WireOp; round-tripping through JSON keeps the tests faithful to the real wire
    let json = serde_json::to_value(&wire).unwrap();
    let parsed: WireOp = serde_json::from_value(json).unwrap();
    op_from_wire(parsed)
}

fn to_in(out: WireOpOut) -> WireOp {
    let json = serde_json::to_value(&out).unwrap();
    serde_json::from_value(json).unwrap()
}

// ---- Round filling out the HTTP orchestration defense arms (2026-09-29 coverage) ----
// Hand-written TCP mock (following the auth/remote_http.rs test conventions): the core dev-deps have no
// ready-made HTTP mock, and reqwest handles hand-written TCP responses just fine. Each connection reads one
// request and answers a `Connection: close` response per the handler; status 0 = drop the connection without replying.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A single request the mock received (method + path with query + the raw authorization header value).
struct Captured {
    method: String,
    path: String,
    auth: Option<String>,
    body: String,
}

type Handler = Arc<dyn Fn(Captured) -> (u16, String) + Send + Sync>;

/// Starts a local mock and returns its base_url. The accept loop runs on a background task of the multi_thread
/// runtime and is dropped together with the runtime when the test ends.
async fn spawn_mock(handler: Handler) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Some(req) = read_request(&mut stream).await {
                    let (status, body) = handler(req);
                    if status == 0 {
                        return;
                    }
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {body}",
                        body.len(),
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
                let _ = stream.flush().await;
            });
        }
    });
    format!("http://{addr}")
}

/// Reads one request head (the head alone decides things whether it is a GET with an empty body or a POST with a
/// JSON body; the body stays in the kernel buffer and is reclaimed when the connection closes).
async fn read_request(stream: &mut TcpStream) -> Option<Captured> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let auth = head
        .lines()
        .find_map(|l| l.strip_prefix("authorization: ").map(str::to_string));
    // Body: read the remainder in full according to Content-Length (assertions on the PUT JSON body need it;
    // a lengthless GET counts as empty). Previously the body stayed in the kernel buffer and was reclaimed by the connection closing.
    let content_length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length: ").map(str::to_string))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("read loop only breaks on the header terminator");
    let mut body = buf[split + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Some(Captured {
        method,
        path,
        auth,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

mod admin;
mod cloud;
mod http;
mod snapshot;
mod wire;
