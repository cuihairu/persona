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
    // WireOpOut 与 WireOp 字段同形，经 JSON 往返保证测试与真实 wire 一致
    let json = serde_json::to_value(&wire).unwrap();
    let parsed: WireOp = serde_json::from_value(json).unwrap();
    op_from_wire(parsed)
}

fn to_in(out: WireOpOut) -> WireOp {
    let json = serde_json::to_value(&out).unwrap();
    serde_json::from_value(json).unwrap()
}

// ---- HTTP 编排防御臂补齐轮（2026-09-29 覆盖率）----
// 手写 TCP mock（沿 auth/remote_http.rs 测试惯例）：core dev-deps 无
// 现成 HTTP mock，reqwest 对手写 TCP 响应完全够用。每连接读一个请求、
// 按 handler 回 `Connection: close` 响应；status 0 = 不回包直接断开。

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// mock 收到的一次请求（方法 + 路径带 query + authorization 头原值）。
struct Captured {
    method: String,
    path: String,
    auth: Option<String>,
    body: String,
}

type Handler = Arc<dyn Fn(Captured) -> (u16, String) + Send + Sync>;

/// 起本地 mock，返回 base_url。accept loop 挂在 multi_thread runtime
/// 的后台 task 上，测试结束随 runtime 一起丢弃。
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

/// 读一个请求头（GET 空 body / POST JSON body 都只需头即可判定；
/// body 留在内核缓冲由连接关闭回收）。
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
    // body：按 Content-Length 把余量读全（PUT 的 JSON 体断言要看；
    // 无长度的 GET 视为空）。此前 body 留在内核缓冲由连接关闭回收。
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
mod http;
mod snapshot;
mod wire;
