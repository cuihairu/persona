//! Favicon fetching for entry icons (`favicon` feature).
//!
//! 隐私红线（TODO.md）：不常驻外联、不默认抓取——本模块唯一的网络入口
//! [`FaviconFetcher::fetch`] 只在用户于详情面板点击 "Fetch icon" 时被
//! service 调用，抓取源直连 `https://{host}/favicon.ico`，不经任何第三方
//! 图标服务。这是仓库首个"用户可控 URL 外联"，host 提取按 SSRF 从紧校验：
//! 只允许解析为公网域名的 https URL，IP 字面量与裸主机名一律拒绝。

use crate::{PersonaError, Result};
use url::Url;

/// 单个 favicon 的字节上限（512 KiB），与 `migrations/011_favicon_cache.sql`
/// 中 `data` 列的 CHECK 上限保持一致（改动需双方同步）。
pub const MAX_FAVICON_BYTES: usize = 512 * 1024;

const FETCH_TIMEOUT_SECS: u64 = 10;
const USER_AGENT: &str = "persona-favicon";

/// 抓取成功的产物；`data` 已确保非空且 ≤ [`MAX_FAVICON_BYTES`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaviconBlob {
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// 从用户提供的 URL / 裸域名中提取可用于抓取 favicon 的 host。
///
/// 规则按序执行，任一失败即 Err。校验只覆盖 URL 字面 host
/// （DNS rebinding 不在此防线内，见 TODO.md 已知限制）：
///
/// ① `Url::parse` 失败时借道 `https://{raw}` 再试（补全裸域名）
/// ② 仅接受 https scheme
/// ③ 必须有 host
/// ④ 拒绝 IP 字面量（IPv4/IPv6，含十进制/十六进制缩写——url crate 按
///    WHATWG 规范归一，`169.254.169.254`、`127.0.0.1`、`[::1]` 全部落此）
/// ⑤ 拒绝不含 `.` 的裸主机名（localhost / 内网单标签名）
/// ⑥ 归一：去尾点 + ASCII 小写；端口 / userinfo / path 天然丢弃
pub fn extract_favicon_host(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(PersonaError::InvalidInput("empty url".to_string()).into());
    }

    let parsed = match Url::parse(raw) {
        Ok(url) => url,
        // 无 scheme 的裸域名（"example.com"）借道 https 再试一次
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            Url::parse(&format!("https://{raw}"))?
        }
        Err(e) => return Err(e.into()),
    };

    if parsed.scheme() != "https" {
        return Err(PersonaError::InvalidInput(format!(
            "only https urls are fetched, got scheme {:?}",
            parsed.scheme()
        ))
        .into());
    }

    match parsed.host() {
        Some(url::Host::Domain(domain)) => {
            let trimmed = domain.trim_end_matches('.');
            if !trimmed.contains('.') {
                return Err(PersonaError::InvalidInput(format!(
                    "bare hostname {trimmed:?} is not fetched (intranet names are rejected)"
                ))
                .into());
            }
            Ok(trimmed.to_ascii_lowercase())
        }
        Some(url::Host::Ipv4(ip)) => Err(PersonaError::InvalidInput(format!(
            "ip literals are not fetched: {ip}"
        ))
        .into()),
        Some(url::Host::Ipv6(ip)) => Err(PersonaError::InvalidInput(format!(
            "ip literals are not fetched: {ip}"
        ))
        .into()),
        None => Err(PersonaError::InvalidInput("url has no host".to_string()).into()),
    }
}

/// On-demand favicon fetcher (`favicon` feature).
#[derive(Debug, Clone)]
pub struct FaviconFetcher {
    http: reqwest::Client,
    /// scheme + authority 前缀；真实路径为 `https://{host}`，测试注入本地 fake。
    base: String,
}

impl FaviconFetcher {
    /// Client：10s 超时 + UA + 不跟随重定向。
    ///
    /// 重定向必须关——host 校验只覆盖 URL 字面 host，跟随跳转等于把
    /// "打向哪里"的决定权交回给远端。
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            base: "https://".to_string(),
        })
    }

    /// Override the origin (tests point this at a local fake).
    #[cfg(test)]
    pub(crate) fn with_base_url(mut self, base: String) -> Self {
        self.base = base;
        self
    }

    /// 抓取 `https://{host}/favicon.ico`。
    ///
    /// 请求 URL 仅由已校验的 host 重建，不回带端口 / path / userinfo。
    /// 响应侧防线：非 2xx bail（`Policy::none` 下 3xx 自然落此）→
    /// Content-Length 预检 → Content-Type 归一（`text/` 拒，SPA 的
    /// 200 + HTML 不能混进图标缓存）→ chunk 流式累计双保险超限 bail →
    /// 空 body bail。
    pub async fn fetch(&self, host: &str) -> Result<FaviconBlob> {
        // fetch 是 pub 入口，host 再过一遍与 extract 相同的六规则
        // （裸域名借道 https 后结果不变，IP/裸主机名在此被拒）
        let host = extract_favicon_host(&format!("https://{host}"))?;
        let url = format!("{}{}/favicon.ico", self.base, host);

        let mut response = self.http.get(&url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!(
                "favicon request failed with status {} for {host}",
                response.status()
            );
        }

        if let Some(len) = response.content_length() {
            if len as usize > MAX_FAVICON_BYTES {
                anyhow::bail!(
                    "favicon from {host} is too large: {len} > {MAX_FAVICON_BYTES} bytes"
                );
            }
        }

        // 归一：取 `;` 前段 lowercase（去 charset 等参数）；缺省回退 ico
        let mime_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "image/x-icon".to_string());
        if mime_type.starts_with("text/") {
            anyhow::bail!(
                "favicon from {host} is a text response ({mime_type}), not an image"
            );
        }

        let mut data: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if data.len() + chunk.len() > MAX_FAVICON_BYTES {
                anyhow::bail!(
                    "favicon from {host} exceeded {MAX_FAVICON_BYTES} bytes while streaming"
                );
            }
            data.extend_from_slice(&chunk);
        }
        if data.is_empty() {
            anyhow::bail!("favicon from {host} is empty");
        }

        Ok(FaviconBlob { mime_type, data })
    }
}

#[cfg(all(test, feature = "favicon"))]
mod tests {
    use super::*;

    // ---- extract_favicon_host：接受矩阵 ----

    #[test]
    fn extracts_host_from_bare_domain() {
        assert_eq!(extract_favicon_host("example.com").unwrap(), "example.com");
    }

    #[test]
    fn normalizes_case_trailing_dot_and_drops_everything_else() {
        assert_eq!(
            extract_favicon_host("https://Example.COM./a/b?q=1").unwrap(),
            "example.com"
        );
        assert_eq!(
            extract_favicon_host("https://user:pass@Example.COM:8443/x").unwrap(),
            "example.com"
        );
    }

    // ---- extract_favicon_host：拒绝矩阵 ----

    fn assert_rejected(raw: &str) {
        let err = extract_favicon_host(raw).expect_err(raw);
        assert!(
            err.downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
            "expected InvalidInput for {raw:?}, got: {err}"
        );
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_rejected("");
        assert_rejected("   ");
    }

    #[test]
    fn rejects_non_https_schemes() {
        assert_rejected("http://example.com");
        assert_rejected("ftp://example.com");
    }

    #[test]
    fn rejects_ip_literals() {
        // 云元数据 / 本机回环 / IPv6 / 十进制与十六进制 IPv4 缩写
        assert_rejected("https://169.254.169.254/latest/meta-data");
        assert_rejected("https://127.0.0.1/x");
        assert_rejected("https://[::1]/x");
        assert_rejected("https://2130706433/x"); // == 127.0.0.1
        assert_rejected("https://0x7f.0.0.1/x");
    }

    #[test]
    fn rejects_bare_hostnames() {
        assert_rejected("https://localhost");
        assert_rejected("localhost");
        assert_rejected("intranet"); // 借道 https 后仍是单标签名
        assert_rejected("localhost."); // 去尾点后才查点号
    }

    #[test]
    fn rejects_urls_without_host() {
        // "https://" 在 parse 阶段即 EmptyHost 错误（非借道分支），同样拒绝
        assert!(extract_favicon_host("https://").is_err());
    }

    // ---- FaviconFetcher：本地 fake server 集成 ----

    /// 起一个本地 fake favicon 源；返回注入用 base URL 和收到的请求行日志。
    /// `status` / `headers` / `body` 逐字回写（headers 传完整行）；可选用
    /// `content_length_override` 谎报 Content-Length（body 照发真实长度）。
    async fn spawn_fake_favicon(
        status: &'static str,
        headers: &'static [&'static str],
        body: &'static [u8],
        content_length_override: Option<usize>,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::sync::{Arc, Mutex};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));

        let log = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let log = log.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                    let request_line = raw.lines().next().unwrap_or("").to_string();
                    log.lock().unwrap().push(request_line);

                    let declared =
                        content_length_override.unwrap_or(body.len());
                    let mut response = format!(
                        "{status}\r\nContent-Length: {declared}\r\nConnection: close\r\n"
                    );
                    for h in headers {
                        response.push_str(h);
                        response.push_str("\r\n");
                    }
                    response.push_str("\r\n");
                    let mut out = response.into_bytes();
                    out.extend_from_slice(body);
                    let _ = socket.write_all(&out).await;
                });
            }
        });

        (format!("http://{addr}/"), requests)
    }

    /// 起一个 chunked 传输的 fake（无 Content-Length），单块写指定字节。
    async fn spawn_fake_chunked(body: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await;
            let mut out =
                b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    .to_vec();
            // 单块写完整 body；reqwest 解析 chunked 后 content_length 为 None
            out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
            out.extend_from_slice(&body);
            out.extend_from_slice(b"\r\n0\r\n\r\n");
            let _ = socket.write_all(&out).await;
        });
        format!("http://{addr}/")
    }

    const PNG_BYTES: &[u8] = b"\x89PNG\r\n\x1a\nfake-icon-bytes";

    #[tokio::test]
    async fn fetch_downloads_and_normalizes_mime() {
        let (base, requests) = spawn_fake_favicon(
            "HTTP/1.1 200 OK",
            &["Content-Type: image/png; charset=binary"],
            PNG_BYTES,
            None,
        )
        .await;

        let blob = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap();

        assert_eq!(blob.mime_type, "image/png");
        assert_eq!(blob.data, PNG_BYTES);

        // URL 仅由 host 重建：真实 base 下 path 恒为 /favicon.ico；
        // 测试注入本地 base 后 host 落在 path 前段，形态必须是
        // GET /{host}/favicon.ico（不会带端口之外的任何杂项）
        let requests = requests.lock().unwrap();
        assert!(
            requests[0].starts_with("GET /example.com/favicon.ico HTTP/1.1"),
            "unexpected request line: {}",
            requests[0]
        );
    }

    #[tokio::test]
    async fn fetch_falls_back_to_x_icon_without_content_type() {
        let (base, _) = spawn_fake_favicon("HTTP/1.1 200 OK", &[], PNG_BYTES, None).await;
        let blob = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap();
        assert_eq!(blob.mime_type, "image/x-icon");
    }

    #[tokio::test]
    async fn fetch_rejects_non_success_status() {
        let (base, _) =
            spawn_fake_favicon("HTTP/1.1 404 Not Found", &[], b"nope", None).await;
        let err = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
    }

    #[tokio::test]
    async fn fetch_does_not_follow_redirects() {
        let (base, _) = spawn_fake_favicon(
            "HTTP/1.1 302 Found",
            &["Location: /moved"],
            b"",
            None,
        )
        .await;
        let err = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("302"), "got: {err}");
    }

    #[tokio::test]
    async fn fetch_rejects_text_responses() {
        // SPA 常见陷阱：200 + HTML（index.html 兜底路由），混进缓存必然破图
        let (base, _) = spawn_fake_favicon(
            "HTTP/1.1 200 OK",
            &["Content-Type: text/html; charset=utf-8"],
            b"<!doctype html><html></html>",
            None,
        )
        .await;
        let err = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("text/html"), "got: {err}");
    }

    #[tokio::test]
    async fn fetch_rejects_oversized_content_length_before_reading_body() {
        // Content-Length 谎报 600KB（body 其实很小）——预检必须在读 body 前 bail
        let (base, _) = spawn_fake_favicon(
            "HTTP/1.1 200 OK",
            &["Content-Type: image/png"],
            PNG_BYTES,
            Some(MAX_FAVICON_BYTES + 1),
        )
        .await;
        let err = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_oversized_streaming_body() {
        // chunked 响应无 Content-Length → 预检跳过，流式累计双保险必须拦下
        let base = spawn_fake_chunked(vec![0u8; MAX_FAVICON_BYTES + 1]).await;
        let err = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("while streaming"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_empty_body() {
        let (base, _) = spawn_fake_favicon(
            "HTTP/1.1 200 OK",
            &["Content-Type: image/png"],
            b"",
            None,
        )
        .await;
        let err = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[tokio::test]
    async fn fetch_revalidates_host() {
        // fetch 是 pub 入口：IP host 即便绕过 extract 直呼也要被拒
        let err = FaviconFetcher::new()
            .unwrap()
            .fetch("127.0.0.1")
            .await
            .unwrap_err();
        assert!(
            err.downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
            "got: {err}"
        );
    }
}
