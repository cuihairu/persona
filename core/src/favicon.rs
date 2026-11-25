//! Favicon fetching for entry icons (`favicon` feature).
//!
//! Privacy red line (todo.md): no standing outbound calls, no fetching by default — the only
//! network entry in this module, [`FaviconFetcher::fetch`], is called by the service only when
//! the user clicks "Fetch icon" in the detail panel. The fetch source connects directly to
//! `https://{host}/favicon.ico` and never goes through any third-party icon service. This is the
//! repo's first "user-controllable URL outbound call"; host extraction is validated strictly for
//! SSRF: only https URLs resolving to public domains are allowed, and IP literals and bare
//! hostnames are always rejected.

use crate::{PersonaError, Result};
use url::Url;

/// Per-favicon byte limit (512 KiB), kept consistent with the `data` column CHECK limit in
/// `migrations/011_favicon_cache.sql` (any change must be made on both sides).
pub const MAX_FAVICON_BYTES: usize = 512 * 1024;

const FETCH_TIMEOUT_SECS: u64 = 10;
const USER_AGENT: &str = "persona-favicon";

/// A successful fetch's output; `data` is guaranteed non-empty and ≤ [`MAX_FAVICON_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaviconBlob {
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// Extract the host to fetch a favicon from, from a user-supplied URL / bare domain.
///
/// Rules run in order; any failure is an Err. Validation only covers the URL's literal host
/// (DNS rebinding is not covered by this line of defense; see todo.md known limitations):
///
/// ① When `Url::parse` fails, retry via `https://{raw}` (completing bare domains)
/// ② Only the https scheme is accepted
/// ③ A host is required
/// ④ IP literals are rejected (IPv4/IPv6, including decimal/hexadecimal shorthand — the url crate
///    normalizes per the WHATWG spec, so `169.254.169.254`, `127.0.0.1`, `[::1]` all land here)
/// ⑤ Bare hostnames without `.` are rejected (localhost / intranet single-label names)
/// ⑥ Normalization: strip the trailing dot + ASCII lowercase; port / userinfo / path are naturally dropped
pub fn extract_favicon_host(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(PersonaError::InvalidInput("empty url".to_string()).into());
    }

    let parsed = match Url::parse(raw) {
        Ok(url) => url,
        // Bare domain without a scheme ("example.com"): retry once via https
        Err(url::ParseError::RelativeUrlWithoutBase) => Url::parse(&format!("https://{raw}"))?,
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
        Some(url::Host::Ipv4(ip)) => {
            Err(PersonaError::InvalidInput(format!("ip literals are not fetched: {ip}")).into())
        }
        Some(url::Host::Ipv6(ip)) => {
            Err(PersonaError::InvalidInput(format!("ip literals are not fetched: {ip}")).into())
        }
        None => Err(PersonaError::InvalidInput("url has no host".to_string()).into()),
    }
}

/// On-demand favicon fetcher (`favicon` feature).
#[derive(Debug, Clone)]
pub struct FaviconFetcher {
    http: reqwest::Client,
    /// scheme + authority prefix; in production this is `https://{host}`, tests inject a local fake.
    base: String,
}

impl FaviconFetcher {
    /// Client: 10s timeout + UA + no redirect following.
    ///
    /// Redirects must stay off — host validation only covers the URL's literal host, and
    /// following redirects would hand the decision of "where to hit" back to the remote.
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

    /// Fetch `https://{host}/favicon.ico`.
    ///
    /// The request URL is rebuilt from the validated host only; port / path / userinfo are never
    /// carried back. Response-side defenses: non-2xx bail (under `Policy::none`, 3xx naturally
    /// lands here) → Content-Length pre-check → Content-Type normalization (`text/` rejected;
    /// an SPA's 200 + HTML must not slip into the icon cache) → chunked streaming accumulation
    /// as a second size-limit check, bailing on overflow → empty body bail.
    pub async fn fetch(&self, host: &str) -> Result<FaviconBlob> {
        // fetch is a public entry point: run the host through the same six rules as extract again
        // (bare domains come out unchanged after the https detour; IP/bare hostnames are rejected here)
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

        // Normalize: take the segment before `;`, lowercased (drops charset etc. parameters); default fallback is ico
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
            anyhow::bail!("favicon from {host} is a text response ({mime_type}), not an image");
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

    // ---- extract_favicon_host: acceptance matrix ----

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

    // ---- extract_favicon_host: rejection matrix ----

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
        // Cloud metadata / local loopback / IPv6 / decimal and hexadecimal IPv4 shorthand
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
        assert_rejected("intranet"); // still a single-label name after the https detour
        assert_rejected("localhost."); // the dot check runs after the trailing dot is stripped
    }

    #[test]
    fn rejects_urls_without_host() {
        // "https://" fails at parse time with EmptyHost (not the detour branch); also rejected
        assert!(extract_favicon_host("https://").is_err());
    }

    // ---- FaviconFetcher: local fake server integration ----

    /// Start a local fake favicon source; returns the base URL for injection and a log of received
    /// request lines. `status` / `headers` / `body` are written back verbatim (headers are full
    /// lines); optionally `content_length_override` lies about Content-Length (the body is still
    /// sent at its real length).
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

                    let declared = content_length_override.unwrap_or(body.len());
                    let mut response =
                        format!("{status}\r\nContent-Length: {declared}\r\nConnection: close\r\n");
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

    /// Start a chunked-transfer fake (no Content-Length), writing the given bytes in a single chunk.
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
            // Write the full body in one chunk; after reqwest parses the chunked encoding, content_length is None
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

        // URL is rebuilt from the host alone: with the real base the path is always /favicon.ico;
        // once a test injects a local base, the host lands at the front of the path, so the shape
        // must be GET /{host}/favicon.ico (no extras beyond the port)
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
        let (base, _) = spawn_fake_favicon("HTTP/1.1 404 Not Found", &[], b"nope", None).await;
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
        let (base, _) =
            spawn_fake_favicon("HTTP/1.1 302 Found", &["Location: /moved"], b"", None).await;
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
        // Common SPA trap: 200 + HTML (the index.html fallback route); letting it into the cache guarantees broken icons
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
        // Content-Length lies about 600KB (the body is actually tiny) — the pre-check must bail before reading the body
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
        assert!(err.to_string().contains("too large"), "got: {err}");
    }

    #[tokio::test]
    async fn fetch_rejects_oversized_streaming_body() {
        // A chunked response has no Content-Length → the pre-check is skipped, so the streaming accumulation must catch the over-limit body
        let base = spawn_fake_chunked(vec![0u8; MAX_FAVICON_BYTES + 1]).await;
        let err = FaviconFetcher::new()
            .unwrap()
            .with_base_url(base)
            .fetch("example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("while streaming"), "got: {err}");
    }

    #[tokio::test]
    async fn fetch_rejects_empty_body() {
        let (base, _) =
            spawn_fake_favicon("HTTP/1.1 200 OK", &["Content-Type: image/png"], b"", None).await;
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
        // fetch is a public entry point: an IP host is rejected even if the caller bypasses extract and calls it directly
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
