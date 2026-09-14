//! Breach checking for the Watchtower health scan.
//!
//! The [`BreachChecker`] trait works purely in SHA-1 hex space: callers hash
//! passwords themselves and hand the checker only digests, so **no
//! implementation ever sees plaintext secrets**. The reference implementation
//! is [`HibpBreachChecker`] (behind the `hibp` feature), which queries the
//! Have I Been Pwned Pwned Passwords API using k-anonymity: only the first
//! five hex characters of the SHA-1 digest ever leave the machine, and the
//! remaining 35 are matched locally against the server's response.

use crate::Result;
use async_trait::async_trait;
use sha1::{Digest, Sha1};
#[cfg(feature = "hibp")]
use std::collections::BTreeMap;
use std::collections::HashMap;

/// Check secret material against a breach corpus.
///
/// Implementations receive and return uppercase SHA-1 hex digests; the map
/// must contain an entry for every input digest (0 = not seen in breaches).
#[async_trait]
pub trait BreachChecker: Send + Sync {
    async fn breach_counts(&self, sha1_hex: &[String]) -> Result<HashMap<String, u64>>;
}

/// Uppercase SHA-1 hex digest of a secret, as used across the breach-check
/// seam. Callers pass digests — never plaintext — to [`BreachChecker`].
pub fn sha1_hex_upper(secret: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(secret.as_bytes());
    hex::encode_upper(hasher.finalize())
}

/// The 5-character k-anonymity prefix sent to the HIBP range endpoint.
/// Input is expected to be uppercase hex (see [`sha1_hex_upper`]); shorter
/// inputs are returned as-is.
pub fn sha1_hex_prefix(sha1_hex: &str) -> &str {
    let end = sha1_hex.len().min(5).min(sha1_hex.len());
    &sha1_hex[..end]
}

/// Parse a HIBP range response (`"<suffix35>:<count>"` per line).
///
/// Blank and malformed lines are skipped silently — partial garbage must
/// not lose the parseable majority, mirroring the bank-card expiry rule.
/// Suffixes are normalized to uppercase to match [`sha1_hex_upper`].
pub fn parse_range_response(body: &str) -> HashMap<String, u64> {
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (suffix, count) = line.split_once(':')?;
            let count: u64 = count.trim().parse().ok()?;
            Some((suffix.trim().to_ascii_uppercase(), count))
        })
        .collect()
}

/// HIBP Pwned Passwords k-anonymity client (`hibp` feature).
///
/// Only the 5-character digest prefix is transmitted; the full digest and
/// the plaintext never leave the machine. Requests are sent sequentially,
/// one per distinct prefix (deduplicated) — HIBP's rate limits are generous
/// and watchtower scans are small, so no retry logic is needed.
#[cfg(feature = "hibp")]
pub struct HibpBreachChecker {
    http: reqwest::Client,
    base_url: String,
}

#[cfg(feature = "hibp")]
impl HibpBreachChecker {
    /// Client with a 10s timeout and an identifying User-Agent.
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("persona-watchtower")
            .build()?;
        Ok(Self {
            http,
            base_url: "https://api.pwnedpasswords.com/range/".to_string(),
        })
    }

    /// Override the endpoint (tests point this at a local fake).
    #[cfg(test)]
    pub(crate) fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    async fn fetch_prefix(&self, prefix: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, prefix);
        let response = self.http.get(&url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!(
                "HIBP range request failed with status {} for prefix {prefix}",
                response.status()
            );
        }
        Ok(response.text().await?)
    }
}

#[cfg(feature = "hibp")]
#[async_trait]
impl BreachChecker for HibpBreachChecker {
    async fn breach_counts(&self, sha1_hex: &[String]) -> Result<HashMap<String, u64>> {
        // One request per distinct prefix; results are matched locally.
        let mut by_prefix: BTreeMap<String, Vec<&String>> = BTreeMap::new();
        for digest in sha1_hex {
            by_prefix
                .entry(sha1_hex_prefix(digest).to_string())
                .or_default()
                .push(digest);
        }

        let mut counts = HashMap::with_capacity(sha1_hex.len());
        for (prefix, digests) in by_prefix {
            let suffixes = parse_range_response(&self.fetch_prefix(&prefix).await?);
            for digest in digests {
                let count = suffixes
                    .get(&digest[sha1_hex_prefix(digest).len()..])
                    .copied();
                counts.insert(digest.clone(), count.unwrap_or(0));
            }
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // sha1("password") — the canonical HIBP example digest.
    const PASSWORD_SHA1: &str = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn sha1_hex_upper_matches_known_vectors() {
        assert_eq!(sha1_hex_upper("password"), PASSWORD_SHA1);
        assert_eq!(
            sha1_hex_upper(""),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
    }

    #[test]
    fn prefix_takes_first_five_chars() {
        assert_eq!(sha1_hex_prefix(PASSWORD_SHA1), "5BAA6");
        assert_eq!(sha1_hex_prefix("ABC"), "ABC");
        assert_eq!(sha1_hex_prefix(""), "");
    }

    #[test]
    fn parse_range_response_handles_lines_and_garbage() {
        let parsed = parse_range_response(
            "0034660C6A1B:1\n00F3FA63D6B1:2\n\n0120D0b58AAC:3\nnot-a-line\n012A:oops\n012B\n",
        );
        assert_eq!(parsed.get("0034660C6A1B"), Some(&1));
        assert_eq!(parsed.get("00F3FA63D6B1"), Some(&2));
        // Lowercase suffixes are normalized so lookups match uppercase digests.
        assert_eq!(parsed.get("0120D0B58AAC"), Some(&3));
        // Garbage lines are skipped, not fatal.
        assert_eq!(parsed.len(), 3);
        assert_eq!(parse_range_response(""), HashMap::new());
    }

    /// Start a local fake of the HIBP range endpoint; returns the base URL
    /// to inject and a log of request lines it received.
    #[cfg(feature = "hibp")]
    async fn spawn_fake_hibp(
        status: &'static str,
        body: &'static str,
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
                    let response = format!(
                        "{status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        (format!("http://{addr}/range/"), requests)
    }

    #[tokio::test]
    #[cfg(feature = "hibp")]
    async fn hibp_checker_queries_prefix_only_and_matches_suffix() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:37451\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2\n";
        let (base_url, requests) = spawn_fake_hibp("HTTP/1.1 200 OK", body).await;

        let checker = HibpBreachChecker::new().unwrap().with_base_url(base_url);
        let out = checker
            .breach_counts(&[PASSWORD_SHA1.to_string()])
            .await
            .unwrap();

        // Suffix of the digest matched; count carried through.
        assert_eq!(out.get(PASSWORD_SHA1), Some(&37451));

        // Privacy anchor: the request line carries only the 5-char prefix,
        // never the full digest or any secret material.
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with("GET /range/5BAA6 HTTP/1.1"),
            "unexpected request line: {}",
            requests[0]
        );
        assert!(!requests[0].contains(PASSWORD_SHA1));
    }

    #[tokio::test]
    #[cfg(feature = "hibp")]
    async fn hibp_checker_dedupes_prefixes_and_reports_zero_for_missing() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9\n";
        let (base_url, requests) = spawn_fake_hibp("HTTP/1.1 200 OK", body).await;

        // Digests are opaque to the checker (it only slices prefixes), so a
        // synthetic same-prefix digest is fine; the third one has no match.
        let other = format!("{}{}", sha1_hex_prefix(PASSWORD_SHA1), "F".repeat(35));
        let unrelated = "F".repeat(40);

        let checker = HibpBreachChecker::new().unwrap().with_base_url(base_url);
        let out = checker
            .breach_counts(&[PASSWORD_SHA1.to_string(), other.clone(), unrelated.clone()])
            .await
            .unwrap();

        assert_eq!(out.get(PASSWORD_SHA1), Some(&9));
        // Same prefix, different suffix → present in mapping but count 0.
        assert_eq!(out.get(&other), Some(&0));
        assert_eq!(out.get(&unrelated), Some(&0), "missing suffix counts as 0");
        assert_eq!(out.len(), 3, "every input digest gets an entry");

        // Two distinct prefixes → two requests; the shared prefix was
        // queried once despite two digests (three requests without dedupe).
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.contains("/range/5BAA6"))
                .count(),
            1,
            "shared prefix must be queried exactly once"
        );
    }

    #[tokio::test]
    #[cfg(feature = "hibp")]
    async fn hibp_checker_surfaces_http_errors() {
        let (base_url, _requests) =
            spawn_fake_hibp("HTTP/1.1 500 Internal Server Error", "nope").await;

        let checker = HibpBreachChecker::new().unwrap().with_base_url(base_url);
        let err = checker
            .breach_counts(&[PASSWORD_SHA1.to_string()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"));
    }
}
