//! 无账号信箱中继客户端：会话创建/投递/轮询与双端驱动循环。
//! （明文 HTTP 仅放行 loopback——配对材料不过公网明文。）

/// 中转信箱客户端（feature `remote-auth`）：persona-server
/// `/api/v1/pairing/*`。只做 wire（URL/方法/JSON/状态码/错误映射），
/// 密码学与状态机在 [`PairingHost`]/[`PairingGuest`]。
use std::time::Duration;

use base64::Engine as _;
use reqwest::Method;
use serde::Deserialize;

use super::{PairingGuest, PairingHost, PairingInviteLink, PairingMessage};
use crate::{PersonaError, Result};

/// 轮询间隔（take 即消费，无需长轮询）。
pub const POLL_EVERY: Duration = Duration::from_millis(500);
/// 单次配对的生命周期上限（对应中转 TTL 600s 的上限内侧）。
pub const DRIVE_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Debug, Deserialize)]
struct CreateSession {
    session_id: String,
    #[allow(dead_code)]
    expires_in_secs: i64,
}

#[derive(Debug, Deserialize)]
pub struct RelaySessionInfo {
    pub salt: Vec<u8>,
    pub expires_in_secs: i64,
    #[allow(dead_code)]
    pub to_host_len: i64,
    #[allow(dead_code)]
    pub to_guest_len: i64,
}

pub struct PairingRelayClient {
    base_url: String,
    http: reqwest::Client,
}

impl PairingRelayClient {
    /// Build a relay client, refusing to send pairing material over
    /// cleartext HTTP to a non-loopback host.
    ///
    /// Pairing messages carry the group key and invite secrets, so a plain
    /// `http://` relay on a real network would expose them in transit. Loopback
    /// (`http://127.0.0.1`, `http://localhost`, `http://[::1]`) stays allowed so
    /// local development and the in-process test relay keep working.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&base_url).map_err(|e| {
            PersonaError::ConfigurationError(format!("pairing relay URL is not a valid URL: {e}"))
        })?;
        if parsed.scheme() == "http" {
            let host = parsed
                .host_str()
                .unwrap_or_default()
                .trim_start_matches('[')
                .trim_end_matches(']');
            let loopback = host == "localhost"
                || host == "::1"
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
            if !loopback {
                return Err(PersonaError::ConfigurationError(
                    "pairing relay URL must use https:// (cleartext http:// is \
                     only allowed for loopback hosts)"
                        .to_string(),
                )
                .into());
            }
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| {
                PersonaError::ConfigurationError(format!("pairing relay client init failed: {e}"))
            })?;
        Ok(Self { base_url, http })
    }

    fn uri(&self, session_id: &str, path: &str) -> String {
        format!(
            "{}/api/v1/pairing/sessions/{session_id}{path}",
            self.base_url
        )
    }

    /// 非 2xx/422 统一转 [`PersonaError::Io`]（带服务器 error.message）；
    /// 422 转 [`PersonaError::Validation`]（队列满/载荷超限等）。
    async fn ensure_success(resp: reqwest::Response, step: &str) -> Result<reqwest::Response> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            });
        let message = match detail {
            Some(m) => format!("{step} failed (HTTP {status}): {m}"),
            None => format!("{step} failed (HTTP {status})"),
        };
        match status.as_u16() {
            422 => Err(PersonaError::Validation(message).into()),
            _ => Err(PersonaError::Io(message).into()),
        }
    }

    /// 建会话（host）：POST /sessions，返回 (session_id, expires_in_secs)。
    pub async fn create_session(
        &self,
        salt: &[u8; super::PAIRING_SALT_LEN],
    ) -> Result<(String, i64)> {
        let resp = self
            .http
            .request(
                Method::POST,
                format!("{}/api/v1/pairing/sessions", self.base_url),
            )
            .json(&serde_json::json!({
                "salt": base64::engine::general_purpose::STANDARD.encode(salt),
            }))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("pairing create request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "pairing create").await?;
        let created: CreateSession = resp
            .json()
            .await
            .map_err(|e| PersonaError::Io(format!("pairing create response malformed: {e}")))?;
        Ok((created.session_id, created.expires_in_secs))
    }

    /// 会话元信息（guest 取 salt）。
    pub async fn session_info(&self, session_id: &str) -> Result<RelaySessionInfo> {
        let resp = self
            .http
            .request(Method::GET, self.uri(session_id, ""))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("pairing info request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "pairing info").await?;
        let raw: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| PersonaError::Io(format!("pairing info response malformed: {e}")))?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(raw["salt"].as_str().unwrap_or_default())
            .map_err(|e| PersonaError::Io(format!("pairing info salt malformed: {e}")))?;
        Ok(RelaySessionInfo {
            salt,
            expires_in_secs: raw["expires_in_secs"].as_i64().unwrap_or(0),
            to_host_len: raw["to_host_len"].as_i64().unwrap_or(0),
            to_guest_len: raw["to_guest_len"].as_i64().unwrap_or(0),
        })
    }

    /// DELETE /sessions/{id}（完成/放弃后清理；幂等）。
    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        let resp = self
            .http
            .request(Method::DELETE, self.uri(session_id, ""))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("pairing delete request failed: {e}")))?;
        let _ = Self::ensure_success(resp, "pairing delete").await?;
        Ok(())
    }

    /// POST /sessions/{id}/messages/{direction}。
    async fn post_message(
        &self,
        session_id: &str,
        direction: &str,
        msg: &PairingMessage,
    ) -> Result<()> {
        let payload = serde_json::to_vec(msg)
            .map_err(|e| PersonaError::Io(format!("pairing message serialize failed: {e}")))?;
        let resp = self
            .http
            .request(
                Method::POST,
                self.uri(session_id, &format!("/messages/{direction}")),
            )
            .json(&serde_json::json!({
                "payload": base64::engine::general_purpose::STANDARD.encode(payload),
            }))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("pairing post failed: {e}")))?;
        let _ = Self::ensure_success(resp, "pairing post").await?;
        Ok(())
    }

    pub async fn post_to_host(&self, session_id: &str, msg: &PairingMessage) -> Result<()> {
        self.post_message(session_id, "to-host", msg).await
    }

    pub async fn post_to_guest(&self, session_id: &str, msg: &PairingMessage) -> Result<()> {
        self.post_message(session_id, "to-guest", msg).await
    }

    /// GET /sessions/{id}/messages/{direction}（取即消费）。
    async fn take_messages(
        &self,
        session_id: &str,
        direction: &str,
    ) -> Result<Vec<PairingMessage>> {
        let resp = self
            .http
            .request(
                Method::GET,
                self.uri(session_id, &format!("/messages/{direction}")),
            )
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("pairing take request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "pairing take").await?;
        let raw: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| PersonaError::Io(format!("pairing take response malformed: {e}")))?;
        let mut out = Vec::new();
        for m in raw["messages"]
            .as_array()
            .ok_or_else(|| PersonaError::Io("pairing take messages malformed".into()))?
        {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(m.as_str().unwrap_or_default())
                .map_err(|e| PersonaError::Io(format!("pairing take b64 malformed: {e}")))?;
            let msg: PairingMessage = serde_json::from_slice(&bytes)
                .map_err(|e| PersonaError::Io(format!("pairing message malformed: {e}")))?;
            out.push(msg);
        }
        Ok(out)
    }

    pub async fn take_to_host(&self, session_id: &str) -> Result<Vec<PairingMessage>> {
        self.take_messages(session_id, "to-host").await
    }

    pub async fn take_to_guest(&self, session_id: &str) -> Result<Vec<PairingMessage>> {
        self.take_messages(session_id, "to-guest").await
    }

    /// host 全自动驱动：等到 guest 的 ClientPublic 后交付 ServerOffer 与
    /// Handoff（[`PairingGuest`] 侧确认流程见 [`Self::join_begin`]）。
    /// 返回 host 短指纹（供 UI 与 guest 比对）。错码/超期 → Err。
    pub async fn drive_host(
        &self,
        host: &mut PairingHost,
        group_key: &[u8; super::PAIRING_GROUP_KEY_LEN],
        session_id: &str,
    ) -> Result<String> {
        let deadline = std::time::Instant::now() + DRIVE_DEADLINE;
        let mut fingerprint: Option<String> = None;
        loop {
            for msg in self.take_to_host(session_id).await? {
                let Some(reply) = host.handle_message(msg, group_key)? else {
                    return Err(PersonaError::Io("host 侧意外收到完成信号".into()).into());
                };
                if let Some(fp) = host.fingerprint() {
                    fingerprint = Some(fp);
                }
                self.post_to_guest(session_id, &reply).await?;
                if host.finished() {
                    return fingerprint.ok_or_else(|| {
                        { PersonaError::Io("配对完成但缺少指纹（状态异常）".into()) }.into()
                    });
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(PersonaError::Io("配对等待超时（90s，请重试）".into()).into());
            }
            tokio::time::sleep(POLL_EVERY).await;
        }
    }

    /// guest 第一步：解码邀请串、取 salt、起配、交 ClientPublic、
    /// 等回 ServerOffer。返回 (guest, 短指纹)——指纹展示给用户比对，
    /// 比对通过后调 [`Self::join_confirm`] 才真正入组。
    pub async fn join_begin(&self, link: &PairingInviteLink) -> Result<(PairingGuest, String)> {
        let info = self.session_info(&link.session_id).await?;
        if info.salt.len() != super::PAIRING_SALT_LEN {
            return Err(PersonaError::Io(format!(
                "relay salt 长度应为 {}，得 {}",
                super::PAIRING_SALT_LEN,
                info.salt.len()
            ))
            .into());
        }
        let (mut guest, first) = PairingGuest::start_message(&link.code, &info.salt)?;
        self.post_to_host(&link.session_id, &first).await?;
        let deadline = std::time::Instant::now() + DRIVE_DEADLINE;
        loop {
            if let Some(msg) = self
                .take_to_guest(&link.session_id)
                .await?
                .into_iter()
                .next()
            {
                let Some(reply) = guest.handle_message(msg)? else {
                    return Err(PersonaError::Io("配对意外提前完成".into()).into());
                };
                // ServerOffer 已消费 → ClientProof 待用户确认，先不投
                debug_assert!(
                    matches!(reply, PairingMessage::ClientProof { .. }),
                    "join_begin 只应停在 ClientProof 前"
                );
                let fp = guest
                    .fingerprint()
                    .ok_or_else(|| PersonaError::Io("指纹派生失败（状态异常）".into()))?;
                return Ok((guest, fp));
            }
            if std::time::Instant::now() >= deadline {
                return Err(PersonaError::Io("等待 host 应答超时（90s，请重试）".into()).into());
            }
            tokio::time::sleep(POLL_EVERY).await;
        }
    }

    /// guest 第二步：用户指纹比对通过——交 ClientProof，等 Handoff，
    /// 解出组密钥。调用后 [`PairingGuest::group_key`] 有值。
    pub async fn join_confirm(&self, guest: &mut PairingGuest, session_id: &str) -> Result<()> {
        // 取出 join_begin 持有的待投 M1
        let proof_msg = guest
            .take_pending_proof()
            .ok_or_else(|| PersonaError::Io("join_confirm 前必须先 join_begin".into()))?;
        self.post_to_host(session_id, &proof_msg).await?;
        let deadline = std::time::Instant::now() + DRIVE_DEADLINE;
        loop {
            if let Some(msg) = self.take_to_guest(session_id).await?.into_iter().next() {
                if let Some(_reply) = guest.handle_message(msg)? {
                    return Err(PersonaError::Io("后续不应再有应答消息".into()).into());
                }
                // None = 配对完成，组密钥已落袋
                self.delete_session(session_id).await.ok();
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(PersonaError::Io("等待交接超时（90s，请重试）".into()).into());
            }
            tokio::time::sleep(POLL_EVERY).await;
        }
    }
}
