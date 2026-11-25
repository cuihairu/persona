//! /api authentication: a set of named-device Bearer tokens + SRP short-term tokens,
//! fail-closed.
//!
//! `PERSONA_SERVER_TOKENS="laptop:tok1,phone:tok2"` configures multi-device tokens;
//! the legacy `PERSONA_SERVER_TOKEN` is still accepted (as the "default" device). With no
//! token configured at all, all of /api is 503 (disabled takes precedence over
//! authentication failure, exposing no probeable difference); when configured,
//! `require_bearer` tries the static tokens then the SRP short-term tokens in turn (the
//! latter issued by the `/api/v1/auth/*` handshake, E2EE sync track phase 1), performing an
//! early-exit-free constant-time comparison against the static entries. The device name is
//! derived from the winning token and cannot be self-reported by the client; on a hit it is
//! passed to handlers via request extensions ([`DeviceName`]). `/`, `/health` and
//! `/metrics` are authentication-free.
//!
//! SRP session/token/lockout state ([`SrpAuthState`]) is entirely in memory and
//! deliberately not persisted.

use std::collections::HashMap;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use subtle::ConstantTimeEq;

use crate::api::ApiError;
use crate::state::AppState;

/// A single named-device token.
struct DeviceToken {
    device_name: String,
    token: String,
}

/// A set of named-device tokens (the parse result of `PERSONA_SERVER_TOKENS`).
///
/// Until device names land in the devices table in phase 2, they are derived from token
/// ownership; the wire protocol is unchanged.
pub struct AuthTokens {
    entries: Vec<DeviceToken>,
}

impl AuthTokens {
    /// The legacy single-token view: acts as the "default" device. An empty string is
    /// equivalent to unconfigured (empty set, API disabled — keeping the filtering
    /// semantics of "configured but wrongly, to an empty value").
    pub fn single(token: &str) -> Self {
        if token.is_empty() {
            return Self {
                entries: Vec::new(),
            };
        }
        Self {
            entries: vec![DeviceToken {
                device_name: "default".to_owned(),
                token: token.to_owned(),
            }],
        }
    }

    /// Parses `name:token,name:token`.
    ///
    /// Fail-closed: names are non-empty, at most 64 bytes (UTF-8), and contain no
    /// `:`/`,`/whitespace; tokens are non-empty; device names must not repeat (ambiguous
    /// ownership); any invalid entry returns Err (main errors out at startup — a
    /// "configured but wrongly" state must not be allowed to become half-usable). An empty
    /// spec yields an empty set (equivalent to unconfigured).
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for raw in spec.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            let Some((name, token)) = entry.split_once(':') else {
                return Err(format!("条目 {entry:?} 缺少 name:token 分隔符"));
            };
            let name = name.trim();
            let token = token.trim();
            if name.is_empty()
                || name.len() > 64
                || name.contains(|c: char| c.is_whitespace())
                || token.is_empty()
                || token.contains(|c: char| c.is_whitespace())
            {
                return Err(format!(
                    "条目 {entry:?} 非法：设备名须非空且 ≤64 字节且不含空白，令牌须非空且不含空白"
                ));
            }
            if name.contains(',') || token.contains(',') {
                // Leftovers already truncated by split(',') are explicitly rejected here
                // (e.g. "a:b,c" is one whole entry)
                return Err(format!("条目 {entry:?} 含非法字符 ','"));
            }
            if entries
                .iter()
                .any(|entry: &DeviceToken| entry.device_name == name)
            {
                return Err(format!("设备名 {name:?} 重复"));
            }
            entries.push(DeviceToken {
                device_name: name.to_owned(),
                token: token.to_owned(),
            });
        }
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Runs an early-exit-free constant-time comparison over every entry and returns the
    /// winning entry's device name.
    ///
    /// The loop always runs to completion whether or not a hit has occurred (a constant
    /// number of comparisons), avoiding leaking by position which entry was correct.
    pub fn authenticate(&self, provided: &[u8]) -> Option<&str> {
        let mut matched: Option<&str> = None;
        for entry in &self.entries {
            let equal = constant_time_eq(provided, entry.token.as_bytes());
            if equal && matched.is_none() {
                matched = Some(&entry.device_name);
            }
        }
        matched
    }
}

/// The device name injected by the authentication middleware (derived from the winning
/// token; the client cannot self-report it). Backup endpoints attribute versions by this;
/// a missing extension means the auth layer was bypassed, and extraction fails with 500.
#[derive(Clone, Debug)]
pub struct DeviceName(pub String);

/// The in-memory state for SRP sessions/tokens/lockouts (E2EE sync track phase 1).
///
/// Everything is **deliberately not persisted**: a server restart = pending handshakes
/// are lost (clients re-run challenge) and short-term tokens become invalid (clients log
/// in again) — authentication sessions are not data, and persisting them would only widen
/// the attack surface. It shares `AuthTokens`' lifecycle: it exists only when static
/// tokens are configured (fail-closed alignment — TOKENS unset = the auth system is not
/// enabled at all).
pub struct SrpAuthState {
    /// Pending challenges: session_id -> (device name, b_priv, a_pub, filter moment).
    /// b_priv is as sensitive as the verifier; it stays in memory only and is dropped when
    /// its TTL expires.
    challenges: std::sync::Mutex<HashMap<String, SrpChallengeEntry>>,
    /// Issued short-term tokens: token -> (device name, expiry moment).
    tokens: std::sync::RwLock<HashMap<String, SrpTokenEntry>>,
    /// Failure counts (lockout): device name -> (consecutive failures, lockout deadline).
    failures: std::sync::Mutex<HashMap<String, SrpFailureEntry>>,
}

pub(crate) struct SrpChallengeEntry {
    pub(crate) device_name: String,
    pub(crate) verifier: Vec<u8>,
    pub(crate) b_priv: Vec<u8>,
    pub(crate) client_public: Vec<u8>,
    pub(crate) expires_at: std::time::Instant,
}

impl SrpAuthState {
    pub fn new() -> Self {
        Self {
            challenges: std::sync::Mutex::new(HashMap::new()),
            tokens: std::sync::RwLock::new(HashMap::new()),
            failures: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn store_challenge(&self, id: String, entry: SrpChallengeEntry) {
        self.challenges
            .lock()
            .expect("challenge lock")
            .insert(id, entry);
    }

    /// Take an unexpired challenge (removed from the cache upon verification — one entry
    /// per handshake).
    pub(crate) fn take_challenge(&self, id: &str) -> Option<SrpChallengeEntry> {
        let mut map = self.challenges.lock().expect("challenge lock");
        Self::prune_challenges(&mut map);
        map.remove(id)
            .filter(|e| e.expires_at > std::time::Instant::now())
    }

    /// Lazy cleanup: every touch of the cache also drops expired entries (no timer task).
    fn prune_challenges(map: &mut HashMap<String, SrpChallengeEntry>) {
        let now = std::time::Instant::now();
        map.retain(|_, e| e.expires_at > now);
    }

    /// Issue a short-term Bearer token (random, at least 256-bit, base64url).
    pub(crate) fn issue_token(&self, device_name: &str) -> String {
        let raw: [u8; 32] = rand::random();
        let token = URL_SAFE_NO_PAD.encode(raw);
        self.tokens.write().expect("token lock").insert(
            token.clone(),
            SrpTokenEntry {
                device_name: device_name.to_owned(),
                expires_at: std::time::Instant::now() + SRP_TOKEN_TTL,
            },
        );
        token
    }

    /// Verify a short-term token and return the device name on a hit; expired entries are
    /// pruned along the way.
    pub fn authenticate_token(&self, token: &str) -> Option<String> {
        let mut map = self.tokens.write().expect("token lock");
        let now = std::time::Instant::now();
        map.retain(|_, e| e.expires_at > now);
        map.get(token).map(|e| e.device_name.clone())
    }

    /// Revoke every unexpired short-term token of a device and discard its pending
    /// handshakes (device-lifecycle closure: invoked in cascade when a sync device is
    /// revoked — existing tokens become invalid **immediately** rather than waiting for
    /// the TTL to run out). Returns the number of token entries removed.
    pub fn revoke_device(&self, device_name: &str) -> usize {
        let mut tokens = self.tokens.write().expect("token lock");
        let before = tokens.len();
        tokens.retain(|_, e| e.device_name != device_name);
        let removed = before - tokens.len();
        drop(tokens);
        self.challenges
            .lock()
            .expect("challenge lock")
            .retain(|_, e| e.device_name != device_name);
        removed
    }

    /// Login failure accounting.
    pub(crate) fn register_failure(&self, device_name: &str) {
        let mut map = self.failures.lock().expect("failure lock");
        let entry = map
            .entry(device_name.to_owned())
            .or_insert(SrpFailureEntry {
                count: 0,
                locked_until: None,
            });
        if let Some(until) = entry.locked_until {
            if until > std::time::Instant::now() {
                return; // already locked: no accumulation within the window (resetting is
                        // pointless)
            }
        }
        entry.count += 1;
        if entry.count >= SRP_MAX_FAILURES {
            entry.locked_until = Some(std::time::Instant::now() + SRP_LOCKOUT);
            entry.count = 0;
        }
    }

    /// Login success: clear the failure count.
    pub(crate) fn clear_failures(&self, device_name: &str) {
        self.failures
            .lock()
            .expect("failure lock")
            .remove(device_name);
    }

    /// Whether currently locked (pre-checked at the verify entry point; no side effects).
    pub(crate) fn is_locked(&self, device_name: &str) -> bool {
        self.failures
            .lock()
            .expect("failure lock")
            .get(device_name)
            .and_then(|e| e.locked_until)
            .is_some_and(|until| until > std::time::Instant::now())
    }
}

/// Challenge cache lifetime: the client completes verify within the window; past it, the
/// client re-runs challenge.
pub(crate) const SRP_CHALLENGE_TTL: std::time::Duration = std::time::Duration::from_secs(120);

/// Short-term token TTL: 15 minutes. Past it, the client logs in again via SRP (matching
/// the design doc's "on the order of minutes").
pub(crate) const SRP_TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(900);

/// Lockout threshold: 5 consecutive failures (matching the local user_auth's semantics
/// of 5).
pub(crate) const SRP_MAX_FAILURES: u32 = 5;

/// Lockout duration.
pub(crate) const SRP_LOCKOUT: std::time::Duration = std::time::Duration::from_secs(900);

impl Default for SrpAuthState {
    fn default() -> Self {
        Self::new()
    }
}

struct SrpTokenEntry {
    device_name: String,
    expires_at: std::time::Instant,
}

struct SrpFailureEntry {
    count: u32,
    locked_until: Option<std::time::Instant>,
}

pub async fn require_bearer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(tokens) = state.auth.as_deref() else {
        return ApiError::disabled().into_response();
    };
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(extract_bearer);
    // Static tokens first (early-exit-free constant-time comparison); on a miss, consult
    // the short-term token table if SRP is configured (hash-table lookup — the tokens are
    // random values of at least 256 bits, so there is no dictionary to mount).
    let device = provided.and_then(|token| {
        tokens
            .authenticate(token.as_bytes())
            .map(str::to_owned)
            .or_else(|| state.srp.as_ref()?.authenticate_token(token))
    });
    let Some(device) = device else {
        return ApiError::unauthorized().into_response();
    };
    let mut req = req;
    req.extensions_mut().insert(DeviceName(device));
    next.run(req).await
}

/// The Bearer middleware dedicated to the account routes (M2: the consumer of
/// `account_sessions` tokens).
///
/// It behaves exactly like [`require_bearer`] for the static tokens / SRP short-term
/// tokens it recognizes; on top of that it also accepts unexpired account session tokens
/// from `account_sessions` — the 15-minute tokens issued by srp/verify and the 24-hour
/// tokens issued by the sessions endpoint — but lets them through only on their own
/// account's paths (`/api/v1/accounts/{account_id}/...`; cross-account is always 401,
/// shaped like any other failure). The migration-0007 boundary is unchanged: account
/// sessions do not serve as the Bearer for sync/events/backups — those routes still go
/// through [`require_bearer`] (which does not consult account_sessions).
pub async fn require_account_bearer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(tokens) = state.auth.as_deref() else {
        return ApiError::disabled().into_response();
    };
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(extract_bearer);
    // Static/SRP short-term tokens first (same order and semantics as require_bearer,
    // with no DB query).
    if let Some(device) = provided.and_then(|token| {
        tokens
            .authenticate(token.as_bytes())
            .map(str::to_owned)
            .or_else(|| state.srp.as_ref()?.authenticate_token(token))
    }) {
        let mut req = req;
        req.extensions_mut().insert(DeviceName(device));
        return next.run(req).await;
    }
    // Account session token: admitted only when the row is unexpired + the path's
    // account_id matches the owner; failing either falls into the uniform 401 (which does
    // not leak whether the row exists).
    if let (Some(token), Some(path_account)) = (provided, account_path_id(req.uri().path())) {
        if let Some(owner) = live_account_session_owner(&state, token).await {
            if owner == path_account {
                touch_session_activity(&state, token).await;
                let mut req = req;
                req.extensions_mut()
                    .insert(DeviceName(format!("account:{owner}")));
                return next.run(req).await;
            }
        }
    }
    ApiError::unauthorized().into_response()
}

/// This middleware's mount-point path -> the account_id segment (returns None on a shape
/// mismatch, and session-token paths are then not admitted — fail-closed).
///
/// axum 0.8's `nest` strips the prefix before handing off to the inner router; after the
/// two nesting levels `/api/v1` and `/accounts` are stripped, the middleware sees
/// `/{account_id}/...` — the first segment is the account_id. The shape is used only for
/// the session token's path-ownership comparison (first segment not equal to the token's
/// owning account -> 401); a conservative parse can only cause rejection, never admit the
/// wrong account.
fn account_path_id(path: &str) -> Option<&str> {
    let account_id = path.strip_prefix('/')?.split('/').next()?;
    (!account_id.is_empty()).then_some(account_id)
}

/// Look up the owning account_id of an unexpired account session (the TTL check uses the
/// same convention as the issuing/evidence-verification side: an RFC3339 string
/// comparison of `expires_at > now`).
async fn live_account_session_owner(state: &AppState, token: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT account_id FROM account_sessions
         WHERE session_token = ? AND expires_at > ? LIMIT 1",
    )
    .bind(token)
    .bind(chrono::Utc::now().to_rfc3339())
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
}

/// The consumption-side activity touch for session tokens (last_activity_at; a failure
/// does not block the request).
async fn touch_session_activity(state: &AppState, token: &str) {
    let _ = sqlx::query("UPDATE account_sessions SET last_activity_at = ? WHERE session_token = ?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(token)
        .execute(&state.pool)
        .await;
}

/// Parse `Bearer <token>`: the scheme is case-insensitive, the token matches exactly.
fn extract_bearer(value: &HeaderValue) -> Option<&str> {
    let value = value.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Constant-time comparison: length differences are folded into the accumulator, with no
/// early exit anywhere.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut acc = (a.len() ^ b.len()) as u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    bool::from(acc.ct_eq(&0))
}

#[cfg(test)]
mod tests {
    use super::{constant_time_eq, AuthTokens};

    #[test]
    fn constant_time_eq_matches_equal_slices() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"tokeN"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths_and_empty() {
        assert!(!constant_time_eq(b"token", b"tok"));
        assert!(!constant_time_eq(b"", b"token"));
        assert!(constant_time_eq(b"", b""));
    }

    // Revocation closure (device lifecycle): revoke_device clears all of that device's
    // unexpired tokens and pending handshakes; other devices' tokens are untouched;
    // repeated revocation is a no-op.
    #[test]
    fn revoke_device_evicts_tokens_and_challenges_for_that_device_only() {
        use super::{SrpAuthState, SrpChallengeEntry};

        let srp = SrpAuthState::new();
        let a1 = srp.issue_token("laptop");
        let a2 = srp.issue_token("laptop");
        let b1 = srp.issue_token("phone");
        srp.store_challenge(
            "sess-a".to_string(),
            SrpChallengeEntry {
                device_name: "laptop".to_string(),
                verifier: vec![0; 512],
                b_priv: vec![1; 32],
                client_public: vec![2; 32],
                expires_at: std::time::Instant::now() + std::time::Duration::from_secs(60),
            },
        );

        assert_eq!(srp.revoke_device("laptop"), 2);
        assert_eq!(srp.authenticate_token(&a1), None);
        assert_eq!(srp.authenticate_token(&a2), None);
        assert_eq!(srp.authenticate_token(&b1).as_deref(), Some("phone"));
        assert!(srp.take_challenge("sess-a").is_none());
        // Repeated revocation is a no-op
        assert_eq!(srp.revoke_device("laptop"), 0);
    }

    #[test]
    fn parse_accepts_multiple_named_devices() {
        let tokens = AuthTokens::parse("laptop:tok1,phone:tok2, tablet:tok3 ").unwrap();
        assert_eq!(tokens.authenticate(b"tok1"), Some("laptop"));
        assert_eq!(tokens.authenticate(b"tok2"), Some("phone"));
        assert_eq!(tokens.authenticate(b"tok3"), Some("tablet"));
        assert_eq!(tokens.authenticate(b"nope"), None);
        assert_eq!(tokens.authenticate(b""), None);
    }

    #[test]
    fn parse_returns_empty_collection_for_blank_spec() {
        assert!(AuthTokens::parse("").unwrap().is_empty());
        assert!(AuthTokens::parse(" , ").unwrap().is_empty());
    }

    #[test]
    fn parse_rejects_malformed_entries() {
        // Missing separator / empty name / empty token / duplicate device name / name or
        // token containing whitespace
        assert!(AuthTokens::parse("laptop").is_err());
        assert!(AuthTokens::parse(":tok").is_err());
        assert!(AuthTokens::parse("laptop:").is_err());
        assert!(AuthTokens::parse("lap top:tok").is_err());
        assert!(AuthTokens::parse("laptop:to k").is_err());
        assert!(AuthTokens::parse("laptop:tok,laptop:tok2").is_err());
        // "a:b,c" gets truncated by split(',') into "a:b" (legal) — a leftover comma cannot
        // exist inside an entry, but the explicit illegal-character check is a backstop
        // against format changes
    }

    #[test]
    fn parse_rejects_overlong_device_names() {
        let name = "x".repeat(65);
        assert!(AuthTokens::parse(&format!("{name}:tok")).is_err());
        let name = "x".repeat(64);
        assert!(AuthTokens::parse(&format!("{name}:tok")).is_ok());
    }

    #[test]
    fn single_token_authenticates_as_default_device() {
        let tokens = AuthTokens::single("legacy");
        assert_eq!(tokens.authenticate(b"legacy"), Some("default"));
        assert_eq!(tokens.authenticate(b"other"), None);
    }

    #[test]
    fn account_path_id_extracts_the_account_segment_only() {
        use super::account_path_id;
        // The mount-point shape after axum 0.8's two nesting levels (/api/v1, /accounts)
        // strip their prefixes
        assert_eq!(account_path_id("/abc/devices"), Some("abc"));
        assert_eq!(account_path_id("/abc"), Some("abc"));
        assert_eq!(account_path_id("/abc/sessions/tok"), Some("abc"));
        // Empty segment / not starting with `/`: always None (fail-closed; a shape
        // deviation can only cause rejection)
        assert_eq!(account_path_id("/"), None);
        assert_eq!(account_path_id(""), None);
        assert_eq!(account_path_id("abc/devices"), None);
    }

    #[test]
    fn authenticate_does_not_short_circuit_on_earlier_match() {
        // After an earlier entry hits, the loop still runs to completion: the absence of an
        // early exit cannot be asserted directly in these semantics, but every hit path
        // must return the first winning entry's device name.
        let tokens = AuthTokens::parse("a:t1,b:t2").unwrap();
        assert_eq!(tokens.authenticate(b"t1"), Some("a"));
        assert_eq!(tokens.authenticate(b"t2"), Some("b"));
    }
}
