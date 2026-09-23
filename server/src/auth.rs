//! /api 认证：命名设备 Bearer 令牌集合 + SRP 短期令牌，fail-closed。
//!
//! `PERSONA_SERVER_TOKENS="laptop:tok1,phone:tok2"` 配置多设备令牌；
//! 兼容旧 `PERSONA_SERVER_TOKEN`（作为 "default" 设备）。未配置任何令牌
//! 时 /api 全部 503（禁用优先于认证失败，避免暴露任何可探测差异）；
//! 已配置时 `require_bearer` 依次尝试静态令牌与 SRP 短期令牌（后者由
//! `/api/v1/auth/*` 握手签发，E2EE 同步轨道阶段 1），对静态条目做无早退的
//! 常量时间比较。设备名由命中的令牌推导、客户端不可自报，命中后经
//! request extensions（[`DeviceName`]）传给处理器。`/`、`/health`、
//! `/metrics` 免认证。
//!
//! SRP 会话/令牌/锁户状态（[`SrpAuthState`]）全部内存态、有意不持久化。

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

/// 单个命名设备令牌。
struct DeviceToken {
    device_name: String,
    token: String,
}

/// 命名设备令牌集合（`PERSONA_SERVER_TOKENS` 的解析结果）。
///
/// 设备名在 phase 2 落 devices 表前由令牌归属推导，wire 协议不变。
pub struct AuthTokens {
    entries: Vec<DeviceToken>,
}

impl AuthTokens {
    /// legacy 单令牌视图：作为 "default" 设备。空串与未配置等价
    /// （空集合，API 禁用——沿用"配了但配错成空"的过滤语义）。
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

    /// 解析 `name:token,name:token`。
    ///
    /// fail-closed：名字非空、≤64 字节（UTF-8）、不含 `:`/`,`/空白，
    /// token 非空，设备名不得重复（归属歧义），任何非法条目返回 Err
    /// （main 启动即错，不允许"配了但配错"形成半可用状态）。空 spec
    /// 返回空集合（与未配置等价）。
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
                // split(',') 已截断的残余在此显式报错（如 "a:b,c" 整体是一条目）
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

    /// 对全部条目做无早退常量时间比较，返回命中条目的设备名。
    ///
    /// 不论是否已命中都遍历完（比较次数恒定），避免按位置泄露哪个
    /// 条目正确。
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

/// 认证中间件注入的设备名（由命中的令牌推导，客户端不可自报）。
/// 备份端点以此归属版本；缺 extension 说明绕过了认证层，提取失败 500。
#[derive(Clone, Debug)]
pub struct DeviceName(pub String);

/// SRP 会话/令牌/锁户的内存状态（E2EE 同步轨道阶段 1）。
///
/// 全部**有意不持久化**：服务器重启 = 未决握手丢失（客户端重走 challenge）
/// 且短期令牌失效（客户端重新登录）——认证会话不是数据，落盘只会扩大
/// 攻击面。与 `AuthTokens` 同生命周期：仅在静态令牌已配置时存在
/// （fail-closed 对齐——TOKENS 未配 = 认证体系整体未启用）。
pub struct SrpAuthState {
    /// 未决 challenge：session_id → (设备名, b_priv, a_pub, 过滤时刻)。
    /// b_priv 与 verifier 一样敏感，只留内存、TTL 到期即弃。
    challenges: std::sync::Mutex<HashMap<String, SrpChallengeEntry>>,
    /// 已签发短期令牌：token → (设备名, 过期时刻)。
    tokens: std::sync::RwLock<HashMap<String, SrpTokenEntry>>,
    /// 失败计数（锁户）：设备名 → (连续失败次数, 锁定截止)。
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

    /// 取走一个未过期的 challenge（验证后即从缓存移除——一次握手一条）。
    pub(crate) fn take_challenge(&self, id: &str) -> Option<SrpChallengeEntry> {
        let mut map = self.challenges.lock().expect("challenge lock");
        Self::prune_challenges(&mut map);
        map.remove(id)
            .filter(|e| e.expires_at > std::time::Instant::now())
    }

    /// 惰性清理：每次触碰缓存时顺带丢掉过期项（无定时任务）。
    fn prune_challenges(map: &mut HashMap<String, SrpChallengeEntry>) {
        let now = std::time::Instant::now();
        map.retain(|_, e| e.expires_at > now);
    }

    /// 签发短期 Bearer 令牌（随机 ≥256-bit，base64url）。
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

    /// 校验短期令牌，命中返回设备名；顺带清过期项。
    pub fn authenticate_token(&self, token: &str) -> Option<String> {
        let mut map = self.tokens.write().expect("token lock");
        let now = std::time::Instant::now();
        map.retain(|_, e| e.expires_at > now);
        map.get(token).map(|e| e.device_name.clone())
    }

    /// 吊销一台设备的全部未到期短期令牌并丢弃其未决握手（设备生命周期
    /// 闭环：同步设备被吊销时级联调用——既有令牌**即刻**失效，而非等
    /// TTL 自然过期）。返回清除的令牌条数。
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

    /// 登录失败记账。
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
                return; // 已锁定：窗口内不累计（重置无意义）
            }
        }
        entry.count += 1;
        if entry.count >= SRP_MAX_FAILURES {
            entry.locked_until = Some(std::time::Instant::now() + SRP_LOCKOUT);
            entry.count = 0;
        }
    }

    /// 登录成功：清失败计数。
    pub(crate) fn clear_failures(&self, device_name: &str) {
        self.failures
            .lock()
            .expect("failure lock")
            .remove(device_name);
    }

    /// 当前是否锁定（verify 入口预检；不产生副作用）。
    pub(crate) fn is_locked(&self, device_name: &str) -> bool {
        self.failures
            .lock()
            .expect("failure lock")
            .get(device_name)
            .and_then(|e| e.locked_until)
            .is_some_and(|until| until > std::time::Instant::now())
    }
}

/// challenge 缓存存活期：客户端在窗口内完成 verify，过期重走 challenge。
pub(crate) const SRP_CHALLENGE_TTL: std::time::Duration = std::time::Duration::from_secs(120);

/// 短期令牌 TTL：15 分钟。过期重新 SRP 登录（对齐设计稿「分钟级」）。
pub(crate) const SRP_TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(900);

/// 锁户阈值：连续失败 5 次（对齐本机 user_auth 的 5 次语义）。
pub(crate) const SRP_MAX_FAILURES: u32 = 5;

/// 锁户时长。
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
    // 静态令牌优先（无早退常量时间比较）；未命中且配置了 SRP 时再查
    // 短期令牌表（哈希表查找——令牌是 ≥256-bit 随机值，无字典可挡）。
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

/// 解析 `Bearer <token>`：scheme 大小写不敏感，token 精确匹配。
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

/// 常量时间比较：长度差异并入累计值，全程无早退。
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

    // 吊销闭环（设备生命周期）：revoke_device 清掉该设备全部未到期令牌
    // 与未决握手，其他设备令牌不受影响；重复吊销 no-op。
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
        // 重复吊销 no-op
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
        // 缺分隔符 / 空名 / 空令牌 / 重复设备名 / 含空白的名或令牌
        assert!(AuthTokens::parse("laptop").is_err());
        assert!(AuthTokens::parse(":tok").is_err());
        assert!(AuthTokens::parse("laptop:").is_err());
        assert!(AuthTokens::parse("lap top:tok").is_err());
        assert!(AuthTokens::parse("laptop:to k").is_err());
        assert!(AuthTokens::parse("laptop:tok,laptop:tok2").is_err());
        // "a:b,c" 被 split(',') 截断成 "a:b"（合法）——残余逗号在条目内
        // 无法存在，但显式的非法字符检查兜底防御格式变化
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
    fn authenticate_does_not_short_circuit_on_earlier_match() {
        // 前面的条目命中后仍遍历完：语义上无从直接断言无早退，
        // 但全部命中路径必须返回第一个命中的设备名。
        let tokens = AuthTokens::parse("a:t1,b:t2").unwrap();
        assert_eq!(tokens.authenticate(b"t1"), Some("a"));
        assert_eq!(tokens.authenticate(b"t2"), Some("b"));
    }
}
