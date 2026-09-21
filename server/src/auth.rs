//! /api 认证：命名设备 Bearer 令牌集合，fail-closed。
//!
//! `PERSONA_SERVER_TOKENS="laptop:tok1,phone:tok2"` 配置多设备令牌；
//! 兼容旧 `PERSONA_SERVER_TOKEN`（作为 "default" 设备）。未配置任何令牌
//! 时 /api 全部 503（禁用优先于认证失败，避免暴露任何可探测差异）；
//! 已配置时要求 `Authorization: Bearer <token>`，对全部条目做无早退的
//! 常量时间比较。设备名由命中的令牌推导、客户端不可自报，命中后经
//! request extensions（[`DeviceName`]）传给处理器。`/`、`/health`、
//! `/metrics` 免认证。

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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

pub async fn require_bearer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(tokens) = state.auth.as_deref() else {
        return ApiError::disabled().into_response();
    };
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(extract_bearer);
    let Some(device) = provided.and_then(|token| tokens.authenticate(token.as_bytes())) else {
        return ApiError::unauthorized().into_response();
    };
    let mut req = req;
    req.extensions_mut().insert(DeviceName(device.to_owned()));
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
