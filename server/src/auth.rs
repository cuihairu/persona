//! /api 认证：单 Bearer 令牌，fail-closed。
//!
//! 未配置 `PERSONA_SERVER_TOKEN` 时 /api 全部 503（禁用优先于认证失败，
//! 避免暴露任何可探测差异）；已配置时要求 `Authorization: Bearer <token>`，
//! 比较用常量时间实现。`/`、`/health`、`/metrics` 免认证。

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::api::ApiError;
use crate::state::AppState;

pub async fn require_bearer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(expected) = state.auth_token.as_deref() else {
        return ApiError::disabled().into_response();
    };
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(extract_bearer);
    let authorized =
        provided.is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()));
    if !authorized {
        return ApiError::unauthorized().into_response();
    }
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
    use super::constant_time_eq;

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
}
