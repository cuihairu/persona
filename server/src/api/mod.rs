//! /api 子路由：统一错误形状、请求体守卫与事件端点。

mod events;

use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub use events::{ingest, query};

/// 请求体上限（线上字节）。带 Content-Length 的请求由
/// `payload_size_guard` 预检直接给出确定性 413——这是压缩传输的真实
/// 上限；`DefaultBodyLimit` 对 /events 作用于解压后明文（见
/// [`MAX_DECOMPRESSED_BODY_BYTES`]）。
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// 解压后明文上限（防解压炸弹）。理论最大合法批：500 条 × 逐字段上限
/// ≈ 9.5 MiB，10 MiB 留余量。位于 `RequestDecompressionLayer` 内层的
/// `DefaultBodyLimit` 作用于解压后的 body，同时也兜底 chunked 请求
///（该路径无 Content-Length，线上预检跳过）。
pub const MAX_DECOMPRESSED_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Content-Length 预检：超限直接 413，不读 body、不进认证。
pub async fn payload_size_guard(req: Request, next: Next) -> Response {
    let too_large = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|len| len > MAX_BODY_BYTES);
    if too_large {
        ApiError::payload_too_large().into_response()
    } else {
        next.run(req).await
    }
}

/// 统一错误形状：`{"error":{"code","message","items":[...]}}`。
///
/// 内部 `Box` 保持 `Result<_, ApiError>` 体积小（避免 clippy::result_large_err）。
#[derive(Debug)]
pub struct ApiError(Box<ApiErrorInner>);

#[derive(Debug)]
struct ApiErrorInner {
    status: StatusCode,
    extra_header: Option<(HeaderName, HeaderValue)>,
    body: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    items: Vec<ErrorItem>,
}

/// 批量校验的逐条错误定位。
#[derive(Debug, Serialize)]
pub(crate) struct ErrorItem {
    pub(crate) index: Option<usize>,
    pub(crate) field: String,
    pub(crate) issue: String,
}

impl ErrorItem {
    pub(crate) fn at(index: usize, field: &str, issue: impl Into<String>) -> Self {
        Self {
            index: Some(index),
            field: field.to_owned(),
            issue: issue.into(),
        }
    }

    pub(crate) fn batch(field: &str, issue: impl Into<String>) -> Self {
        Self {
            index: None,
            field: field.to_owned(),
            issue: issue.into(),
        }
    }
}

impl ApiError {
    /// 422：批量校验失败（附逐条 items）。
    pub fn validation(message: impl Into<String>, items: Vec<ErrorItem>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
            message,
            items,
        )
    }

    /// 400/415：JSON 反序列化等请求层错误（沿用 axum rejection 的状态码）。
    pub fn rejection(status: StatusCode, message: impl Into<String>) -> Self {
        Self::new(status, "bad_request", message, Vec::new())
    }

    /// 401：缺/错 Bearer 令牌（附 WWW-Authenticate）。
    pub fn unauthorized() -> Self {
        let mut error = Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
            Vec::new(),
        );
        error.0.extra_header = Some((header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer")));
        error
    }

    /// 503：未配置 PERSONA_SERVER_TOKEN，fail-closed。
    pub fn disabled() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "api_disabled",
            "API is disabled: PERSONA_SERVER_TOKEN is not configured",
            Vec::new(),
        )
    }

    /// 413：请求体超限。
    pub fn payload_too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("request body exceeds {MAX_BODY_BYTES} bytes"),
            Vec::new(),
        )
    }

    /// 404：路由表外（fallback 兜底）。
    pub(crate) fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such route",
            Vec::new(),
        )
    }

    /// 500：内部错误，细节只进日志不外泄。
    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(%error, "internal server error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal server error",
            Vec::new(),
        )
    }

    fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        items: Vec<ErrorItem>,
    ) -> Self {
        Self(Box::new(ApiErrorInner {
            status,
            extra_header: None,
            body: ErrorBody {
                error: ErrorDetail {
                    code,
                    message: message.into(),
                    items,
                },
            },
        }))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let inner = self.0;
        let mut response = (inner.status, axum::Json(inner.body)).into_response();
        if let Some((name, value)) = inner.extra_header {
            response.headers_mut().insert(name, value);
        }
        response
    }
}
