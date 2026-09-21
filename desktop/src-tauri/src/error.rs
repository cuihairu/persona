//! 把 persona-core 的错误映射为机器可读错误码，供前端分流处理。

use persona_core::PersonaError;

/// 错误码：敏感操作需要重新认证（前端应弹出 ReauthModal）
pub const CODE_REAUTH_REQUIRED: &str = "REAUTH_REQUIRED";
/// 错误码：服务已锁定（前端应回到解锁屏）
pub const CODE_SERVICE_LOCKED: &str = "SERVICE_LOCKED";
/// 错误码：主密码按策略需要轮换（前端应引导改密流程）
pub const CODE_PASSWORD_CHANGE_REQUIRED: &str = "PASSWORD_CHANGE_REQUIRED";
/// 错误码：biometric 托管条目已失效并被删除（未配置/陈旧自删，前端应
/// 刷新 status 隐藏指纹按钮、提示改用主密码登录）
pub const CODE_BIOMETRIC_RESET: &str = "BIOMETRIC_RESET";

/// 将任意 service 错误映射为 `(error_code, message)`。
///
/// `error_code` 为 None 表示没有专用错误码，前端按通用错误提示即可。
pub fn map_persona_error(err: &anyhow::Error) -> (Option<String>, String) {
    // 优先按 PersonaError 变体精确匹配
    for cause in err.chain() {
        if let Some(pe) = cause.downcast_ref::<PersonaError>() {
            match pe {
                PersonaError::ReauthRequired(_) => {
                    return (Some(CODE_REAUTH_REQUIRED.to_string()), pe.to_string());
                }
                PersonaError::AuthenticationFailed(msg)
                    if msg.contains("locked") || msg.contains("Service is locked") =>
                {
                    return (Some(CODE_SERVICE_LOCKED.to_string()), pe.to_string());
                }
                _ => {}
            }
        }
    }

    // 回退：按消息文本识别（覆盖未被 PersonaError 包装的场景）
    let msg = err.to_string();
    if msg.contains("Re-authentication required") {
        return (Some(CODE_REAUTH_REQUIRED.to_string()), msg);
    }
    if msg.contains("Service is locked") || msg.contains("Session is auto-locked") {
        return (Some(CODE_SERVICE_LOCKED.to_string()), msg);
    }

    (None, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reauth_required_variant_maps_to_code() {
        let err: anyhow::Error = PersonaError::ReauthRequired("sensitive op".to_string()).into();
        let (code, msg) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_REAUTH_REQUIRED));
        assert!(msg.contains("Re-authentication required"));
    }

    #[test]
    fn locked_messages_map_to_service_locked() {
        let err: anyhow::Error =
            PersonaError::AuthenticationFailed("Service is locked".into()).into();
        let (code, _) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_SERVICE_LOCKED));
    }

    #[test]
    fn reauth_message_without_variant_still_detected() {
        let err = anyhow::anyhow!("Re-authentication required for sensitive operation");
        let (code, _) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_REAUTH_REQUIRED));
    }

    #[test]
    fn generic_error_has_no_code() {
        let err = anyhow::anyhow!("boom");
        let (code, msg) = map_persona_error(&err);
        assert!(code.is_none());
        assert_eq!(msg, "boom");
    }
}
