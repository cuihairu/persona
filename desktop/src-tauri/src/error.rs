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
/// 错误码：用户在生物识别弹框点了取消（包裹未被删除，前端应静默回到
/// 解锁屏并保留指纹按钮——不是失败，不要弹错误提示；设计文档 §3.4）
pub const CODE_BIOMETRIC_CANCELLED: &str = "BIOMETRIC_CANCELLED";
/// 错误码：旅行模式进行中（改密等与 sidecar 中 wrapped key 不兼容的
/// 操作被拒；前端应提示先退出旅行模式）
pub const CODE_TRAVEL_MODE_ACTIVE: &str = "TRAVEL_MODE_ACTIVE";
/// 错误码：并发互斥操作冲突（group key 轮换的 epoch 乐观锁未命中，另一台
/// 设备已抢先轮换；前端应提示同步状态已更新、稍后重试轮换）
pub const CODE_CONCURRENT_CONFLICT: &str = "CONCURRENT_CONFLICT";

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
                PersonaError::TravelModeActive(_) => {
                    return (Some(CODE_TRAVEL_MODE_ACTIVE.to_string()), pe.to_string());
                }
                PersonaError::ConcurrentConflict(_) => {
                    return (Some(CODE_CONCURRENT_CONFLICT.to_string()), pe.to_string());
                }
                PersonaError::AuthenticationFailed(msg)
                    if msg.contains("locked") || msg.contains("Service is locked") =>
                {
                    return (Some(CODE_SERVICE_LOCKED.to_string()), pe.to_string());
                }
                // Connect 自动化数据面的锁定语义（core 503 口径）——变体
                // 直映射，不依赖 "Vault is locked" 文本。
                PersonaError::VaultLocked(_) => {
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
    fn vault_locked_variant_maps_to_service_locked_by_type() {
        // "Vault is locked" 不落入任何文本回退——变体直映射必须生效，
        // 且隔着一层 context 也能沿链翻出。
        let err = anyhow::Error::from(PersonaError::VaultLocked("data plane".into()))
            .context("connect request failed");
        let (code, msg) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_SERVICE_LOCKED));
        assert!(msg.contains("Vault is locked"));
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

    #[test]
    fn travel_mode_active_maps_to_code_even_wrapped() {
        // 改密拦截在 core 内部经 thiserror From 链进 anyhow，链条中途
        // 出现 TravelModeActive 也必须被翻出对应码
        let err = anyhow::Error::from(PersonaError::TravelModeActive(
            "exit travel mode first".to_string(),
        ))
        .context("change_master_password failed");
        let (code, msg) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_TRAVEL_MODE_ACTIVE));
        assert!(msg.contains("Travel mode is active"));
    }

    #[test]
    fn concurrent_conflict_maps_to_code_even_wrapped() {
        // 轮换并发互斥：rotate_group_key 经 begin_group_rotation 的 409
        // 映射进 anyhow，中途隔 context 也必须翻出 CONCURRENT_CONFLICT
        let err = anyhow::Error::from(PersonaError::ConcurrentConflict(
            "concurrent group key rotation detected".to_string(),
        ))
        .context("sync_rotate failed");
        let (code, msg) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_CONCURRENT_CONFLICT));
        assert!(msg.contains("Concurrent operation conflict"));
    }
}
