//! 统一授权入口（架构校正批1）：动作词汇、主体/资源/上下文与纯策略
//! 裁决。[`authorize`] 是唯一的策略裁决点——此前分散在四处（core 敏感
//! 操作门、Connect token scope 过滤、SSH Agent 签名策略、CLI 导出确认）
//! 的授权判定，现在都从这里取裁决，再各自映射到既有可观察行为（错误
//! 变体 / 空·None 的 404 形 / failure 包 / 取消提示）。
//!
//! 边界（不放松任何现有机制）：
//! - 状态性门禁不进纯函数——会话锁、自动锁、敏感重认证仍由
//!   `ensure_sensitive_operation_allowed` 把守；token 吊销与查表校验仍在
//!   service 层；主机规则/频率/确认计数仍在 agent 的 `PolicyEnforcer`。
//!   本模块只回答「该主体能否对该资源做该动作，或是否需要交互履约」。
//! - [`AuthzDecision::InteractionRequired`] 表示策略允许但需调用边履约
//!   （CLI 确认、桌面对话框、agent 审批/生物识别）；履约完成前视同未
//!   授权。非交互上下文直接拒绝（fail-closed），不产生「等一个永远不
//!   来的确认」。
//! - 动词模型统一 read/use/export/sign：Connect token 目前只能被授予
//!   `read`（创建期 `validate` 强制，见 `ConnectTokenScope::validate`），
//!   其余动词对 token 一律拒绝；agent 密钥唯一能力是签名；本地会话的
//!   导出永远要求显式确认。

use crate::connect::token::{ConnectTokenScope, ConnectVerb};
use crate::models::CredentialType;
use uuid::Uuid;

/// 授权动作。`Read` 读元数据/数据，`Use` 在本库内使用凭据（解密展示、
/// 签名断言），`Export` 导出秘密本体（离开库边界），`Sign` 用密钥对外
/// 签名（SSH agent 数据面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzAction {
    Read,
    Use,
    Export,
    Sign,
}

impl AuthzAction {
    /// Connect verb 折算：`read` 是目前唯一可授予 token 的动词；
    /// use/export/sign 不是 Connect 动词（无对应端点）。
    pub fn connect_verb(self) -> Option<ConnectVerb> {
        match self {
            Self::Read => Some(ConnectVerb::Read),
            Self::Use | Self::Export | Self::Sign => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Use => "use",
            Self::Export => "export",
            Self::Sign => "sign",
        }
    }
}

/// 授权主体。`LocalSession` = 本机已认证会话（状态门禁在 service 层）；
/// `ConnectToken` = 浏览器扩展自动化 token（scope 三维随行）；`AgentKey`
/// = SSH agent 持有的签名密钥。
#[derive(Debug, Clone)]
pub enum AuthzPrincipal {
    LocalSession,
    ConnectToken {
        scope: ConnectTokenScope,
    },
    AgentKey {
        credential_id: Uuid,
        identity_id: Uuid,
    },
}

/// 被访问资源。
#[derive(Debug, Clone)]
pub enum AuthzResource {
    /// vault 级（列表、元数据、管理面）。
    Vault,
    /// 某身份本体。
    Identity { id: Uuid },
    /// 某身份下的凭据条目。
    Credential {
        identity_id: Uuid,
        credential_type: CredentialType,
    },
    /// SSH agent 持有的签名密钥。
    SshKey { credential_id: Uuid },
}

/// 授权上下文：调用来源与交互能力。`interactive = false` 时任何
/// `InteractionRequired` 判定折叠为拒绝（无履约边可用）。
#[derive(Debug, Clone, Copy)]
pub struct AuthzContext {
    pub origin: &'static str,
    pub interactive: bool,
}

impl AuthzContext {
    /// 本机入口（CLI/桌面）。
    pub const LOCAL: Self = Self {
        origin: "local",
        interactive: true,
    };
    /// Connect 自动化端点（无人值守，永不交互）。
    pub const CONNECT: Self = Self {
        origin: "connect",
        interactive: false,
    };
    /// SSH agent（交互经审批处理器/生物识别，非本判定层职责）。
    pub const AGENT: Self = Self {
        origin: "ssh-agent",
        interactive: false,
    };
}

/// 裁决结果。`Allowed` 放行；`InteractionRequired` 需调用边履约（确认框
/// /生物识别），未履约视同未授权；`Denied` 一律拒绝。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    Allowed,
    InteractionRequired { reason: String },
    Denied { reason: String },
}

impl AuthzDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// 唯一策略裁决点。
pub fn authorize(
    principal: &AuthzPrincipal,
    resource: &AuthzResource,
    action: AuthzAction,
    ctx: &AuthzContext,
) -> AuthzDecision {
    match principal {
        AuthzPrincipal::LocalSession => authorize_local(resource, action, ctx),
        AuthzPrincipal::ConnectToken { scope } => authorize_token(scope, resource, action),
        AuthzPrincipal::AgentKey { .. } => authorize_agent_key(principal, resource, action, ctx),
    }
}

/// 本地会话策略：读/用/签名放行（状态性门禁由 service 层把守）；导出
/// 永远要求调用边显式确认——非交互上下文直接拒绝。
fn authorize_local(
    resource: &AuthzResource,
    action: AuthzAction,
    ctx: &AuthzContext,
) -> AuthzDecision {
    match action {
        AuthzAction::Read | AuthzAction::Use | AuthzAction::Sign => AuthzDecision::Allowed,
        AuthzAction::Export => {
            let reason = format!(
                "export of {} requires explicit user confirmation",
                resource_label(resource)
            );
            if ctx.interactive {
                AuthzDecision::InteractionRequired { reason }
            } else {
                AuthzDecision::Denied { reason }
            }
        }
    }
}

/// Connect token 策略：动词集折算（非 `read` 一律拒绝）+ scope 三维
/// （身份 × 类型 × 动词）。scope 外资源同形拒绝，端点层映射 404 形。
fn authorize_token(
    scope: &ConnectTokenScope,
    resource: &AuthzResource,
    action: AuthzAction,
) -> AuthzDecision {
    let Some(verb) = action.connect_verb() else {
        return AuthzDecision::Denied {
            reason: format!(
                "verb '{}' is not grantable to connect tokens",
                action.label()
            ),
        };
    };
    if !scope.allows_verb(verb) {
        return AuthzDecision::Denied {
            reason: format!("token scope does not grant '{}'", action.label()),
        };
    }
    match resource {
        AuthzResource::Vault => AuthzDecision::Allowed,
        AuthzResource::Identity { id } => {
            if scope.allows_identity(id) {
                AuthzDecision::Allowed
            } else {
                AuthzDecision::Denied {
                    reason: "identity outside token scope".to_string(),
                }
            }
        }
        AuthzResource::Credential {
            identity_id,
            credential_type,
        } => {
            if scope.allows_identity(identity_id) && scope.allows_credential_type(credential_type) {
                AuthzDecision::Allowed
            } else {
                AuthzDecision::Denied {
                    reason: "credential outside token scope".to_string(),
                }
            }
        }
        // token 永远碰不到 agent 密钥（跨上下文隔离）。
        AuthzResource::SshKey { .. } => AuthzDecision::Denied {
            reason: "connect tokens cannot access agent keys".to_string(),
        },
    }
}

/// Agent 密钥策略：唯一能力是对自己的密钥签名（主机规则/频率/确认计数
/// 等条件策略由 agent 的 `PolicyEnforcer` 在机制层把守）；密钥材料不经
/// agent 读取或导出。
fn authorize_agent_key(
    principal: &AuthzPrincipal,
    resource: &AuthzResource,
    action: AuthzAction,
    ctx: &AuthzContext,
) -> AuthzDecision {
    let AuthzPrincipal::AgentKey { credential_id, .. } = principal else {
        return AuthzDecision::Denied {
            reason: "internal: non-agent principal".to_string(),
        };
    };
    match (resource, action) {
        (
            AuthzResource::SshKey {
                credential_id: target,
            },
            AuthzAction::Sign,
        ) => {
            if target == credential_id {
                AuthzDecision::Allowed
            } else {
                AuthzDecision::Denied {
                    reason: "sign request targets a different key".to_string(),
                }
            }
        }
        (_, AuthzAction::Export) => {
            let reason = "agent key export requires explicit user confirmation".to_string();
            if ctx.interactive {
                AuthzDecision::InteractionRequired { reason }
            } else {
                AuthzDecision::Denied { reason }
            }
        }
        _ => AuthzDecision::Denied {
            reason: "agent keys only support signing".to_string(),
        },
    }
}

fn resource_label(resource: &AuthzResource) -> &'static str {
    match resource {
        AuthzResource::Vault => "the vault",
        AuthzResource::Identity { .. } => "an identity",
        AuthzResource::Credential { .. } => "credential data",
        AuthzResource::SshKey { .. } => "an agent key",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::token::ConnectVerb;

    fn read_scope() -> ConnectTokenScope {
        ConnectTokenScope {
            identities: vec![],
            item_types: vec![],
            verbs: vec![ConnectVerb::Read],
        }
    }

    fn cred(identity_id: Uuid) -> AuthzResource {
        AuthzResource::Credential {
            identity_id,
            credential_type: CredentialType::Password,
        }
    }

    /// 拒绝未授权：无 read 动词的 token、token 请求非 Connect 动词、
    /// agent 密钥请求非签名动作，一律 Denied。
    #[test]
    fn deny_unauthorized_actions() {
        let no_read = ConnectTokenScope {
            verbs: vec![],
            ..read_scope()
        };
        let d = authorize(
            &AuthzPrincipal::ConnectToken { scope: no_read },
            &AuthzResource::Vault,
            AuthzAction::Read,
            &AuthzContext::CONNECT,
        );
        assert!(matches!(d, AuthzDecision::Denied { .. }));

        // token 请求 use/export/sign：Connect 动词集外，无论 scope 如何。
        for action in [AuthzAction::Use, AuthzAction::Export, AuthzAction::Sign] {
            let d = authorize(
                &AuthzPrincipal::ConnectToken {
                    scope: read_scope(),
                },
                &cred(Uuid::new_v4()),
                action,
                &AuthzContext::CONNECT,
            );
            assert!(
                matches!(d, AuthzDecision::Denied { .. }),
                "{action:?} must be denied for tokens"
            );
        }

        // agent 密钥只能签名；读/用一律拒绝。
        let key = AuthzPrincipal::AgentKey {
            credential_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
        };
        for action in [AuthzAction::Read, AuthzAction::Use] {
            let d = authorize(
                &key,
                &AuthzResource::SshKey {
                    credential_id: Uuid::new_v4(),
                },
                action,
                &AuthzContext::AGENT,
            );
            assert!(matches!(d, AuthzDecision::Denied { .. }));
        }
    }

    /// 跨上下文访问：token 只看得见 scope 内身份/类型；agent 密钥只对
    /// 自己签名；token 与 agent 密钥互不可见。
    #[test]
    fn cross_context_access_is_denied() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let scoped = ConnectTokenScope {
            identities: vec![id_a],
            ..read_scope()
        };
        let principal = AuthzPrincipal::ConnectToken { scope: scoped };

        // A 内可见，B 内拒绝。
        assert!(authorize(
            &principal,
            &cred(id_a),
            AuthzAction::Read,
            &AuthzContext::CONNECT
        )
        .is_allowed());
        assert!(matches!(
            authorize(
                &principal,
                &cred(id_b),
                AuthzAction::Read,
                &AuthzContext::CONNECT
            ),
            AuthzDecision::Denied { .. }
        ));
        // 身份本体同样按 scope 隔离。
        assert!(matches!(
            authorize(
                &principal,
                &AuthzResource::Identity { id: id_b },
                AuthzAction::Read,
                &AuthzContext::CONNECT
            ),
            AuthzDecision::Denied { .. }
        ));
        // scope 外敏感类型（SSH key 由排除法永不可见，即使空 item_types）。
        let ssh_cred = AuthzResource::Credential {
            identity_id: id_a,
            credential_type: CredentialType::SshKey,
        };
        assert!(matches!(
            authorize(
                &principal,
                &ssh_cred,
                AuthzAction::Read,
                &AuthzContext::CONNECT
            ),
            AuthzDecision::Denied { .. }
        ));
        // token 摸 agent 密钥：跨上下文拒绝。
        assert!(matches!(
            authorize(
                &principal,
                &AuthzResource::SshKey {
                    credential_id: Uuid::new_v4()
                },
                AuthzAction::Read,
                &AuthzContext::CONNECT
            ),
            AuthzDecision::Denied { .. }
        ));

        // agent 密钥对别人的密钥签名：密钥不匹配拒绝。
        let key = AuthzPrincipal::AgentKey {
            credential_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
        };
        assert!(matches!(
            authorize(
                &key,
                &AuthzResource::SshKey {
                    credential_id: Uuid::new_v4()
                },
                AuthzAction::Sign,
                &AuthzContext::AGENT
            ),
            AuthzDecision::Denied { .. }
        ));
        // 自己的密钥签名：放行（条件策略在 PolicyEnforcer）。
        let own = AuthzResource::SshKey {
            credential_id: match key {
                AuthzPrincipal::AgentKey { credential_id, .. } => credential_id,
                _ => unreachable!(),
            },
        };
        assert!(authorize(&key, &own, AuthzAction::Sign, &AuthzContext::AGENT).is_allowed());
    }

    /// 敏感导出：本地会话导出永远要求交互履约；非交互上下文（无人值守
    /// 的调用边）直接拒绝，不会「等一个永远不来的确认」。
    #[test]
    fn sensitive_export_requires_interaction() {
        let d = authorize(
            &AuthzPrincipal::LocalSession,
            &AuthzResource::Vault,
            AuthzAction::Export,
            &AuthzContext::LOCAL,
        );
        assert!(matches!(d, AuthzDecision::InteractionRequired { .. }));

        let d = authorize(
            &AuthzPrincipal::LocalSession,
            &AuthzResource::Vault,
            AuthzAction::Export,
            &AuthzContext::CONNECT,
        );
        assert!(matches!(d, AuthzDecision::Denied { .. }));

        // agent 密钥导出同理（当前无导出路径，此为未来路径的策略边界）。
        let key = AuthzPrincipal::AgentKey {
            credential_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
        };
        let d = authorize(
            &key,
            &AuthzResource::SshKey {
                credential_id: Uuid::new_v4(),
            },
            AuthzAction::Export,
            &AuthzContext::AGENT,
        );
        assert!(matches!(d, AuthzDecision::Denied { .. }));

        // 读/用/签名在交互与非交互上下文一致放行（状态门禁另算）。
        for ctx in [&AuthzContext::LOCAL, &AuthzContext::CONNECT] {
            assert!(authorize(
                &AuthzPrincipal::LocalSession,
                &cred(Uuid::new_v4()),
                AuthzAction::Read,
                ctx
            )
            .is_allowed());
            assert!(authorize(
                &AuthzPrincipal::LocalSession,
                &cred(Uuid::new_v4()),
                AuthzAction::Use,
                ctx
            )
            .is_allowed());
        }
    }

    /// 全 scope token 的可见性 = 现行 allows_* 语义：空 = 全部（合法类型
    /// 内），vault 级读放行。
    #[test]
    fn token_read_matrix_matches_scope_semantics() {
        let principal = AuthzPrincipal::ConnectToken {
            scope: read_scope(),
        };
        assert!(authorize(
            &principal,
            &AuthzResource::Vault,
            AuthzAction::Read,
            &AuthzContext::CONNECT
        )
        .is_allowed());

        // 合法类型全可见。
        for t in [
            CredentialType::Password,
            CredentialType::ApiKey,
            CredentialType::TwoFactor,
        ] {
            let r = AuthzResource::Credential {
                identity_id: Uuid::new_v4(),
                credential_type: t,
            };
            assert!(
                authorize(&principal, &r, AuthzAction::Read, &AuthzContext::CONNECT).is_allowed()
            );
        }
        // 非法类型（custom/wallet）永不可见。
        for t in [
            CredentialType::CryptoWallet,
            CredentialType::Custom("x".into()),
        ] {
            let r = AuthzResource::Credential {
                identity_id: Uuid::new_v4(),
                credential_type: t,
            };
            assert!(matches!(
                authorize(&principal, &r, AuthzAction::Read, &AuthzContext::CONNECT),
                AuthzDecision::Denied { .. }
            ));
        }
    }
}
