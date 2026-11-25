//! Unified authorization entry point (architecture correction batch 1): the
//! action vocabulary, principal/resource/context, and pure policy decisions.
//! [`authorize`] is the single policy decision point — authorization checks
//! previously scattered across four sites (the core sensitive-operation gate,
//! Connect token scope filtering, SSH Agent signing policy, CLI export
//! confirmation) now take their ruling from here and each map it onto the
//! existing observable behavior (error variants / the 404 shape of
//! empty-None / failure packages / cancel prompts).
//!
//! Boundaries (no existing mechanism is loosened):
//! - Stateful gates stay out of the pure functions — session lock, auto-lock,
//!   and sensitive re-authentication are still guarded by
//!   `ensure_sensitive_operation_allowed`; token revocation and table lookups
//!   remain in the service layer; host rules / rate limits / confirmation
//!   counts remain in the agent's `PolicyEnforcer`. This module only answers
//!   "may this principal perform this action on this resource, or is
//!   interactive fulfillment required?"
//! - [`AuthzDecision::InteractionRequired`] means the policy allows but the
//!   calling edge must fulfill it (CLI confirmation, desktop dialog, agent
//!   approval/biometrics); until fulfillment completes it counts as
//!   unauthorized. Non-interactive contexts are refused outright
//!   (fail-closed) and never produce "waiting for a confirmation that will
//!   never come".
//! - The verb model is unified as read/use/export/sign: a Connect token can be
//!   granted `read`/`use` (the `validate` at creation time restricts the
//!   subset, see `ConnectTokenScope::validate`), export/sign are always
//!   refused for tokens (not Connect verbs); an agent key's only capability is
//!   signing; a local session's export always requires explicit confirmation.

use crate::connect::token::{ConnectTokenScope, ConnectVerb};
use crate::models::CredentialType;
use crate::PersonaError;
use uuid::Uuid;

/// Authorization action. `Read` reads metadata/data, `Use` uses credentials
/// within this vault (decrypt-and-reveal, signing assertions), `Export` moves
/// the secret itself out (crosses the vault boundary), `Sign` signs external
/// data with a key (SSH agent data plane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzAction {
    Read,
    Use,
    Export,
    Sign,
}

impl AuthzAction {
    /// Connect verb conversion: `read`/`use` can be granted to tokens (`use`
    /// serves the signing/code-output endpoints, export is never granted);
    /// export/sign are not Connect verbs (no corresponding endpoint).
    pub fn connect_verb(self) -> Option<ConnectVerb> {
        match self {
            Self::Read => Some(ConnectVerb::Read),
            Self::Use => Some(ConnectVerb::Use),
            Self::Export | Self::Sign => None,
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

/// Authorization principal. `LocalSession` = an authenticated local session
/// (stateful gating lives in the service layer); `ConnectToken` = the browser
/// extension automation token (carries its three-dimensional scope);
/// `AgentKey` = a signing key held by the SSH agent.
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

/// The resource being accessed.
#[derive(Debug, Clone)]
pub enum AuthzResource {
    /// Vault level (listing, metadata, management surface).
    Vault,
    /// A specific identity.
    Identity { id: Uuid },
    /// A credential entry under a specific identity.
    Credential {
        identity_id: Uuid,
        credential_type: CredentialType,
    },
    /// A signing key held by the SSH agent.
    SshKey { credential_id: Uuid },
}

/// Authorization context: the calling origin and interactivity. When
/// `interactive = false`, any `InteractionRequired` ruling collapses to a
/// denial (no fulfillment edge is available).
#[derive(Debug, Clone, Copy)]
pub struct AuthzContext {
    pub origin: &'static str,
    pub interactive: bool,
}

impl AuthzContext {
    /// Local entry (CLI/desktop).
    pub const LOCAL: Self = Self {
        origin: "local",
        interactive: true,
    };
    /// Connect automation endpoint (unattended, never interactive).
    pub const CONNECT: Self = Self {
        origin: "connect",
        interactive: false,
    };
    /// SSH agent (interactivity goes through the approval handler / biometrics, not this decision layer's concern).
    pub const AGENT: Self = Self {
        origin: "ssh-agent",
        interactive: false,
    };
}

/// The ruling. `Allowed` lets it through; `InteractionRequired` requires the
/// calling edge to fulfill it (confirmation dialog / biometrics) and counts as
/// unauthorized until fulfilled; `Denied` refuses outright.
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

/// Convert a ruling into a domain error: `Denied` →
/// [`PersonaError::Forbidden`] (identity already established but the action is
/// out of scope, distinct from authentication failure); `Allowed` /
/// `InteractionRequired` pass through — the latter is fulfilled at the calling
/// edge (confirmation dialog), and fulfillment failure is reported by the
/// caller, not converted here.
pub fn denied_error(decision: &AuthzDecision) -> Option<PersonaError> {
    match decision {
        AuthzDecision::Denied { reason } => Some(PersonaError::Forbidden(format!(
            "operation denied: {reason}"
        ))),
        _ => None,
    }
}

/// The single policy decision point.
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

/// Local session policy: read/use/sign are allowed (stateful gating is
/// guarded by the service layer); export always requires explicit confirmation
/// at the calling edge — non-interactive contexts are refused outright.
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

/// Connect token policy: verb set conversion (anything not `read` is refused)
/// plus the three-dimensional scope (identity × type × verb). Out-of-scope
/// resources are refused in the same shape, which the endpoint layer maps to a
/// 404 form.
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
        // Tokens can never touch agent keys (cross-context isolation).
        AuthzResource::SshKey { .. } => AuthzDecision::Denied {
            reason: "connect tokens cannot access agent keys".to_string(),
        },
    }
}

/// Agent key policy: the only capability is signing with its own key
/// (conditional policy such as host rules / rate limits / confirmation counts
/// is guarded at the mechanism layer by the agent's `PolicyEnforcer`); key
/// material is never read or exported through the agent.
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

    /// Deny unauthorized: a token without the read verb, a token requesting a
    /// non-Connect verb, and an agent key requesting a non-signing action are
    /// all Denied.
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

        // Token requests use/export/sign: the read-only scope did not grant
        // use (export/sign are not Connect verbs in the first place, so no
        // scope could ever grant them).
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

        // Agent keys can only sign; read/use are refused outright.
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

    /// Cross-context access: a token only sees identities/types within scope;
    /// an agent key only signs its own key; tokens and agent keys are mutually
    /// invisible.
    #[test]
    fn cross_context_access_is_denied() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let scoped = ConnectTokenScope {
            identities: vec![id_a],
            ..read_scope()
        };
        let principal = AuthzPrincipal::ConnectToken { scope: scoped };

        // Visible inside A, refused inside B.
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
        // Identity objects are isolated by scope too.
        assert!(matches!(
            authorize(
                &principal,
                &AuthzResource::Identity { id: id_b },
                AuthzAction::Read,
                &AuthzContext::CONNECT
            ),
            AuthzDecision::Denied { .. }
        ));
        // Sensitive type outside scope (SSH keys are never visible by exclusion, even with empty item_types).
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
        // Token touching an agent key: refused as cross-context.
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

        // Agent key signing someone else's key: refused on key mismatch.
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
        // Signing its own key: allowed (conditional policy lives in the PolicyEnforcer).
        let own = AuthzResource::SshKey {
            credential_id: match key {
                AuthzPrincipal::AgentKey { credential_id, .. } => credential_id,
                _ => unreachable!(),
            },
        };
        assert!(authorize(&key, &own, AuthzAction::Sign, &AuthzContext::AGENT).is_allowed());
    }

    /// Sensitive export: a local session's export always requires interactive
    /// fulfillment; a non-interactive context (an unattended calling edge) is
    /// refused outright and never "waits for a confirmation that will never
    /// come".
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

        // Agent key export follows the same rule (there is no export path today; this is the policy boundary for a future path).
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

        // Read/use/sign are allowed identically in interactive and non-interactive contexts (stateful gating is a separate matter).
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

    /// Full-scope token visibility = the current allows_* semantics: empty =
    /// all (within legal types), vault-level read allowed.
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

        // All legal types fully visible.
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
        // Illegal types (custom/wallet) are never visible.
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

    /// A token with the use verb (architecture correction batch 2):
    /// signing/code-output operations can be granted, while export and read
    /// paths outside signing are decided by scope; a pure-use token cannot
    /// read the data plane.
    #[test]
    fn token_use_verb_grants_use_but_never_export() {
        let id = Uuid::new_v4();
        let scope = ConnectTokenScope {
            identities: vec![id],
            item_types: vec![],
            verbs: vec![ConnectVerb::Read, ConnectVerb::Use],
        };
        let principal = AuthzPrincipal::ConnectToken { scope };

        // use is allowed on in-scope credentials; export/sign are always refused (not Connect verbs).
        assert!(authorize(
            &principal,
            &cred(id),
            AuthzAction::Use,
            &AuthzContext::CONNECT
        )
        .is_allowed());
        for action in [AuthzAction::Export, AuthzAction::Sign] {
            assert!(matches!(
                authorize(&principal, &cred(id), action, &AuthzContext::CONNECT),
                AuthzDecision::Denied { .. }
            ));
        }

        // Pure-use token: cannot read (read was not granted).
        let use_only = AuthzPrincipal::ConnectToken {
            scope: ConnectTokenScope {
                identities: vec![],
                item_types: vec![],
                verbs: vec![ConnectVerb::Use],
            },
        };
        assert!(matches!(
            authorize(
                &use_only,
                &cred(Uuid::new_v4()),
                AuthzAction::Read,
                &AuthzContext::CONNECT
            ),
            AuthzDecision::Denied { .. }
        ));
        assert!(authorize(
            &use_only,
            &cred(Uuid::new_v4()),
            AuthzAction::Use,
            &AuthzContext::CONNECT
        )
        .is_allowed());
    }

    /// Using and exporting an SSH private key are different actions with
    /// different rulings (acceptance criteria): an agent key's only capability
    /// is signing with its own key (produces a signature, never returns
    /// material); export is refused in an unattended agent context, and only
    /// interactive local sessions can carry it, with fulfillment required;
    /// key material is never visible to tokens.
    #[test]
    fn ssh_key_sign_and_export_are_different_decisions() {
        let credential_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();
        let key = AuthzPrincipal::AgentKey {
            credential_id,
            identity_id,
        };
        let own = AuthzResource::SshKey { credential_id };

        // Use (signing) allowed.
        assert!(authorize(&key, &own, AuthzAction::Sign, &AuthzContext::AGENT).is_allowed());
        // Export refused in an unattended agent context (fail-closed).
        assert!(matches!(
            authorize(&key, &own, AuthzAction::Export, &AuthzContext::AGENT),
            AuthzDecision::Denied { .. }
        ));
        // The same export action goes through in an interactive local session, but requires fulfillment at the calling edge.
        assert!(matches!(
            authorize(
                &AuthzPrincipal::LocalSession,
                &AuthzResource::Credential {
                    identity_id,
                    credential_type: CredentialType::SshKey,
                },
                AuthzAction::Export,
                &AuthzContext::LOCAL,
            ),
            AuthzDecision::InteractionRequired { .. }
        ));
        // Key material is never visible to tokens (even with the full read+use verb set).
        let token = AuthzPrincipal::ConnectToken {
            scope: ConnectTokenScope {
                identities: vec![],
                item_types: vec![],
                verbs: vec![ConnectVerb::Read, ConnectVerb::Use],
            },
        };
        for action in [AuthzAction::Read, AuthzAction::Sign, AuthzAction::Export] {
            assert!(
                matches!(
                    authorize(&token, &own, action, &AuthzContext::CONNECT),
                    AuthzDecision::Denied { .. }
                ),
                "{action:?} 必须对密钥材料拒绝"
            );
        }
    }

    /// Ruling -> error conversion: only `Denied` produces `Forbidden` (with
    /// the original refusal reason); `Allowed` and `InteractionRequired`
    /// produce no error — the latter is fulfilled at the calling edge.
    #[test]
    fn denied_error_maps_only_denied() {
        assert!(denied_error(&AuthzDecision::Allowed).is_none());
        assert!(denied_error(&AuthzDecision::InteractionRequired {
            reason: "needs confirmation".into()
        })
        .is_none());

        let err = denied_error(&AuthzDecision::Denied {
            reason: "verb 'export' is not grantable to connect tokens".into(),
        })
        .unwrap();
        match err {
            PersonaError::Forbidden(msg) => {
                assert!(msg.starts_with("operation denied: "), "{msg}");
                assert!(msg.contains("verb 'export'"), "{msg}");
            }
            other => panic!("Denied must map to Forbidden, got {other:?}"),
        }
    }
}
