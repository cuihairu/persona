//! Connect local-automation tokens (phase 1 of CONNECT_AUTOMATION_DESIGN;
//! migration 015).
//!
//! Responsibility boundary: this module only holds the scope types, the
//! token generation/hashing pure functions, and the decision logic; table
//! access lives in [`crate::storage::ConnectTokenRepository`], and the
//! unlocked-state orchestration (creation/authentication/data-plane scope
//! filtering) lives in the `connect_*` methods of
//! [`crate::PersonaService`]. The HTTP surface (the three Host/Origin
//! lines of defense, rate limits, response envelope) is the job of the
//! host layer (desktop axum / CLI serve) and is not part of this module —
//! framework-agnostic.
//!
//! Security invariants (locked in by service-layer tests):
//! - the plaintext token is returned exactly once, at creation time; the
//!   database keeps only the SHA-256 hash + fingerprint;
//! - invalid/revoked/nonexistent tokens all yield `None` (making 404/403
//!   indistinguishable is enforced by the endpoint layer);
//! - scopes always exclude sensitive types (SSH key / crypto wallet /
//!   custom), and the verbs start with only `read`.

pub mod token;

pub use token::{
    fingerprint_from_hash, generate_token, hash_token, ConnectItemType, ConnectTokenRow,
    ConnectTokenScope, ConnectVerb, TOKEN_PREFIX,
};
