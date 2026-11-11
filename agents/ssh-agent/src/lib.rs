//! Persona SSH Agent daemon
//! - Cross-platform agent (UNIX sockets on Unix, Named Pipes on Windows)
//! - Implements SSH Agent protocol subset:
//!   - request_identities
//!   - sign_request (ed25519 / RSA rsa-sha2-256|512 / ECDSA nistp256)
//! - Loads SSH keys from Persona vault (CredentialType::SshKey): legacy
//!   BASE64 seed entries and imported OpenSSH PEM entries (ed25519/rsa/ecdsa)
//! - Unlocks using master password from env PERSONA_MASTER_PASSWORD (if required)
//! - Advanced policy enforcement: per-host, per-key, time-based restrictions
//!
//! NOTE: This is an early MVP; enhanced policies/approvals in progress.

pub mod approval;
pub mod policy;
pub mod transport;

mod daemon;

pub use approval::{
    fingerprint_for_blob, ApprovalHandler, ApprovalRequest, DenyAllApprovalHandler,
    TtyApprovalHandler,
};
pub use daemon::{run_agent, run_agent_with_approval, run_agent_with_hooks};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use persona_core::{
    BiometricPlatform, BiometricPrompt, BiometricProvider, PersonaError, Repository,
};
use policy::{PolicyEnforcer, SignatureDecision};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use transport::AgentStream;

mod agent;
mod context;
mod keys;
mod protocol;

#[cfg(test)]
use agent::audit_sign_with_digest;
pub use agent::Agent;
use context::is_host_in_known_hosts;
use context::{current_target_host, detect_platform, resolve_persona_db_path};
use keys::{agent_key_from_ssh_data, build_signature_blob};
#[cfg(test)]
use keys::{parse_public_line_to_blob, public_key_algorithm};
pub use keys::{AgentKey, SigningKeyMaterial};
pub use protocol::handle_connection;
use protocol::{failure_packet, read_ssh_string, wrap_packet, write_ssh_string};

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
// env_lock must be held across .await for env var isolation in parallel tests
mod tests;
