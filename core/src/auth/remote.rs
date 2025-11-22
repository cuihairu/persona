use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{PersonaError, Result};

/// Minimal SRP-like parameters used to negotiate a remote authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrpParameters {
    /// Large safe prime (hex-encoded). In a real SRP flow this would be RFC 5054 primes.
    pub prime: String,
    /// Generator value.
    pub generator: u32,
    /// Server-supplied salt (hex-encoded).
    pub salt: String,
}

/// Public values exchanged during the SRP-like handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrpHandshake {
    /// Public ephemeral from the client (e.g., `A` in SRP).
    pub client_public: String,
    /// Public ephemeral from the server (e.g., `B` in SRP).
    pub server_public: String,
}

/// Proofs that bind the session key to prevent MITM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrpProof {
    /// Client proof (e.g., `M1`).
    pub client_proof: String,
    /// Server proof (e.g., `M2`).
    pub server_proof: String,
}

/// Remote auth contract used by the server layer. This is intentionally protocol-agnostic enough
/// to stub locally while remaining compatible with real SRP implementations later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAuthChallenge {
    pub user_id: Uuid,
    pub params: SrpParameters,
    pub handshake: SrpHandshake,
}

/// Result of a remote auth attempt, including a session key fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAuthResult {
    pub user_id: Uuid,
    pub session_key_fingerprint: String,
    pub proof: SrpProof,
}

/// Trait that server-side auth backends should implement. The core crate provides a pure-Rust
/// placeholder so clients/CLIs can compile without talking to a real server.
pub trait RemoteAuthProvider: Send + Sync {
    /// Start a remote authentication flow. The server returns parameters and its public value.
    fn begin(&self, username: &str) -> Result<RemoteAuthChallenge>;
    /// Verify the client proof and return the server proof plus a derived session fingerprint.
    fn finalize(
        &self,
        challenge: &RemoteAuthChallenge,
        client_proof: &str,
    ) -> Result<RemoteAuthResult>;
}

/// No-op SRP-like provider that simulates the handshake locally. It does NOT provide
/// cryptographic guarantees; it is only meant for offline testing and UI wiring.
pub struct MockRemoteAuthProvider;

impl RemoteAuthProvider for MockRemoteAuthProvider {
    fn begin(&self, _username: &str) -> Result<RemoteAuthChallenge> {
        Ok(RemoteAuthChallenge {
            user_id: Uuid::new_v4(),
            params: SrpParameters {
                prime: "FF".to_string(),
                generator: 2,
                salt: "00".to_string(),
            },
            handshake: SrpHandshake {
                client_public: "client_pub_placeholder".to_string(),
                server_public: "server_pub_placeholder".to_string(),
            },
        })
    }

    fn finalize(
        &self,
        challenge: &RemoteAuthChallenge,
        client_proof: &str,
    ) -> Result<RemoteAuthResult> {
        if client_proof.is_empty() {
            return Err(
                PersonaError::AuthenticationFailed("empty client proof".to_string()).into(),
            );
        }

        Ok(RemoteAuthResult {
            user_id: challenge.user_id,
            session_key_fingerprint: "mock_session_fingerprint".to_string(),
            proof: SrpProof {
                client_proof: client_proof.to_string(),
                server_proof: "server_proof_placeholder".to_string(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_provider_round_trip() {
        let provider = MockRemoteAuthProvider;
        let challenge = provider.begin("user@example.com").unwrap();
        let result = provider.finalize(&challenge, "client_proof").unwrap();
        assert_eq!(result.user_id, challenge.user_id);
        assert_eq!(result.proof.client_proof, "client_proof");
        assert_eq!(result.proof.server_proof, "server_proof_placeholder");
        assert_eq!(result.session_key_fingerprint, "mock_session_fingerprint");
    }

    #[test]
    fn finalize_requires_proof() {
        let provider = MockRemoteAuthProvider;
        let challenge = provider.begin("user").unwrap();
        let err = provider.finalize(&challenge, "").unwrap_err();
        assert!(err.to_string().contains("empty client proof"));
    }
}
