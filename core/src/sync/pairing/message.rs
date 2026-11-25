//! Relay-line messages: the `PairingMessage` enum, base64 wire
//! encoding/decoding, and the invite link `PairingInviteLink` (version prefix +
//! payload encoding/decoding).

use base64::Engine as _;

use crate::{PersonaError, PersonaResult};

use super::guest::{GuestOffer, GuestProof};
use super::host::{HostHandoff, HostOffer};

// ---- Relay wire messages ----

/// Pairing messages shuttled between both sides via the relay mailbox (the
/// inner payload of the mailbox; the relay does not interpret the contents and
/// only ever sees SRP public messages and AEAD ciphertext — zero knowledge).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairingMessage {
    /// guest → host: client ephemeral public (A_pub).
    ClientPublic { client_public: String },
    /// host → guest: server ephemeral public (B_pub).
    ServerOffer { server_public: String },
    /// guest → host: M1 submitted after the fingerprint comparison passes.
    ClientProof { client_proof: String },
    /// host → guest: M2 + the AEAD-wrapped group key (pairing wrap-up, single
    /// delivery).
    Handoff {
        server_proof: String,
        wrapped_group_key: String,
    },
}

pub(super) mod wire {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    pub fn encode(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    pub fn decode(value: &str) -> crate::PersonaResult<Vec<u8>> {
        B64.decode(value)
            .map_err(|e| crate::PersonaError::InvalidInput(format!("非法 base64: {e}")))
    }
}

impl PairingMessage {
    /// Guest step one: assembled from [`GuestOffer`].
    pub fn client_public(offer: &GuestOffer) -> Self {
        Self::ClientPublic {
            client_public: wire::encode(&offer.client_public),
        }
    }

    /// Host reply: assembled from [`HostOffer`].
    pub fn server_offer(offer: &HostOffer) -> Self {
        Self::ServerOffer {
            server_public: wire::encode(&offer.server_public),
        }
    }

    /// Guest step two: assembled from [`GuestProof`].
    pub fn client_proof(proof: &GuestProof) -> Self {
        Self::ClientProof {
            client_proof: wire::encode(&proof.client_proof),
        }
    }

    /// Host wrap-up: assembled from [`HostHandoff`].
    pub fn handoff(handoff: &HostHandoff) -> Self {
        Self::Handoff {
            server_proof: wire::encode(&handoff.server_proof),
            wrapped_group_key: wire::encode(&handoff.wrapped_group_key),
        }
    }
}

// ---- Invite link (the out-of-band carrier, host → guest) ----

/// Version prefix of the pairing invite link.
pub const INVITE_LINK_PREFIX: &str = "persona-pair-1";

/// Invite-link payload: short code + relay address + session id. The short code
/// remains the core interaction (both sides see the same code when comparing);
/// session addressing is technical payload (carried by QR code or clipboard).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PairingInviteLink {
    pub code: String,
    pub relay_url: String,
    pub session_id: String,
}

impl PairingInviteLink {
    pub fn encode(&self) -> String {
        let payload = serde_json::to_vec(self).expect("PairingInviteLink 必然可序列化");
        format!(
            "{INVITE_LINK_PREFIX}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        )
    }

    pub fn decode(input: &str) -> PersonaResult<Self> {
        let (prefix, payload) = input
            .trim()
            .split_once('.')
            .ok_or_else(|| PersonaError::InvalidInput("邀请串格式错误（缺版本段）".into()))?;
        if prefix != INVITE_LINK_PREFIX {
            return Err(PersonaError::InvalidInput(format!(
                "邀请串版本不支持：{prefix}"
            )));
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| PersonaError::InvalidInput(format!("邀请串 base64 非法: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| PersonaError::InvalidInput(format!("邀请串载荷非法: {e}")))
    }
}
