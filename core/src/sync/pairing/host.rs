//! Inviting side (host): the invite / offer / handoff facets and the
//! `PairingHost` handshake state, including the protocol-driven
//! `handle_message`.

use sha2::Sha256;

use crate::auth::srp::{SrpClient, SrpServer, SrpServerVerifier};
use crate::{PersonaError, PersonaResult};

use super::crypto::{
    derive_pairing_secret, generate_pairing_code, pairing_fingerprint, pairing_key_from,
    seal_group_key_with, PAIRING_GROUP_KEY_LEN, PAIRING_IDENTITY, PAIRING_SALT_LEN,
};
use super::message::{wire, PairingMessage};

// ---- Inviting side (host) ----

/// Invite facet: material handed to the relay and to the guest (short code + salt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingInvite {
    /// One-time passcode (shown for the guest to type in; short TTL and single
    /// use are enforced by the relay layer).
    pub code: String,
    /// KDF salt (distributed with the invite facet; feeds both sides' Argon2id).
    pub salt: [u8; PAIRING_SALT_LEN],
}

/// Offer facet, emitted by the host after receiving the guest's `client_public`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOffer {
    /// SRP server public (B_pub), returned to the guest via the relay.
    pub server_public: Vec<u8>,
    /// Host-side short fingerprint (shown in the UI, compared against the guest's).
    pub fingerprint: String,
}

/// Handoff facet after the host validates M1 (delivered to the guest once, via
/// the relay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHandoff {
    /// SRP server proof (M2).
    pub server_proof: Vec<u8>,
    /// Group key wrapped with AEAD(pairing_key) (nonce‖ct).
    pub wrapped_group_key: Vec<u8>,
}

/// Inviting-side session (in-memory only; neither the short code nor the verifier
/// is persisted or leaves the device — the Argon2id derived value is dropped
/// right after in-place use).
pub struct PairingHost {
    b_priv: [u8; 32],
    verifier: Vec<u8>,
    handshake: Option<(SrpServerVerifier<Sha256>, [u8; 32])>,
    finished: bool,
}

impl PairingHost {
    /// Start an invite: generate the passcode and pairing salt, and derive the
    /// verifier in place (never persisted).
    pub fn new_invite() -> PersonaResult<(Self, PairingInvite)> {
        let code = generate_pairing_code();
        let salt: [u8; PAIRING_SALT_LEN] = rand::random();
        let derived = derive_pairing_secret(&code, &salt)?;
        // The verifier is computed by the party holding the password (SRP's x
        // is only derived on the password side); in pairing both host and guest
        // hold the same code — the host derives and immediately discards it,
        // never persisting it.
        let client_for_v = SrpClient::<Sha256>::new(crate::auth::srp::srp_group());
        let verifier = client_for_v.compute_verifier(PAIRING_IDENTITY, &derived, &salt);
        let b_priv: [u8; 32] = rand::random();
        Ok((
            Self {
                b_priv,
                verifier,
                handshake: None,
                finished: false,
            },
            PairingInvite { code, salt },
        ))
    }

    /// Accept the guest's `client_public`: derive B_pub and the pairing key, and
    /// produce the short fingerprint.
    pub fn accept_join(&mut self, client_public: &[u8]) -> PersonaResult<HostOffer> {
        if self.handshake.is_some() || self.finished {
            return Err(PersonaError::InvalidInput(
                "配对已进行中或已完结，勿重复 join".into(),
            ));
        }
        let server = SrpServer::<Sha256>::new(crate::auth::srp::srp_group());
        let server_public = server.compute_public_ephemeral(&self.b_priv, &self.verifier);
        let sv = server
            .process_reply(&self.b_priv, &self.verifier, client_public)
            .map_err(|e| PersonaError::InvalidInput(format!("非法 client_public: {e}")))?;
        let key = pairing_key_from(sv.key())?;
        let fingerprint = pairing_fingerprint(&key);
        self.handshake = Some((sv, key));
        Ok(HostOffer {
            server_public,
            fingerprint,
        })
    }

    /// Short fingerprint of the current handshake (set after `accept_join`, for
    /// UI display and comparison).
    pub fn fingerprint(&self) -> Option<String> {
        self.handshake
            .as_ref()
            .map(|(_, key)| pairing_fingerprint(key))
    }

    /// Whether pairing is finished (handoff delivered) — no new join is accepted
    /// afterwards.
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// M1 submitted after the guest's fingerprint comparison passes: M2 + the
    /// wrapped group key are released only once verification succeeds.
    pub fn complete(
        &mut self,
        group_key: &[u8; PAIRING_GROUP_KEY_LEN],
        client_proof: &[u8],
    ) -> PersonaResult<HostHandoff> {
        let (sv, key) = self
            .handshake
            .take()
            .ok_or_else(|| PersonaError::InvalidInput("尚无进行中的配对握手".into()))?;
        sv.verify_client(client_proof).map_err(|_| {
            PersonaError::AuthenticationFailed("配对证明不匹配（动态密码不一致）".into())
        })?;
        self.finished = true;
        let wrapped = seal_group_key_with(&key, group_key)?;
        Ok(HostHandoff {
            server_proof: sv.proof().to_vec(),
            wrapped_group_key: wrapped,
        })
    }
}

// ---- Protocol driver (recommended host entry: mailbox polling + handle_message) ----

impl PairingHost {
    /// Consume a guest message and produce the reply (the host POSTs the return
    /// value back to the to-guest mailbox).
    ///
    /// `ClientPublic` → [`PairingMessage::ServerOffer`]; `ClientProof`
    /// (submitted after the UI fingerprint comparison passes) →
    /// [`PairingMessage::Handoff`]. All other directions/orderings are rejected.
    pub fn handle_message(
        &mut self,
        msg: PairingMessage,
        group_key: &[u8; PAIRING_GROUP_KEY_LEN],
    ) -> PersonaResult<Option<PairingMessage>> {
        match msg {
            PairingMessage::ClientPublic { client_public } => {
                let offer = self.accept_join(&wire::decode(&client_public)?)?;
                Ok(Some(PairingMessage::server_offer(&offer)))
            }
            PairingMessage::ClientProof { client_proof } => {
                let handoff = self.complete(group_key, &wire::decode(&client_proof)?)?;
                Ok(Some(PairingMessage::handoff(&handoff)))
            }
            _ => Err(PersonaError::InvalidInput(
                "host 侧不接受该类型消息（时序错或方向反）".into(),
            )),
        }
    }
}
