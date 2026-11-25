//! Joining side (guest): the proof facet and the `PairingGuest` handshake state,
//! including the protocol-driven `start_message`/`handle_message`/`group_key`.

use sha2::Sha256;

use crate::auth::srp::{SrpClient, SrpClientVerifier};
use crate::{PersonaError, PersonaResult};

use super::crypto::{
    derive_pairing_secret, open_group_key_with, pairing_fingerprint, pairing_key_from,
    PAIRING_GROUP_KEY_LEN, PAIRING_IDENTITY,
};
use super::message::{wire, PairingMessage};

// ---- Joining side (guest) ----

/// Guest's first-step output: `client_public`, relayed to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestOffer {
    pub client_public: Vec<u8>,
}

/// Guest's second-step output: short fingerprint (human comparison) + M1
/// submitted to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProof {
    pub fingerprint: String,
    pub client_proof: Vec<u8>,
}

/// Joining-side session (in-memory only; the derived short-code value is never
/// persisted).
pub struct PairingGuest {
    derived: [u8; 32],
    a_priv: [u8; 32],
    salt: Vec<u8>,
    handshake: Option<(SrpClientVerifier<Sha256>, [u8; 32])>,
    received_group_key: Option<[u8; PAIRING_GROUP_KEY_LEN]>,
    /// M1 produced by `finish`: held until the UI fingerprint comparison passes,
    /// then delivered.
    pending_proof: Option<Vec<u8>>,
}

impl PairingGuest {
    /// Start pairing with the passcode: derive `client_public` (sent to the host
    /// via the relay).
    pub fn start(code: &str, salt: &[u8]) -> PersonaResult<(Self, GuestOffer)> {
        let derived = derive_pairing_secret(code, salt)?;
        let client = SrpClient::<Sha256>::new(crate::auth::srp::srp_group());
        let a_priv: [u8; 32] = rand::random();
        let client_public = client.compute_public_ephemeral(&a_priv);
        Ok((
            Self {
                derived,
                a_priv,
                salt: salt.to_vec(),
                handshake: None,
                received_group_key: None,
                pending_proof: None,
            },
            GuestOffer { client_public },
        ))
    }

    /// Receive the host's B_pub: derive the pairing key and short fingerprint
    /// (for UI comparison) and emit M1.
    pub fn finish(&mut self, server_public: &[u8]) -> PersonaResult<GuestProof> {
        if self.handshake.is_some() {
            return Err(PersonaError::InvalidInput("配对已进行中".into()));
        }
        let client = SrpClient::<Sha256>::new(crate::auth::srp::srp_group());
        let cv = client
            .process_reply(
                &self.a_priv,
                PAIRING_IDENTITY,
                &self.derived,
                &self.salt,
                server_public,
            )
            .map_err(|e| PersonaError::InvalidInput(format!("非法 server_public: {e}")))?;
        let key = pairing_key_from(cv.key())?;
        let fingerprint = pairing_fingerprint(&key);
        let proof = cv.proof().to_vec();
        self.handshake = Some((cv, key));
        self.pending_proof = Some(proof.clone());
        Ok(GuestProof {
            fingerprint,
            client_proof: proof,
        })
    }

    /// Take the M1 awaiting delivery (set after `finish`; taking it clears it —
    /// delivery happens exactly once).
    pub fn take_pending_proof(&mut self) -> Option<PairingMessage> {
        let proof = self.pending_proof.take()?;
        Some(PairingMessage::ClientProof {
            client_proof: wire::encode(&proof),
        })
    }

    /// Short fingerprint of the current handshake (set after `finish`, for UI
    /// display and comparison).
    pub fn fingerprint(&self) -> Option<String> {
        self.handshake
            .as_ref()
            .map(|(_, key)| pairing_fingerprint(key))
    }

    /// Accept the handoff once comparison passes: verify M2 and extract the group
    /// key (join complete).
    pub fn accept_handoff(
        &mut self,
        server_proof: &[u8],
        wrapped_group_key: &[u8],
    ) -> PersonaResult<[u8; PAIRING_GROUP_KEY_LEN]> {
        let (cv, key) = self
            .handshake
            .take()
            .ok_or_else(|| PersonaError::InvalidInput("尚无进行中的配对握手".into()))?;
        cv.verify_server(server_proof).map_err(|_| {
            PersonaError::AuthenticationFailed("server 证明不匹配（中间人或错码）".into())
        })?;
        open_group_key_with(&key, wrapped_group_key)
    }
}

impl PairingGuest {
    /// Start pairing (step one): return the first message (the host POSTs it to
    /// the to-host mailbox).
    pub fn start_message(code: &str, salt: &[u8]) -> PersonaResult<(Self, PairingMessage)> {
        let (guest, offer) = Self::start(code, salt)?;
        Ok((guest, PairingMessage::client_public(&offer)))
    }

    /// Consume a host message: `ServerOffer` → `ClientProof`; `Handoff`
    /// (delivered after the UI comparison passes) → the group key is captured
    /// and `None` is returned, meaning pairing is complete.
    pub fn handle_message(&mut self, msg: PairingMessage) -> PersonaResult<Option<PairingMessage>> {
        match msg {
            PairingMessage::ServerOffer { server_public } => {
                let proof = self.finish(&wire::decode(&server_public)?)?;
                Ok(Some(PairingMessage::client_proof(&proof)))
            }
            PairingMessage::Handoff {
                server_proof,
                wrapped_group_key,
            } => {
                let key = self.accept_handoff(
                    &wire::decode(&server_proof)?,
                    &wire::decode(&wrapped_group_key)?,
                )?;
                self.received_group_key = Some(key);
                Ok(None)
            }
            _ => Err(PersonaError::InvalidInput(
                "guest 侧不接受该类型消息（时序错或方向反）".into(),
            )),
        }
    }

    /// Fetch the group key once pairing is complete (set after
    /// [`Self::handle_message`] returns `None`).
    pub fn group_key(&self) -> Option<&[u8; PAIRING_GROUP_KEY_LEN]> {
        self.received_group_key.as_ref()
    }
}
