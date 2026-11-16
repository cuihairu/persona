//! 加入端（guest）：出证面与 `PairingGuest` 握手态，含协议驱动
//! `start_message`/`handle_message`/`group_key`。

use sha2::Sha256;

use crate::auth::srp::{SrpClient, SrpClientVerifier};
use crate::{PersonaError, PersonaResult};

use super::crypto::{
    derive_pairing_secret, open_group_key_with, pairing_fingerprint, pairing_key_from,
    PAIRING_GROUP_KEY_LEN, PAIRING_IDENTITY,
};
use super::message::{wire, PairingMessage};

// ---- 加入端（guest） ----

/// guest 第一步产物：交中转转给 host 的 `client_public`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestOffer {
    pub client_public: Vec<u8>,
}

/// guest 第二步产物：短指纹（人工比对）+ 提交 host 的 M1。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProof {
    pub fingerprint: String,
    pub client_proof: Vec<u8>,
}

/// 加入端会话（内存态；短码派生值不落盘）。
pub struct PairingGuest {
    derived: [u8; 32],
    a_priv: [u8; 32],
    salt: Vec<u8>,
    handshake: Option<(SrpClientVerifier<Sha256>, [u8; 32])>,
    received_group_key: Option<[u8; PAIRING_GROUP_KEY_LEN]>,
    /// `finish` 产出的 M1：UI 指纹比对通过前持有、通过后投递。
    pending_proof: Option<Vec<u8>>,
}

impl PairingGuest {
    /// 用动态密码起配：派 `client_public`（经中转交 host）。
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

    /// 收到 host 的 B_pub：派 pairing key 与短指纹（UI 比对），出 M1。
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

    /// 取出待投递的 M1（`finish` 后有值；取出即清空——投递只此一次）。
    pub fn take_pending_proof(&mut self) -> Option<PairingMessage> {
        let proof = self.pending_proof.take()?;
        Some(PairingMessage::ClientProof {
            client_proof: wire::encode(&proof),
        })
    }

    /// 当前握手的短指纹（`finish` 后有值，供 UI 展示比对）。
    pub fn fingerprint(&self) -> Option<String> {
        self.handshake
            .as_ref()
            .map(|(_, key)| pairing_fingerprint(key))
    }

    /// 比对通过后收交接：验 M2，解出组密钥（入组完成）。
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
    /// 起配（第一步）：返回首条消息（宿主 POST 到 to-host 信箱）。
    pub fn start_message(code: &str, salt: &[u8]) -> PersonaResult<(Self, PairingMessage)> {
        let (guest, offer) = Self::start(code, salt)?;
        Ok((guest, PairingMessage::client_public(&offer)))
    }

    /// 消费 host 消息：`ServerOffer` → 出 `ClientProof`；`Handoff`（UI
    /// 比对通过后投递）→ 组密钥落袋，返回 `None` 表示配对完成。
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

    /// 配对完成后取组密钥（[`Self::handle_message`] 返回 `None` 后有值）。
    pub fn group_key(&self) -> Option<&[u8; PAIRING_GROUP_KEY_LEN]> {
        self.received_group_key.as_ref()
    }
}
