//! 邀请端（host）：邀请面/应答面/交接面与 `PairingHost` 握手态，
//! 含协议驱动 `handle_message`。

use sha2::Sha256;

use crate::auth::srp::{SrpClient, SrpServer, SrpServerVerifier};
use crate::{PersonaError, PersonaResult};

use super::crypto::{
    derive_pairing_secret, generate_pairing_code, pairing_fingerprint, pairing_key_from,
    seal_group_key_with, PAIRING_GROUP_KEY_LEN, PAIRING_IDENTITY, PAIRING_SALT_LEN,
};
use super::message::{wire, PairingMessage};

// ---- 邀请端（host） ----

/// 邀请面：交给中转与 guest 的材料（短码 + salt）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingInvite {
    /// 动态密码（展示给 guest 输入；短时效单次使用由中转层强制）。
    pub code: String,
    /// KDF salt（随邀请面分发，进双侧 Argon2id）。
    pub salt: [u8; PAIRING_SALT_LEN],
}

/// host 收到 guest 的 `client_public` 后的应答面。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOffer {
    /// SRP server public（B_pub），经中转回 guest。
    pub server_public: Vec<u8>,
    /// host 侧短指纹（UI 展示，与 guest 侧比对）。
    pub fingerprint: String,
}

/// host 校验 M1 通过后的交接面（经中转单次递送 guest）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHandoff {
    /// SRP server proof（M2）。
    pub server_proof: Vec<u8>,
    /// AEAD(pairing_key) 包裹的组密钥（nonce‖ct）。
    pub wrapped_group_key: Vec<u8>,
}

/// 邀请端会话（内存态；短码与 verifier 都不落盘、不出端——Argon2id
/// 派生值现场使用后即弃）。
pub struct PairingHost {
    b_priv: [u8; 32],
    verifier: Vec<u8>,
    handshake: Option<(SrpServerVerifier<Sha256>, [u8; 32])>,
    finished: bool,
}

impl PairingHost {
    /// 发起邀请：生成动态密码与配对 salt，现场派 verifier（不落盘）。
    pub fn new_invite() -> PersonaResult<(Self, PairingInvite)> {
        let code = generate_pairing_code();
        let salt: [u8; PAIRING_SALT_LEN] = rand::random();
        let derived = derive_pairing_secret(&code, &salt)?;
        // verifier 由持有口令的一方计算（SRP 的 x 只在口令侧派生），
        // 配对里 host/guest 都持同码——host 现场派完即弃，不落盘。
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

    /// 接受 guest 的 `client_public`：派 B_pub 与 pairing key，出短指纹。
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

    /// 当前握手的短指纹（`accept_join` 后有值，供 UI 展示比对）。
    pub fn fingerprint(&self) -> Option<String> {
        self.handshake
            .as_ref()
            .map(|(_, key)| pairing_fingerprint(key))
    }

    /// 配对是否已完结（handoff 已交付）——完结后不再接受新 join。
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// guest 比对指纹通过后提交 M1：验证通过才交出 M2 + 包裹的组密钥。
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

// ---- 协议驱动（宿主侧推荐入口：信箱轮询 + handle_message） ----

impl PairingHost {
    /// 消费 guest 消息，产出应答消息（宿主把返回值 POST 回 to-guest 信箱）。
    ///
    /// `ClientPublic` → 出 [`PairingMessage::ServerOffer`]；`ClientProof`
    /// （UI 比对指纹通过后提交）→ 出 [`PairingMessage::Handoff`]。
    /// 其余方向/时序一律拒绝。
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
