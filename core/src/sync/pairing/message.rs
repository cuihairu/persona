//! 中转线路消息：`PairingMessage` 枚举、base64 wire 编解码与邀请串
//! `PairingInviteLink`（版本前缀 + 载荷编解码）。

use base64::Engine as _;

use crate::{PersonaError, PersonaResult};

use super::guest::{GuestOffer, GuestProof};
use super::host::{HostHandoff, HostOffer};

// ---- 中转 wire 消息 ----

/// 双端经中转信箱递送的配对消息（信箱内层载荷；中转不解释内容，
/// 只见 SRP 公开消息与 AEAD 密文——零知识）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairingMessage {
    /// guest → host：client ephemeral public（A_pub）。
    ClientPublic { client_public: String },
    /// host → guest：server ephemeral public（B_pub）。
    ServerOffer { server_public: String },
    /// guest → host：指纹比对通过后提交的 M1。
    ClientProof { client_proof: String },
    /// host → guest：M2 + AEAD 包裹的组密钥（配对收尾，单次投递）。
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
    /// guest 第一步：从 [`GuestOffer`] 组装。
    pub fn client_public(offer: &GuestOffer) -> Self {
        Self::ClientPublic {
            client_public: wire::encode(&offer.client_public),
        }
    }

    /// host 应答：从 [`HostOffer`] 组装。
    pub fn server_offer(offer: &HostOffer) -> Self {
        Self::ServerOffer {
            server_public: wire::encode(&offer.server_public),
        }
    }

    /// guest 第二步：从 [`GuestProof`] 组装。
    pub fn client_proof(proof: &GuestProof) -> Self {
        Self::ClientProof {
            client_proof: wire::encode(&proof.client_proof),
        }
    }

    /// host 收尾：从 [`HostHandoff`] 组装。
    pub fn handoff(handoff: &HostHandoff) -> Self {
        Self::Handoff {
            server_proof: wire::encode(&handoff.server_proof),
            wrapped_group_key: wire::encode(&handoff.wrapped_group_key),
        }
    }
}

// ---- 邀请串（host → guest 的带外载体） ----

/// 配对邀请串的版本前缀。
pub const INVITE_LINK_PREFIX: &str = "persona-pair-1";

/// 邀请串载荷：短码 + 中转地址 + 会话 id。短码仍是核心交互（双方比对
/// 时看到同一个码），会话定位是技术载荷（QR 或剪贴板传递）。
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
