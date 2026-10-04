//! 同步组动态密码配对（同步组模式 S1，`docs/sync-group-mode.md` §二.1-2）。
//!
//! 零账号入组：邀请端出短时效动态密码，加入端输入同码，经 PAKE 换出强
//! 共享钥（pairing key），组密钥以其 AEAD 包裹后经中转递交——短码与组密钥
//! 都不上中转线路（中转只见 SRP 公开消息与密文信封，零知识）。
//!
//! 协议（SRP-6a 原语复用 [`crate::auth::srp`]，RFC 5054 向量锁定），
//! host = 邀请端（组内、持组密钥），guest = 加入端，中转 = 无账号信箱：
//!
//! 1. [`PairingHost::new_invite`] → `(host, invite{code, salt})`，code 展示
//! 2. [`PairingGuest::start`]（输码）→ `client_public` 经中转交 host
//! 3. [`PairingHost::accept_join`] → `server_public` 经中转回 guest；
//!    双端各自派生 6 位数字短指纹展示，人工比对（防中间人）
//! 4. [`PairingGuest::finish`] → `client_proof`（M1）经中转交 host
//!    （比对通过后才提交）
//! 5. [`PairingHost::complete`] → 校验 M1，交出 `{server_proof(M2),
//!    wrapped_group_key}`；M2 只在 M1 验证通过后交付
//! 6. [`PairingGuest::accept_handoff`] → 校验 M2，解出组密钥，入组完成
//!
//! 安全语义：
//! - **短码不作密钥**：先 Argon2id（独立域前缀，与本地解锁/备份/登录
//!   SRP 互为不同协议域）派生，派生值才进 SRP 的 `x`；
//! - **防中间人**：无短码的中间人派不出同款 pairing key，短指纹不一致
//!   即被人工比对拦下；M1/M2 双向证明兜底；
//! - **单向递送**：`wrapped_group_key` 只有 pairing key 能开，中转存密文
//!   无益；`complete`/`accept_handoff` 均一次性（消耗握手态）。
//! - TTL/单次会话/限次尝试由中转层负责（见 server `/api/v1/pairing/*`），
//!   本模块只做纯密码逻辑，无 IO。

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine as _;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::auth::srp::{SrpClient, SrpClientVerifier, SrpServer, SrpServerVerifier};
use crate::{PersonaError, PersonaResult};

// ---- 参数常量 ----

/// 动态密码长度（Crockford base32 字符数；9×5 bit = 45 bit 熵，
/// 短时效 + 单次使用 + 中转限次共同兜住在线爆破面）。
pub const PAIRING_CODE_LEN: usize = 9;
/// 配对 salt 字节数（经邀请面交给 guest，与 code 一起进 KDF）。
pub const PAIRING_SALT_LEN: usize = 16;
/// 组密钥长度（与 [`crate::sync::envelope`] 的组密钥同规格）。
pub const PAIRING_GROUP_KEY_LEN: usize = 32;
/// 双端比对的短指纹位数（10^6 空间；防 MITM 靠「不一致即人工拒绝」）。
pub const FINGERPRINT_LEN: usize = 6;

/// Argon2id 域前缀（进 KDF 的盐头）。
const PAIRING_KDF_DOMAIN: &[u8] = b"persona-pairing-v1";
/// SRP identity（配对路径固定身份，与账号登录的 username 空间隔离）。
const PAIRING_IDENTITY: &[u8] = b"persona-pairing-v1";
/// HKDF info：premaster → pairing key。
const PAIRING_KEY_INFO: &[u8] = b"persona-pairing-key-v1";
/// 短指纹派生域。
const FINGERPRINT_DOMAIN: &[u8] = b"persona-pairing-fp-v1";
/// AEAD 附加认证数据（wrap 的域绑定）。
const WRAP_AAD: &[u8] = b"persona-pairing-wrap-v1";

/// Crockford base32（排除 I L O U 易混字形）。
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// nonce + 组密钥 + GCM tag。
pub const WRAPPED_GROUP_KEY_LEN: usize = 12 + PAIRING_GROUP_KEY_LEN + 16;

/// 生成动态密码：Crockford base32，[`PAIRING_CODE_LEN`] 字符。
pub fn generate_pairing_code() -> String {
    let bytes: [u8; 6] = rand::random();
    let mut extended = [0u8; 8];
    extended[..6].copy_from_slice(&bytes);
    let bits = u64::from_be_bytes(extended); // 48 bit，取高 45
    (0..PAIRING_CODE_LEN)
        .map(|i| {
            let idx = ((bits >> (3 + 5 * (PAIRING_CODE_LEN - 1 - i))) & 31) as usize;
            CROCKFORD[idx] as char
        })
        .collect()
}

/// 规范化用户输入的动态密码：去空白/连字符、大写、易混字形映射
/// （O→0、I→1、L→1、U→V）。非字母数字字符一律丢弃。
pub fn normalize_pairing_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .map(|c| match c {
            'O' => '0',
            'I' | 'L' => '1',
            'U' => 'V',
            other => other,
        })
        .collect()
}

/// Argon2id 派生配对密钥材料（短码 → SRP 的「password」角色）。
fn derive_pairing_secret(code: &str, salt: &[u8]) -> PersonaResult<[u8; 32]> {
    let mut domain_salt = Vec::with_capacity(PAIRING_KDF_DOMAIN.len() + salt.len());
    domain_salt.extend_from_slice(PAIRING_KDF_DOMAIN);
    domain_salt.extend_from_slice(salt);
    let mut out = [0u8; 32];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    )
    .hash_password_into(code.as_bytes(), &domain_salt, &mut out)
    .map_err(|e| PersonaError::CryptographicError(format!("pairing KDF failed: {e}")))?;
    Ok(out)
}

/// pairing key = HKDF-SHA256(premaster)——SRP premaster 到 AEAD 钥的
/// 域绑定收缩。
fn pairing_key_from(premaster: &[u8]) -> PersonaResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PAIRING_KDF_DOMAIN), premaster);
    let mut out = [0u8; 32];
    hk.expand(PAIRING_KEY_INFO, &mut out)
        .map_err(|e| PersonaError::CryptographicError(format!("pairing HKDF failed: {e}")))?;
    Ok(out)
}

/// 双端比对的短指纹：6 位十进制（前导零保留）。
pub fn pairing_fingerprint(pairing_key: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(FINGERPRINT_DOMAIN)
        .chain_update(pairing_key)
        .finalize();
    let v = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{v:0>6}")
}

fn seal_group_key_with(
    pairing_key: &[u8; 32],
    group_key: &[u8; PAIRING_GROUP_KEY_LEN],
) -> PersonaResult<Vec<u8>> {
    let cipher = Aes256Gcm::new((&pairing_key.clone()).into());
    let nonce_bytes: [u8; 12] = rand::random();
    let ct = cipher
        .encrypt(
            aes_gcm::Nonce::from(nonce_bytes).as_ref(),
            aes_gcm::aead::Payload {
                msg: group_key.as_ref(),
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| PersonaError::CryptographicError("group key seal failed".into()))?;
    let mut out = Vec::with_capacity(WRAPPED_GROUP_KEY_LEN);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_group_key_with(
    pairing_key: &[u8; 32],
    wrapped: &[u8],
) -> PersonaResult<[u8; PAIRING_GROUP_KEY_LEN]> {
    if wrapped.len() != WRAPPED_GROUP_KEY_LEN {
        return Err(PersonaError::CryptographicError(format!(
            "wrapped group key 长度应为 {WRAPPED_GROUP_KEY_LEN}，得 {}",
            wrapped.len()
        )));
    }
    let cipher = Aes256Gcm::new((&pairing_key.clone()).into());
    let (nonce_bytes, ct) = wrapped.split_at(12);
    let nonce: [u8; 12] = nonce_bytes.try_into().expect("split_at(12) 后必为 12 字节");
    let pt = cipher
        .decrypt(
            &aes_gcm::Nonce::from(nonce),
            aes_gcm::aead::Payload {
                msg: ct,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| {
            PersonaError::CryptographicError("组密钥解封失败（码不对或信封被篡改）".into())
        })?;
    let mut out = [0u8; PAIRING_GROUP_KEY_LEN];
    out.copy_from_slice(&pt);
    Ok(out)
}

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

mod wire {
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

/// 中转信箱客户端（feature `remote-auth`）：persona-server
/// `/api/v1/pairing/*`。只做 wire（URL/方法/JSON/状态码/错误映射），
/// 密码学与状态机在 [`PairingHost`]/[`PairingGuest`]。
#[cfg(feature = "remote-auth")]
pub mod relay {
    use std::time::Duration;

    use base64::Engine as _;
    use reqwest::Method;
    use serde::Deserialize;

    use super::{PairingGuest, PairingHost, PairingInviteLink, PairingMessage};
    use crate::{PersonaError, Result};

    /// 轮询间隔（take 即消费，无需长轮询）。
    pub const POLL_EVERY: Duration = Duration::from_millis(500);
    /// 单次配对的生命周期上限（对应中转 TTL 600s 的上限内侧）。
    pub const DRIVE_DEADLINE: Duration = Duration::from_secs(90);

    #[derive(Debug, Deserialize)]
    struct CreateSession {
        session_id: String,
        #[allow(dead_code)]
        expires_in_secs: i64,
    }

    #[derive(Debug, Deserialize)]
    pub struct RelaySessionInfo {
        pub salt: Vec<u8>,
        pub expires_in_secs: i64,
        #[allow(dead_code)]
        pub to_host_len: i64,
        #[allow(dead_code)]
        pub to_guest_len: i64,
    }

    pub struct PairingRelayClient {
        base_url: String,
        http: reqwest::Client,
    }

    impl PairingRelayClient {
        pub fn new(base_url: impl Into<String>) -> Result<Self> {
            let http = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .build()
                .map_err(|e| {
                    PersonaError::ConfigurationError(format!(
                        "pairing relay client init failed: {e}"
                    ))
                })?;
            Ok(Self {
                base_url: base_url.into().trim_end_matches('/').to_owned(),
                http,
            })
        }

        fn uri(&self, session_id: &str, path: &str) -> String {
            format!(
                "{}/api/v1/pairing/sessions/{session_id}{path}",
                self.base_url
            )
        }

        /// 非 2xx/422 统一转 [`PersonaError::Io`]（带服务器 error.message）；
        /// 422 转 [`PersonaError::Validation`]（队列满/载荷超限等）。
        async fn ensure_success(resp: reqwest::Response, step: &str) -> Result<reqwest::Response> {
            if resp.status().is_success() {
                return Ok(resp);
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("error")
                        .and_then(|e| e.get("message"))
                        .and_then(|m| m.as_str())
                        .map(str::to_string)
                });
            let message = match detail {
                Some(m) => format!("{step} failed (HTTP {status}): {m}"),
                None => format!("{step} failed (HTTP {status})"),
            };
            match status.as_u16() {
                422 => Err(PersonaError::Validation(message).into()),
                _ => Err(PersonaError::Io(message).into()),
            }
        }

        /// 建会话（host）：POST /sessions，返回 (session_id, expires_in_secs)。
        pub async fn create_session(
            &self,
            salt: &[u8; super::PAIRING_SALT_LEN],
        ) -> Result<(String, i64)> {
            let resp = self
                .http
                .request(
                    Method::POST,
                    format!("{}/api/v1/pairing/sessions", self.base_url),
                )
                .json(&serde_json::json!({
                    "salt": base64::engine::general_purpose::STANDARD.encode(salt),
                }))
                .send()
                .await
                .map_err(|e| PersonaError::Io(format!("pairing create request failed: {e}")))?;
            let resp = Self::ensure_success(resp, "pairing create").await?;
            let created: CreateSession = resp
                .json()
                .await
                .map_err(|e| PersonaError::Io(format!("pairing create response malformed: {e}")))?;
            Ok((created.session_id, created.expires_in_secs))
        }

        /// 会话元信息（guest 取 salt）。
        pub async fn session_info(&self, session_id: &str) -> Result<RelaySessionInfo> {
            let resp = self
                .http
                .request(Method::GET, self.uri(session_id, ""))
                .send()
                .await
                .map_err(|e| PersonaError::Io(format!("pairing info request failed: {e}")))?;
            let resp = Self::ensure_success(resp, "pairing info").await?;
            let raw: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| PersonaError::Io(format!("pairing info response malformed: {e}")))?;
            let salt = base64::engine::general_purpose::STANDARD
                .decode(raw["salt"].as_str().unwrap_or_default())
                .map_err(|e| PersonaError::Io(format!("pairing info salt malformed: {e}")))?;
            Ok(RelaySessionInfo {
                salt,
                expires_in_secs: raw["expires_in_secs"].as_i64().unwrap_or(0),
                to_host_len: raw["to_host_len"].as_i64().unwrap_or(0),
                to_guest_len: raw["to_guest_len"].as_i64().unwrap_or(0),
            })
        }

        /// DELETE /sessions/{id}（完成/放弃后清理；幂等）。
        pub async fn delete_session(&self, session_id: &str) -> Result<()> {
            let resp = self
                .http
                .request(Method::DELETE, self.uri(session_id, ""))
                .send()
                .await
                .map_err(|e| PersonaError::Io(format!("pairing delete request failed: {e}")))?;
            let _ = Self::ensure_success(resp, "pairing delete").await?;
            Ok(())
        }

        /// POST /sessions/{id}/messages/{direction}。
        async fn post_message(
            &self,
            session_id: &str,
            direction: &str,
            msg: &PairingMessage,
        ) -> Result<()> {
            let payload = serde_json::to_vec(msg)
                .map_err(|e| PersonaError::Io(format!("pairing message serialize failed: {e}")))?;
            let resp = self
                .http
                .request(
                    Method::POST,
                    self.uri(session_id, &format!("/messages/{direction}")),
                )
                .json(&serde_json::json!({
                    "payload": base64::engine::general_purpose::STANDARD.encode(payload),
                }))
                .send()
                .await
                .map_err(|e| PersonaError::Io(format!("pairing post failed: {e}")))?;
            let _ = Self::ensure_success(resp, "pairing post").await?;
            Ok(())
        }

        pub async fn post_to_host(&self, session_id: &str, msg: &PairingMessage) -> Result<()> {
            self.post_message(session_id, "to-host", msg).await
        }

        pub async fn post_to_guest(&self, session_id: &str, msg: &PairingMessage) -> Result<()> {
            self.post_message(session_id, "to-guest", msg).await
        }

        /// GET /sessions/{id}/messages/{direction}（取即消费）。
        async fn take_messages(
            &self,
            session_id: &str,
            direction: &str,
        ) -> Result<Vec<PairingMessage>> {
            let resp = self
                .http
                .request(
                    Method::GET,
                    self.uri(session_id, &format!("/messages/{direction}")),
                )
                .send()
                .await
                .map_err(|e| PersonaError::Io(format!("pairing take request failed: {e}")))?;
            let resp = Self::ensure_success(resp, "pairing take").await?;
            let raw: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| PersonaError::Io(format!("pairing take response malformed: {e}")))?;
            let mut out = Vec::new();
            for m in raw["messages"]
                .as_array()
                .ok_or_else(|| PersonaError::Io("pairing take messages malformed".into()))?
            {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(m.as_str().unwrap_or_default())
                    .map_err(|e| PersonaError::Io(format!("pairing take b64 malformed: {e}")))?;
                let msg: PairingMessage = serde_json::from_slice(&bytes)
                    .map_err(|e| PersonaError::Io(format!("pairing message malformed: {e}")))?;
                out.push(msg);
            }
            Ok(out)
        }

        pub async fn take_to_host(&self, session_id: &str) -> Result<Vec<PairingMessage>> {
            self.take_messages(session_id, "to-host").await
        }

        pub async fn take_to_guest(&self, session_id: &str) -> Result<Vec<PairingMessage>> {
            self.take_messages(session_id, "to-guest").await
        }

        /// host 全自动驱动：等到 guest 的 ClientPublic 后交付 ServerOffer 与
        /// Handoff（[`PairingGuest`] 侧确认流程见 [`Self::join_begin`]）。
        /// 返回 host 短指纹（供 UI 与 guest 比对）。错码/超期 → Err。
        pub async fn drive_host(
            &self,
            host: &mut PairingHost,
            group_key: &[u8; super::PAIRING_GROUP_KEY_LEN],
            session_id: &str,
        ) -> Result<String> {
            let deadline = std::time::Instant::now() + DRIVE_DEADLINE;
            let mut fingerprint: Option<String> = None;
            loop {
                for msg in self.take_to_host(session_id).await? {
                    let Some(reply) = host.handle_message(msg, group_key)? else {
                        return Err(PersonaError::Io("host 侧意外收到完成信号".into()).into());
                    };
                    if let Some(fp) = host.fingerprint() {
                        fingerprint = Some(fp);
                    }
                    self.post_to_guest(session_id, &reply).await?;
                    if host.finished() {
                        return fingerprint.ok_or_else(|| {
                            {
                                PersonaError::Io("配对完成但缺少指纹（状态异常）".into())
                            }
                            .into()
                        });
                    }
                }
                if std::time::Instant::now() >= deadline {
                    return Err(PersonaError::Io("配对等待超时（90s，请重试）".into()).into());
                }
                tokio::time::sleep(POLL_EVERY).await;
            }
        }

        /// guest 第一步：解码邀请串、取 salt、起配、交 ClientPublic、
        /// 等回 ServerOffer。返回 (guest, 短指纹)——指纹展示给用户比对，
        /// 比对通过后调 [`Self::join_confirm`] 才真正入组。
        pub async fn join_begin(&self, link: &PairingInviteLink) -> Result<(PairingGuest, String)> {
            let info = self.session_info(&link.session_id).await?;
            if info.salt.len() != super::PAIRING_SALT_LEN {
                return Err(PersonaError::Io(format!(
                    "relay salt 长度应为 {}，得 {}",
                    super::PAIRING_SALT_LEN,
                    info.salt.len()
                ))
                .into());
            }
            let (mut guest, first) = PairingGuest::start_message(&link.code, &info.salt)?;
            self.post_to_host(&link.session_id, &first).await?;
            let deadline = std::time::Instant::now() + DRIVE_DEADLINE;
            loop {
                if let Some(msg) = self
                    .take_to_guest(&link.session_id)
                    .await?
                    .into_iter()
                    .next()
                {
                    let Some(reply) = guest.handle_message(msg)? else {
                        return Err(PersonaError::Io("配对意外提前完成".into()).into());
                    };
                    // ServerOffer 已消费 → ClientProof 待用户确认，先不投
                    debug_assert!(
                        matches!(reply, PairingMessage::ClientProof { .. }),
                        "join_begin 只应停在 ClientProof 前"
                    );
                    let fp = guest
                        .fingerprint()
                        .ok_or_else(|| PersonaError::Io("指纹派生失败（状态异常）".into()))?;
                    return Ok((guest, fp));
                }
                if std::time::Instant::now() >= deadline {
                    return Err(PersonaError::Io("等待 host 应答超时（90s，请重试）".into()).into());
                }
                tokio::time::sleep(POLL_EVERY).await;
            }
        }

        /// guest 第二步：用户指纹比对通过——交 ClientProof，等 Handoff，
        /// 解出组密钥。调用后 [`PairingGuest::group_key`] 有值。
        pub async fn join_confirm(&self, guest: &mut PairingGuest, session_id: &str) -> Result<()> {
            // 取出 join_begin 持有的待投 M1
            let proof_msg = guest
                .take_pending_proof()
                .ok_or_else(|| PersonaError::Io("join_confirm 前必须先 join_begin".into()))?;
            self.post_to_host(session_id, &proof_msg).await?;
            let deadline = std::time::Instant::now() + DRIVE_DEADLINE;
            loop {
                if let Some(msg) = self.take_to_guest(session_id).await?.into_iter().next() {
                    if let Some(_reply) = guest.handle_message(msg)? {
                        return Err(PersonaError::Io("后续不应再有应答消息".into()).into());
                    }
                    // None = 配对完成，组密钥已落袋
                    self.delete_session(session_id).await.ok();
                    return Ok(());
                }
                if std::time::Instant::now() >= deadline {
                    return Err(PersonaError::Io("等待交接超时（90s，请重试）".into()).into());
                }
                tokio::time::sleep(POLL_EVERY).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "remote-auth")]
    mod relay_tests {
        use super::*;
        use crate::sync::pairing::relay::{PairingRelayClient, POLL_EVERY};
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};

        struct CapturedRequest {
            method: String,
            path: String,
            body: String,
        }

        /// 一次性 TCP 假 relay：内存双向信箱，路由与 server /pairing/* 一致。
        fn spawn_mock_relay() -> String {
            #[derive(Default)]
            struct Mailbox {
                salt: Option<Vec<u8>>,
                to_host: Vec<Vec<u8>>,
                to_guest: Vec<Vec<u8>>,
            }
            use base64::Engine as _;
            let state = Arc::new(Mutex::new(Mailbox::default()));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).unwrap_or(0) == 0 {
                            break;
                        }
                        buf.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let request_line = head.lines().next().unwrap_or_default().to_string();
                    let content_length: usize = head
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split_once(':')?.1.trim().parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0u8; content_length];
                    if content_length > 0 {
                        let _ = stream.read_exact(&mut body);
                    }
                    let req = CapturedRequest {
                        method: request_line
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_string(),
                        path: request_line
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or_default()
                            .to_string(),
                        body: String::from_utf8_lossy(&body).into_owned(),
                    };
                    let (status, resp_body) = {
                        let mut st = state.lock().unwrap();
                        let b64d =
                            |v: &str| base64::engine::general_purpose::STANDARD.decode(v).unwrap();
                        let b64e = |v: &[u8]| base64::engine::general_purpose::STANDARD.encode(v);
                        if req.method == "POST" && req.path == "/api/v1/pairing/sessions" {
                            let json: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                            st.salt = Some(b64d(json["salt"].as_str().unwrap()));
                            (
                                201,
                                r#"{"session_id":"sess-1","expires_in_secs":600}"#.to_string(),
                            )
                        } else if req.method == "GET"
                            && req.path == "/api/v1/pairing/sessions/sess-1"
                        {
                            let json = serde_json::json!({
                                "salt": b64e(st.salt.as_deref().unwrap_or_default()),
                                "expires_in_secs": 600,
                                "to_host_len": st.to_host.len() as i64,
                                "to_guest_len": st.to_guest.len() as i64,
                            });
                            (200, json.to_string())
                        } else if req.path.ends_with("/messages/to-host") && req.method == "POST" {
                            let json: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                            st.to_host.push(b64d(json["payload"].as_str().unwrap()));
                            (202, "{}".to_string())
                        } else if req.path.ends_with("/messages/to-guest") && req.method == "POST" {
                            let json: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                            st.to_guest.push(b64d(json["payload"].as_str().unwrap()));
                            (202, "{}".to_string())
                        } else if req.path.ends_with("/messages/to-host") {
                            let msgs: Vec<String> =
                                st.to_host.drain(..).map(|m| b64e(&m)).collect();
                            (200, serde_json::json!({ "messages": msgs }).to_string())
                        } else if req.path.ends_with("/messages/to-guest") {
                            let msgs: Vec<String> =
                                st.to_guest.drain(..).map(|m| b64e(&m)).collect();
                            (200, serde_json::json!({ "messages": msgs }).to_string())
                        } else if req.method == "DELETE" {
                            (204, String::new())
                        } else {
                            (404, String::new())
                        }
                    };
                    let reason = if status == 204 { "" } else { "OK" };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                        resp_body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            });
            format!("http://{addr}")
        }

        #[tokio::test]
        async fn relay_client_drives_full_pairing_over_http_mock() {
            let base_url = spawn_mock_relay();
            let client = PairingRelayClient::new(&base_url).unwrap();

            let (mut host, invite) = PairingHost::new_invite().unwrap();
            let (session_id, _ttl) = client.create_session(&invite.salt).await.unwrap();
            let link = PairingInviteLink {
                code: invite.code.clone(),
                relay_url: base_url,
                session_id: session_id.clone(),
            };
            // 邀请串往返
            let decoded = PairingInviteLink::decode(&link.encode()).unwrap();
            assert_eq!(decoded, link);

            let group_key: [u8; 32] = rand::random();
            let host_client = PairingRelayClient::new(&link.relay_url).unwrap();
            let host_session = link.session_id.clone();
            let host_task = tokio::spawn(async move {
                host_client
                    .drive_host(&mut host, &group_key, &host_session)
                    .await
            });

            let guest_client = PairingRelayClient::new(&link.relay_url).unwrap();
            let (mut guest, guest_fp) = guest_client.join_begin(&link).await.unwrap();
            // 先 confirm（drive_host 在等 ClientProof，先 await 会死锁到超时）
            guest_client
                .join_confirm(&mut guest, &link.session_id)
                .await
                .unwrap();
            assert_eq!(guest.group_key(), Some(&group_key));
            // host 侧收尾后取指纹比对
            let host_fp = host_task.await.unwrap().unwrap();
            assert_eq!(host_fp, guest_fp, "双侧指纹必须一致（UI 比对基础）");
        }

        #[tokio::test]
        async fn relay_poll_interval_is_sane() {
            assert!(POLL_EVERY.as_millis() >= 100);
        }
    }

    #[test]
    fn pairing_code_shape_and_normalization() {
        for _ in 0..64 {
            let code = generate_pairing_code();
            assert_eq!(code.len(), PAIRING_CODE_LEN);
            assert!(
                code.chars().all(|c| CROCKFORD.contains(&(c as u8))),
                "非法字形: {code}"
            );
        }
        // 易混字形映射 + 分隔符剔除
        assert_eq!(normalize_pairing_code("o i l-u"), "011V");
        assert_eq!(normalize_pairing_code("abcd-efgh"), "ABCDEFGH");
        assert_eq!(
            normalize_pairing_code(&generate_pairing_code()).len(),
            PAIRING_CODE_LEN
        );
    }

    #[test]
    fn full_handshake_delivers_group_key_and_fingerprints_match() {
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let normalized = normalize_pairing_code(&invite.code);
        assert_eq!(normalized, invite.code, "生成的码应已是规范形");
        let (mut guest, offer) = PairingGuest::start(&normalized, &invite.salt).unwrap();
        let host_offer = host.accept_join(&offer.client_public).unwrap();
        let guest_proof = guest.finish(&host_offer.server_public).unwrap();

        assert_eq!(host_offer.fingerprint, guest_proof.fingerprint);
        assert_eq!(host_offer.fingerprint.len(), FINGERPRINT_LEN);
        assert!(
            host_offer.fingerprint.chars().all(|c| c.is_ascii_digit()),
            "指纹应为 6 位数字: {}",
            host_offer.fingerprint
        );

        let group_key: [u8; 32] = rand::random();
        let handoff = host
            .complete(&group_key, &guest_proof.client_proof)
            .unwrap();
        assert_eq!(handoff.wrapped_group_key.len(), WRAPPED_GROUP_KEY_LEN);
        let got = guest
            .accept_handoff(&handoff.server_proof, &handoff.wrapped_group_key)
            .unwrap();
        assert_eq!(got, group_key);
    }

    #[test]
    fn wrong_code_yields_mismatched_fingerprint_and_rejected_proof() {
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        // guest 输错最后一位（Crockford 内合法替换）
        let wrong: String = invite
            .code
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i == PAIRING_CODE_LEN - 1 {
                    if c == 'A' {
                        'B'
                    } else {
                        'A'
                    }
                } else {
                    c
                }
            })
            .collect();
        assert_ne!(wrong, invite.code);
        let (mut guest, offer) = PairingGuest::start(&wrong, &invite.salt).unwrap();
        let host_offer = host.accept_join(&offer.client_public).unwrap();
        let guest_proof = guest.finish(&host_offer.server_public).unwrap();
        assert_ne!(host_offer.fingerprint, guest_proof.fingerprint);

        // 指纹不一致本应被人工拦下；即便误提交，M1 校验也必须拒绝
        let group_key: [u8; 32] = rand::random();
        let err = host
            .complete(&group_key, &guest_proof.client_proof)
            .unwrap_err();
        assert!(matches!(err, PersonaError::AuthenticationFailed(_)));
        // guest 侧同款拒绝：host 从未交出 handoff，guest 直接收假 M2
        let err = guest
            .accept_handoff(&[0u8; 32], &[0u8; WRAPPED_GROUP_KEY_LEN])
            .unwrap_err();
        assert!(matches!(err, PersonaError::AuthenticationFailed(_)));
    }

    #[test]
    fn tampered_handoff_fails_to_open() {
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
        let host_offer = host.accept_join(&offer.client_public).unwrap();
        let guest_proof = guest.finish(&host_offer.server_public).unwrap();
        let group_key: [u8; 32] = rand::random();
        let handoff = host
            .complete(&group_key, &guest_proof.client_proof)
            .unwrap();

        let mut tampered = handoff.wrapped_group_key.clone();
        tampered[20] ^= 0x40;
        let err = guest
            .accept_handoff(&handoff.server_proof, &tampered)
            .unwrap_err();
        assert!(matches!(err, PersonaError::CryptographicError(_)));

        // M2 篡改同样拒绝（独立握手：上一段的失败已消耗 guest 握手态）
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
        let host_offer = host.accept_join(&offer.client_public).unwrap();
        let guest_proof = guest.finish(&host_offer.server_public).unwrap();
        let handoff = host
            .complete(&group_key, &guest_proof.client_proof)
            .unwrap();
        let mut bad_proof = handoff.server_proof.clone();
        bad_proof[0] ^= 0x01;
        let err = guest
            .accept_handoff(&bad_proof, &handoff.wrapped_group_key)
            .unwrap_err();
        assert!(matches!(err, PersonaError::AuthenticationFailed(_)));
    }

    #[test]
    fn handoff_is_single_use_on_both_sides() {
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
        let host_offer = host.accept_join(&offer.client_public).unwrap();
        let guest_proof = guest.finish(&host_offer.server_public).unwrap();
        let group_key: [u8; 32] = rand::random();
        let handoff = host
            .complete(&group_key, &guest_proof.client_proof)
            .unwrap();

        assert!(guest
            .accept_handoff(&handoff.server_proof, &handoff.wrapped_group_key)
            .is_ok());
        // 第二次收交接：握手态已消耗
        let err = guest
            .accept_handoff(&handoff.server_proof, &handoff.wrapped_group_key)
            .unwrap_err();
        assert!(matches!(err, PersonaError::InvalidInput(_)));

        // host 侧 complete 同样一次性
        let err = host
            .complete(&group_key, &guest_proof.client_proof)
            .unwrap_err();
        assert!(matches!(err, PersonaError::InvalidInput(_)));
    }

    #[test]
    fn wire_messages_round_trip_through_relay_payloads() {
        // 消息经 serde JSON 序列化（中转只搬 bytes），双端按序消费
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();

        let json = serde_json::to_string(&PairingMessage::client_public(&offer)).unwrap();
        let msg: PairingMessage = serde_json::from_str(&json).unwrap();
        let PairingMessage::ClientPublic { client_public } = msg else {
            panic!("首条应为 client_public");
        };
        let host_offer = host
            .accept_join(&wire::decode(&client_public).unwrap())
            .unwrap();

        let json = serde_json::to_string(&PairingMessage::server_offer(&host_offer)).unwrap();
        let PairingMessage::ServerOffer { server_public } = serde_json::from_str(&json).unwrap()
        else {
            panic!("应答应为 server_offer");
        };
        let guest_proof = guest
            .finish(&wire::decode(&server_public).unwrap())
            .unwrap();

        let json = serde_json::to_string(&PairingMessage::client_proof(&guest_proof)).unwrap();
        let PairingMessage::ClientProof { client_proof } = serde_json::from_str(&json).unwrap()
        else {
            panic!("第三条应为 client_proof");
        };
        let group_key: [u8; 32] = rand::random();
        let handoff = host
            .complete(&group_key, &wire::decode(&client_proof).unwrap())
            .unwrap();

        let json = serde_json::to_string(&PairingMessage::handoff(&handoff)).unwrap();
        let PairingMessage::Handoff {
            server_proof,
            wrapped_group_key,
        } = serde_json::from_str(&json).unwrap()
        else {
            panic!("末条应为 handoff");
        };
        let got = guest
            .accept_handoff(
                &wire::decode(&server_proof).unwrap(),
                &wire::decode(&wrapped_group_key).unwrap(),
            )
            .unwrap();
        assert_eq!(got, group_key);
    }

    #[test]
    fn message_driver_rejects_wrong_direction_and_completes_pairing() {
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let (mut guest, guest_msg) =
            PairingGuest::start_message(&invite.code, &invite.salt).unwrap();

        // guest 首条消息误投回自己：拒绝
        assert!(guest.handle_message(guest_msg.clone()).is_err());

        let group_key: [u8; 32] = rand::random();
        // host 收首条 → ServerOffer
        let Some(reply) = host.handle_message(guest_msg, &group_key).unwrap() else {
            panic!("host 应答 ServerOffer");
        };
        // guest 收 ServerOffer → ClientProof
        let Some(reply) = guest.handle_message(reply).unwrap() else {
            panic!("guest 应答 ClientProof");
        };
        // host 收 ClientProof → Handoff
        let Some(reply) = host.handle_message(reply, &group_key).unwrap() else {
            panic!("host 应答 Handoff");
        };
        // guest 收 Handoff → None（完成），组密钥落袋
        assert!(guest.handle_message(reply).unwrap().is_none());
        assert_eq!(guest.group_key(), Some(&group_key));

        // 完成后 host 再收任何消息：握手已消耗，拒绝
        let (guest2, msg2) = PairingGuest::start_message(&invite.code, &invite.salt).unwrap();
        drop(guest2);
        assert!(host.handle_message(msg2, &group_key).is_err());
    }

    #[test]
    fn accept_join_rejects_illegal_public_values() {
        let (mut host, _invite) = PairingHost::new_invite().unwrap();
        // 空 client_public → BigUint 0 ≡ 0 (mod N) → 拒绝
        assert!(host.accept_join(&[]).is_err());
        let (mut host2, _invite) = PairingHost::new_invite().unwrap();
        // 全零 client_public 同款拒绝
        assert!(host2.accept_join(&[0u8; 64]).is_err());
    }

    #[test]
    fn double_join_is_rejected() {
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let (guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
        host.accept_join(&offer.client_public).unwrap();
        let (guest2, offer2) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
        let err = host.accept_join(&offer2.client_public).unwrap_err();
        assert!(matches!(err, PersonaError::InvalidInput(_)));
        drop((guest, guest2));
    }
}
