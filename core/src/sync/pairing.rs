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
        Ok(GuestProof {
            fingerprint,
            client_proof: proof,
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

#[cfg(test)]
mod tests {
    use super::*;

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
