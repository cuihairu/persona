//! 真实 SRP-6a 设备认证（RFC 5054）——E2EE 同步轨道阶段 1 的产品路径。
//!
//! 与 [`super::remote`] 的 mock（`RemoteAuthProvider` UI seam）互补：那边
//! 保持协议无关的离线占位，本模块提供跨端（CLI/desktop ↔ server）可用的
//! 完整握手原语。客户端与服务器两侧逻辑都在这里，server crate 复用
//! [`server_challenge`] / [`server_verify`]（persona-server 依赖 persona-core）。
//!
//! 安全设计：
//! - **Argon2id 预 hash**（[`derive_srp_secret`]）：进入 SRP 的「password」
//!   是 `Argon2id(主密码, domain ‖ salt)` 的派生值——服务器只存 SRP verifier，
//!   verifier 泄露后的离线爆破成本 ≈ Argon2 成本（设计稿 E2EE_SYNC_DESIGN
//!   DR-2）。域分隔前缀把它与本地库解锁、备份加密的 KDF 互为不同协议域。
//! - **RFC 5054 4096-bit group**（[`srp_group()`]）；SHA-256 作为握手哈希。
//! - 数学实现交给 RustCrypto `srp` crate；正确性由 RFC 5054 附录 B 官方
//!   测试向量（SHA-1/1024-bit interop 向量）与本模块 round-trip 测试共同
//!   锁定——换实现时向量测试即回归闸。

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngExt;
use sha2::Sha256;
use srp::client::SrpClient;
use srp::groups::G_4096;
use srp::server::SrpServer;
use srp::types::SrpGroup;

use crate::{PersonaError, PersonaResult};

/// 生产用 group：RFC 5054 4096-bit prime（登记于设计稿 DR-2）。
/// srp crate 经 lazy_static 提供，运行时取引用。
pub fn srp_group() -> &'static SrpGroup {
    &G_4096
}

/// 客户端临时私钥字节数（srp crate 文档建议 64 字节）。
const CLIENT_EPHEMERAL_LEN: usize = 64;

/// 服务器临时私钥字节数。
const SERVER_EPHEMERAL_LEN: usize = 32;

/// SRP salt 字节数（srp crate 文档建议约 32 字节）。
pub const SRP_SALT_LEN: usize = 32;

/// SRP 私钥派生的域分隔前缀。
const SRP_KDF_DOMAIN: &[u8] = b"persona-srp-v1";

/// Argon2id 预 hash：从主密码派生进入 SRP 协议的「password」字节串。
///
/// 盐 = `persona-srp-v1 ‖ 服务器下发 salt`，参数与本地密码验证同族
/// （argon2 crate 默认：Argon2id v19，m=19 MiB，t=2，p=1）。同一
/// （password, salt）必然得到同一派生值——注册与登录两侧都经由此函数。
pub fn derive_srp_secret(password: &str, salt: &[u8]) -> PersonaResult<[u8; 32]> {
    let mut domain_salt = Vec::with_capacity(SRP_KDF_DOMAIN.len() + salt.len());
    domain_salt.extend_from_slice(SRP_KDF_DOMAIN);
    domain_salt.extend_from_slice(salt);
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
        .hash_password_into(password.as_bytes(), &domain_salt, &mut out)
        .map_err(|e| PersonaError::CryptographicError(format!("SRP KDF failed: {e}")))?;
    Ok(out)
}

/// 注册产物：上传服务器持久化的 (salt, verifier)。服务器**永不**接触
/// 主密码或 Argon2 派生值。
#[derive(Debug, Clone)]
pub struct SrpRegistration {
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
}

/// 生成注册材料：随机 salt + SRP verifier（v = g^x mod N）。
pub fn register_verifier(username: &str, password: &str) -> PersonaResult<SrpRegistration> {
    let mut salt = vec![0u8; SRP_SALT_LEN];
    rand::rng().fill(&mut salt);
    let srp_secret = derive_srp_secret(password, &salt)?;
    let verifier = SrpClient::<Sha256>::new(srp_group()).compute_verifier(
        username.as_bytes(),
        &srp_secret,
        &salt,
    );
    Ok(SrpRegistration { salt, verifier })
}

/// 登录客户端第一侧：生成临时密钥对，公开值随 challenge 请求发出。
#[derive(Debug)]
pub struct SrpClientLogin {
    a_priv: Vec<u8>,
    a_pub: Vec<u8>,
}

impl SrpClientLogin {
    /// 新建一次登录：随机客户端临时私钥。
    pub fn new() -> PersonaResult<Self> {
        let mut a_priv = vec![0u8; CLIENT_EPHEMERAL_LEN];
        rand::rng().fill(&mut a_priv);
        let a_pub = SrpClient::<Sha256>::new(srp_group()).compute_public_ephemeral(&a_priv);
        Ok(Self {
            a_priv,
            a_pub: a_pub.to_vec(),
        })
    }

    /// 客户端公开值 `A`（hex 编码由传输层负责）。
    pub fn public_ephemeral(&self) -> &[u8] {
        &self.a_pub
    }

    /// 处理 challenge 响应 (salt, B)：派生 SRP 私钥并计算客户端证明 M1。
    ///
    /// `server_public` 为恶意值（如与 group 冲突）时返回
    /// [`PersonaError::AuthenticationFailed`]——srp crate 会拒绝非法 B。
    pub fn process(
        self,
        username: &str,
        password: &str,
        salt: &[u8],
        server_public: &[u8],
    ) -> PersonaResult<SrpClientProof> {
        let srp_secret = derive_srp_secret(password, salt)?;
        let verifier = SrpClient::<Sha256>::new(srp_group())
            .process_reply(
                &self.a_priv,
                username.as_bytes(),
                &srp_secret,
                salt,
                server_public,
            )
            .map_err(|_| {
                PersonaError::AuthenticationFailed(
                    "SRP handshake rejected server public value".to_string(),
                )
            })?;
        // proof 先取（verifier 随后 move 进返回结构）
        let client_proof = verifier.proof().to_vec();
        Ok(SrpClientProof {
            verifier,
            client_proof,
        })
    }
}

/// 客户端证明与对端校验状态：M1 已就绪，M2 待服务器响应后核验。
pub struct SrpClientProof {
    verifier: srp::client::SrpClientVerifier<Sha256>,
    client_proof: Vec<u8>,
}

impl SrpClientProof {
    /// 客户端证明 `M1`（发给 /auth/verify）。
    pub fn client_proof(&self) -> &[u8] {
        &self.client_proof
    }

    /// 核验服务器证明 `M2`；通过即完成双向认证，返回会话密钥
    /// （SRP-6a premaster 的原始字节，长度 = group 模数字节数，
    /// 4096-bit group 下为 512B——用作密钥材料前应再经 KDF 派生）。
    /// M2 不匹配 = 中间人/服务器降级，返回 [`PersonaError::AuthenticationFailed`]。
    pub fn verify_server(self, server_proof: &[u8]) -> PersonaResult<Vec<u8>> {
        self.verifier
            .verify_server(server_proof)
            .map_err(|_| PersonaError::AuthenticationFailed("server proof mismatch".to_string()))?;
        Ok(self.verifier.key().to_vec())
    }
}

/// 服务器 challenge 产物：临时私钥留在服务器会话缓存，公开值下发。
#[derive(Debug)]
pub struct SrpServerChallenge {
    pub b_priv: Vec<u8>,
    pub b_pub: Vec<u8>,
}

/// 以存储的 verifier 发起 challenge：生成服务器临时密钥对。
pub fn server_challenge(verifier: &[u8]) -> PersonaResult<SrpServerChallenge> {
    let mut b_priv = vec![0u8; SERVER_EPHEMERAL_LEN];
    rand::rng().fill(&mut b_priv);
    let b_pub = SrpServer::<Sha256>::new(srp_group()).compute_public_ephemeral(&b_priv, verifier);
    Ok(SrpServerChallenge {
        b_priv,
        b_pub: b_pub.to_vec(),
    })
}

/// 服务器验证结果：M2 下发 + 会话密钥（与客户端 [`SrpClientProof::verify_server`]
/// 返回值一致）。
#[derive(Debug)]
pub struct SrpServerOutcome {
    pub server_proof: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// 核验客户端证明 M1：匹配则产出服务器证明与会话密钥。
/// M1 不匹配 = 口令错误或伪造，返回 [`PersonaError::AuthenticationFailed`]。
pub fn server_verify(
    b_priv: &[u8],
    verifier: &[u8],
    client_public: &[u8],
    client_proof: &[u8],
) -> PersonaResult<SrpServerOutcome> {
    let sv = SrpServer::<Sha256>::new(srp_group())
        .process_reply(b_priv, verifier, client_public)
        .map_err(|_| {
            PersonaError::AuthenticationFailed(
                "SRP handshake rejected client public value".to_string(),
            )
        })?;
    sv.verify_client(client_proof)
        .map_err(|_| PersonaError::AuthenticationFailed("client proof mismatch".to_string()))?;
    Ok(SrpServerOutcome {
        server_proof: sv.proof().to_vec(),
        session_key: sv.key().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use srp::groups::G_1024;

    /// RFC 5054 附录 B interop 向量（1024-bit group，SHA-1）。
    /// 固定 a/b/盐，对拍 A、B 与 premaster S——换 SRP 实现时的回归闸。
    #[test]
    fn rfc5054_appendix_b_interop_vector() {
        use sha1::Sha1;

        let username = b"alice";
        let password = b"password123";
        let salt = hex::decode("BEB25379D1A8581EB5A727673A2441EE").unwrap();
        let a_priv =
            hex::decode("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393")
                .unwrap();
        let b_priv =
            hex::decode("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20")
                .unwrap();

        let client = SrpClient::<Sha1>::new(&G_1024);
        let server = SrpServer::<Sha1>::new(&G_1024);

        let a_pub = client.compute_public_ephemeral(&a_priv);
        assert_eq!(
            hex::encode(&a_pub).to_uppercase(),
            "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"
        );

        let v = client.compute_verifier(username, password, &salt);
        let b_pub = server.compute_public_ephemeral(&b_priv, &v);
        assert_eq!(
            hex::encode(&b_pub).to_uppercase(),
            "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58"
        );

        let client_v = client
            .process_reply(&a_priv, username, password, &salt, &b_pub)
            .unwrap();
        let server_v = server.process_reply(&b_priv, &v, &a_pub).unwrap();

        // 两侧证明互验 + premaster 相等（RFC 向量 S）
        server_v.verify_client(client_v.proof()).unwrap();
        client_v.verify_server(server_v.proof()).unwrap();
        assert_eq!(
            hex::encode(client_v.key()).to_uppercase(),
            "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"
        );
        assert_eq!(client_v.key().to_vec(), server_v.key().to_vec());
    }

    /// 产品路径全流程：注册 → challenge → 客户端证明 → 服务器验证 →
    /// 双向核验完成，两侧会话密钥一致（生产 group + SHA-256 + Argon2 预 hash）。
    #[test]
    fn product_flow_round_trip_yields_matching_session_keys() {
        let username = "laptop";
        let password = "correct horse battery staple";

        let registration = register_verifier(username, password).unwrap();
        assert_eq!(registration.salt.len(), SRP_SALT_LEN);

        let client_login = SrpClientLogin::new().unwrap();
        // A 必须在 process 消耗登录状态前取出（server_verify 需要）
        let a_pub = client_login.public_ephemeral().to_vec();
        let challenge = server_challenge(&registration.verifier).unwrap();

        let proof = client_login
            .process(username, password, &registration.salt, &challenge.b_pub)
            .unwrap();
        let outcome = server_verify(
            &challenge.b_priv,
            &registration.verifier,
            &a_pub,
            proof.client_proof(),
        )
        .unwrap();

        let client_key = proof.verify_server(&outcome.server_proof).unwrap();
        assert_eq!(client_key, outcome.session_key);
    }

    /// 错误口令：客户端能算出 M1（SRP 数学上无「客户端侧失败」），
    /// 但服务器 verify_client 必拒绝。
    #[test]
    fn product_flow_rejects_wrong_password() {
        let registration = register_verifier("laptop", "right-password").unwrap();
        let client_login = SrpClientLogin::new().unwrap();
        let a_pub = client_login.public_ephemeral().to_vec();
        let challenge = server_challenge(&registration.verifier).unwrap();

        let proof = client_login
            .process(
                "laptop",
                "wrong-password",
                &registration.salt,
                &challenge.b_pub,
            )
            .unwrap();
        let err = server_verify(
            &challenge.b_priv,
            &registration.verifier,
            &a_pub,
            proof.client_proof(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("client proof mismatch"));
    }

    /// 服务器证明被篡改：客户端 verify_server 必拒（防恶意服务器/中间人）。
    #[test]
    fn product_flow_rejects_tampered_server_proof() {
        let registration = register_verifier("laptop", "some-password").unwrap();
        let client_login = SrpClientLogin::new().unwrap();
        let a_pub = client_login.public_ephemeral().to_vec();
        let challenge = server_challenge(&registration.verifier).unwrap();

        let proof = client_login
            .process(
                "laptop",
                "some-password",
                &registration.salt,
                &challenge.b_pub,
            )
            .unwrap();
        let outcome = server_verify(
            &challenge.b_priv,
            &registration.verifier,
            &a_pub,
            proof.client_proof(),
        )
        .unwrap();
        let mut bad_proof = outcome.server_proof.clone();
        bad_proof[0] ^= 0xFF;
        let err = proof.verify_server(&bad_proof).unwrap_err();
        assert!(err.to_string().contains("server proof mismatch"));
    }

    /// Argon2id 预 hash：确定性 + 域分隔（同盐同输出、异盐异输出）。
    #[test]
    fn derive_srp_secret_is_deterministic_and_domain_separated() {
        let a = derive_srp_secret("pw", b"salt-1").unwrap();
        let b = derive_srp_secret("pw", b"salt-1").unwrap();
        let c = derive_srp_secret("pw", b"salt-2").unwrap();
        let d = derive_srp_secret("other", b"salt-1").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }
}
