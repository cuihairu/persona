//! Real SRP-6a device authentication (RFC 5054) — the product path for phase 1
//! of the E2EE sync track.
//!
//! Complements the mock in [`super::remote`] (the `RemoteAuthProvider` UI
//! seam): that one stays a protocol-agnostic offline placeholder, while this
//! module provides usable cross-platform (CLI/desktop <-> server) handshake
//! primitives. Both client- and server-side logic live here; the server crate
//! reuses [`server_challenge`] / [`server_verify`] (persona-server depends on
//! persona-core).
//!
//! Security design:
//! - **Argon2id pre-hash** ([`derive_srp_secret`]): the "password" fed into
//!   SRP is the derived value `Argon2id(master password, domain || salt)` —
//!   the server only stores the SRP verifier, so offline cracking of a leaked
//!   verifier costs roughly the Argon2 cost (design doc E2EE_SYNC_DESIGN
//!   DR-2). The domain-separation prefix keeps it in a distinct protocol
//!   domain from the local vault unlock and backup encryption KDFs.
//! - **RFC 5054 4096-bit group** ([`srp_group()`]); SHA-256 as the handshake
//!   hash.
//! - The math implementation is inlined in this module: the `srp` crate is
//!   stuck in the digest 0.10 ecosystem, and its 0.7-rc series stopped
//!   compiling as dependencies drifted, so it could not follow the digest
//!   0.11 migration; the formulas of its 0.6 version (u/k/x/premaster/M1/M2,
//!   `to_bytes_be` minimal big-endian) were therefore replicated line by line
//!   and inlined. The public API keeps the same shape as before the drift;
//!   correctness is pinned by the official RFC 5054 Appendix B test vectors
//!   (SHA-1/1024-bit interop vectors) together with this module's round-trip
//!   tests — the vector tests are the regression gate when swapping
//!   implementations.
//! - Trade-off: `num-bigint`'s modpow is not constant-time; the temporary
//!   exponents entering the modular exponentiation expose a side channel
//!   under same-host high-precision timing. The password entering SRP is
//!   already an Argon2id-derived value (see above), so a leaked verifier does
//!   not lead back to the master password; tightening later means switching
//!   to a constant-time big-integer library and redoing the modpow (with an
//!   unchanged interface).

use std::marker::PhantomData;
use std::sync::LazyLock;

use argon2::{Algorithm, Argon2, Params, Version};
use num_bigint::BigUint;
use rand::RngExt;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{PersonaError, PersonaResult};

/// SRP group parameters (N is a large prime, g a generator). Fields are
/// public: callers (the remote_http comparison tests) read `n` directly for
/// byte-level assertions.
pub struct SrpGroup {
    pub n: BigUint,
    pub g: BigUint,
}

/// RFC 5054 Appendix A 1024-bit group (for vector tests and legacy
/// compatibility only), g = 2.
pub static G_1024: LazyLock<SrpGroup> = LazyLock::new(|| SrpGroup {
    n: BigUint::from_bytes_be(&hex_1024()),
    g: BigUint::from_bytes_be(&[2]),
});

/// Production group: RFC 5054 4096-bit prime, g = 5 (as recorded in design doc DR-2).
static G_4096: LazyLock<SrpGroup> = LazyLock::new(|| SrpGroup {
    n: BigUint::from_bytes_be(&hex_4096()),
    g: BigUint::from_bytes_be(&[5]),
});

/// Runtime accessor for the production group.
pub fn srp_group() -> &'static SrpGroup {
    &G_4096
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn hex_1024() -> Vec<u8> {
    hex_bytes(
        "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576\
         D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1\
         5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC\
         68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
    )
}

fn hex_4096() -> Vec<u8> {
    hex_bytes(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
         020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
         4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
         EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
         98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
         9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
         E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
         3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
         A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
         ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
         D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
         08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
         88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8\
         DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
         233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
         93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
    )
}

/// Length in bytes of the client's ephemeral private key (the srp crate docs suggest 64 bytes).
const CLIENT_EPHEMERAL_LEN: usize = 64;

/// Length in bytes of the server's ephemeral private key.
const SERVER_EPHEMERAL_LEN: usize = 32;

/// SRP salt length in bytes (the srp crate docs suggest roughly 32 bytes).
pub const SRP_SALT_LEN: usize = 32;

/// Domain-separation prefix for SRP private key derivation.
const SRP_KDF_DOMAIN: &[u8] = b"persona-srp-v1";

/// Argon2id pre-hash: derives the "password" byte string fed into the SRP
/// protocol from the master password.
///
/// Salt = `persona-srp-v1 || server-issued salt`, with parameters in the same
/// family as local password verification (argon2 crate defaults: Argon2id
/// v19, m=19 MiB, t=2, p=1). The same (password, salt) pair always yields the
/// same derived value — both registration and login go through this
/// function.
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

/// Registration artifact: the (salt, verifier) uploaded to and persisted by
/// the server. The server **never** sees the master password or the Argon2
/// derived value.
#[derive(Debug, Clone)]
pub struct SrpRegistration {
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
}

// --- SRP-6a math core (formulas identical line-for-line to srp 0.6) ---

/// u = H(A || B), with both sides' bytes in minimal unsigned representation.
fn compute_u<D: Digest>(a_pub: &[u8], b_pub: &[u8]) -> BigUint {
    let mut u = D::new();
    u.update(a_pub);
    u.update(b_pub);
    BigUint::from_bytes_be(&u.finalize())
}

/// k = H(N || pad_N(g)) — g is left-padded with zeros to N's byte length.
fn compute_k<D: Digest>(params: &SrpGroup) -> BigUint {
    let n = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();
    let mut buf = vec![0u8; n.len()];
    let l = n.len() - g_bytes.len();
    buf[l..].copy_from_slice(&g_bytes);

    let mut d = D::new();
    d.update(&n);
    d.update(&buf);
    BigUint::from_bytes_be(&d.finalize())
}

/// The premaster is left-padded with zeros to the group modulus byte length
/// (RFC 5054: S participates in M1/M2 derivation at N's full width). Without
/// the padding, `to_bytes_be` strips leading zeros, making the session key
/// length drift between 511/512 (~1/256 of the time) and violating the
/// "length = modulus byte count" contract.
fn padded_premaster(params: &SrpGroup, key: &BigUint) -> Vec<u8> {
    let len = params.n.bits().div_ceil(8) as usize;
    let raw = key.to_bytes_be();
    let mut buf = vec![0u8; len];
    buf[len - raw.len()..].copy_from_slice(&raw);
    buf
}

/// M1 = H(A ‖ B ‖ S)。
fn compute_m1<D: Digest>(a_pub: &[u8], b_pub: &[u8], key: &[u8]) -> Vec<u8> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize().to_vec()
}

/// M2 = H(A ‖ M1 ‖ S)。
fn compute_m2<D: Digest>(a_pub: &[u8], m1: &[u8], key: &[u8]) -> Vec<u8> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(m1);
    d.update(key);
    d.finalize().to_vec()
}

/// x = H(salt || H(I || ":" || P)).
fn compute_identity_hash<D: Digest>(username: &[u8], password: &[u8]) -> Vec<u8> {
    let mut d = D::new();
    d.update(username);
    d.update(b":");
    d.update(password);
    d.finalize().to_vec()
}

fn compute_x<D: Digest>(identity_hash: &[u8], salt: &[u8]) -> BigUint {
    let mut x = D::new();
    x.update(salt);
    x.update(identity_hash);
    BigUint::from_bytes_be(&x.finalize())
}

/// Client-side SRP-6a handshake (`D` is the handshake hash; production uses [`Sha256`]).
pub struct SrpClient<'a, D: Digest> {
    params: &'a SrpGroup,
    _d: PhantomData<D>,
}

/// Client proof state: M1/M2 are ready, and the session key is held until peer verification completes.
pub struct SrpClientVerifier<D: Digest> {
    m1: Vec<u8>,
    m2: Vec<u8>,
    key: Vec<u8>,
    _d: PhantomData<D>,
}

impl<D: Digest> SrpClientVerifier<D> {
    /// The client proof M1.
    pub fn proof(&self) -> &[u8] {
        &self.m1
    }

    /// Session key (the premaster left-padded to the group modulus byte
    /// length; always 512B under the 4096-bit group. Should be re-derived
    /// through a KDF before use as key material).
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verify the server proof M2; a mismatch means man-in-the-middle or downgrade.
    pub fn verify_server(&self, server_proof: &[u8]) -> Result<(), String> {
        if self.m2.ct_eq(server_proof).unwrap_u8() != 1 {
            Err("server proof mismatch".to_string())
        } else {
            Ok(())
        }
    }
}

impl<'a, D: Digest> SrpClient<'a, D> {
    pub fn new(params: &'a SrpGroup) -> Self {
        Self {
            params,
            _d: PhantomData,
        }
    }

    fn compute_a_pub(&self, a: &BigUint) -> BigUint {
        self.params.g.modpow(a, &self.params.n)
    }

    fn premaster(
        &self,
        b_pub: &BigUint,
        k: &BigUint,
        x: &BigUint,
        a: &BigUint,
        u: &BigUint,
    ) -> BigUint {
        let base = (k * self.params.g.modpow(x, &self.params.n)) % &self.params.n;
        let base = ((&self.params.n + b_pub) - &base) % &self.params.n;
        let exp = (u * x) + a;
        base.modpow(&exp, &self.params.n)
    }

    /// v = g^x mod N (registration verifier).
    pub fn compute_verifier(&self, username: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {
        let identity_hash = compute_identity_hash::<D>(username, password);
        let x = compute_x::<D>(&identity_hash, salt);
        self.compute_a_pub(&x).to_bytes_be()
    }

    /// A = g^a mod N.
    pub fn compute_public_ephemeral(&self, a: &[u8]) -> Vec<u8> {
        self.compute_a_pub(&BigUint::from_bytes_be(a)).to_bytes_be()
    }

    /// Process the server's (B): derive the premaster and both proofs.
    /// Rejects B == 0 (mod N) (an illegal public value).
    pub fn process_reply(
        &self,
        a: &[u8],
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub: &[u8],
    ) -> Result<SrpClientVerifier<D>, String> {
        let a = BigUint::from_bytes_be(a);
        let a_pub = self.compute_a_pub(&a);
        let b_pub = BigUint::from_bytes_be(b_pub);

        if &b_pub % &self.params.n == BigUint::default() {
            return Err("illegal b_pub".to_string());
        }

        let u = compute_u::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());
        let k = compute_k::<D>(self.params);
        let identity_hash = compute_identity_hash::<D>(username, password);
        let x = compute_x::<D>(&identity_hash, salt);

        let key = self.premaster(&b_pub, &k, &x, &a, &u);
        let key_bytes = padded_premaster(self.params, &key);

        let m1 = compute_m1::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be(), &key_bytes);
        let m2 = compute_m2::<D>(&a_pub.to_bytes_be(), &m1, &key_bytes);

        Ok(SrpClientVerifier {
            m1,
            m2,
            key: key_bytes,
            _d: PhantomData,
        })
    }
}

/// Server-side SRP-6a handshake (`D` is the handshake hash; production uses [`Sha256`]).
pub struct SrpServer<'a, D: Digest> {
    params: &'a SrpGroup,
    _d: PhantomData<D>,
}

/// Server verification state: after M1 checks out, M2 and the session key are issued.
pub struct SrpServerVerifier<D: Digest> {
    m1: Vec<u8>,
    m2: Vec<u8>,
    key: Vec<u8>,
    _d: PhantomData<D>,
}

impl<D: Digest> SrpServerVerifier<D> {
    /// Session key (identical to what the client's `verify_server` returns;
    /// length = group modulus byte count).
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The server proof M2.
    pub fn proof(&self) -> &[u8] {
        &self.m2
    }

    /// Verify the client proof M1 (constant-time comparison); a mismatch means a wrong password or a forgery.
    pub fn verify_client(&self, reply: &[u8]) -> Result<(), String> {
        if self.m1.ct_eq(reply).unwrap_u8() != 1 {
            Err("client proof mismatch".to_string())
        } else {
            Ok(())
        }
    }
}

impl<'a, D: Digest> SrpServer<'a, D> {
    pub fn new(params: &'a SrpGroup) -> Self {
        Self {
            params,
            _d: PhantomData,
        }
    }

    fn compute_b_pub(&self, b: &BigUint, k: &BigUint, v: &BigUint) -> BigUint {
        let inter = (k * v) % &self.params.n;
        (inter + self.params.g.modpow(b, &self.params.n)) % &self.params.n
    }

    fn premaster(&self, a_pub: &BigUint, v: &BigUint, u: &BigUint, b: &BigUint) -> BigUint {
        let base = (a_pub * v.modpow(u, &self.params.n)) % &self.params.n;
        base.modpow(b, &self.params.n)
    }

    /// B = (k*v + g^b) mod N.
    pub fn compute_public_ephemeral(&self, b: &[u8], v: &[u8]) -> Vec<u8> {
        self.compute_b_pub(
            &BigUint::from_bytes_be(b),
            &compute_k::<D>(self.params),
            &BigUint::from_bytes_be(v),
        )
        .to_bytes_be()
    }

    /// Process the client's A: derive the premaster and both proofs.
    /// Rejects A == 0 (mod N) (an illegal public value).
    pub fn process_reply(
        &self,
        b: &[u8],
        v: &[u8],
        a_pub: &[u8],
    ) -> Result<SrpServerVerifier<D>, String> {
        let b = BigUint::from_bytes_be(b);
        let v = BigUint::from_bytes_be(v);
        let a_pub = BigUint::from_bytes_be(a_pub);

        let k = compute_k::<D>(self.params);
        let b_pub = self.compute_b_pub(&b, &k, &v);

        if &a_pub % &self.params.n == BigUint::default() {
            return Err("illegal a_pub".to_string());
        }

        let u = compute_u::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());
        let key = self.premaster(&a_pub, &v, &u, &b);
        let key_bytes = padded_premaster(self.params, &key);

        let m1 = compute_m1::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be(), &key_bytes);
        let m2 = compute_m2::<D>(&a_pub.to_bytes_be(), &m1, &key_bytes);

        Ok(SrpServerVerifier {
            m1,
            m2,
            key: key_bytes,
            _d: PhantomData,
        })
    }
}

// --- Product wrapper layer (public API unchanged from before the drift) ---

/// Generate registration material: random salt + SRP verifier (v = g^x mod N).
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

/// Login, client side one: generates the ephemeral key pair; the public value goes out with the challenge request.
#[derive(Debug)]
pub struct SrpClientLogin {
    a_priv: Vec<u8>,
    a_pub: Vec<u8>,
}

impl SrpClientLogin {
    /// Start a new login: random client ephemeral private key.
    pub fn new() -> PersonaResult<Self> {
        let mut a_priv = vec![0u8; CLIENT_EPHEMERAL_LEN];
        rand::rng().fill(&mut a_priv);
        let a_pub = SrpClient::<Sha256>::new(srp_group()).compute_public_ephemeral(&a_priv);
        Ok(Self { a_priv, a_pub })
    }

    /// The client's public value `A` (hex encoding is the transport layer's job).
    pub fn public_ephemeral(&self) -> &[u8] {
        &self.a_pub
    }

    /// Process the challenge response (salt, B): derive the SRP private key
    /// and compute the client proof M1.
    ///
    /// Returns [`PersonaError::AuthenticationFailed`] if `server_public` is a
    /// malicious value (e.g. inconsistent with the group).
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
        // Take the proof first (the verifier is then moved into the returned struct)
        let client_proof = verifier.proof().to_vec();
        Ok(SrpClientProof {
            verifier,
            client_proof,
        })
    }
}

/// Client proof and peer-verification state: M1 is ready; M2 is verified once the server responds.
pub struct SrpClientProof {
    verifier: SrpClientVerifier<Sha256>,
    client_proof: Vec<u8>,
}

impl SrpClientProof {
    /// The client proof `M1` (sent to /auth/verify).
    pub fn client_proof(&self) -> &[u8] {
        &self.client_proof
    }

    /// Verify the server proof `M2`; on success mutual authentication is
    /// complete and the session key is returned (the raw SRP-6a premaster
    /// bytes; length = group modulus byte count, 512B under the 4096-bit
    /// group — re-derive through a KDF before using as key material). An M2
    /// mismatch = man-in-the-middle / server downgrade; returns
    /// [`PersonaError::AuthenticationFailed`].
    pub fn verify_server(self, server_proof: &[u8]) -> PersonaResult<Vec<u8>> {
        self.verifier
            .verify_server(server_proof)
            .map_err(|_| PersonaError::AuthenticationFailed("server proof mismatch".to_string()))?;
        Ok(self.verifier.key().to_vec())
    }
}

/// Server challenge artifact: the ephemeral private key stays in the server's session cache; the public value is sent down.
#[derive(Debug)]
pub struct SrpServerChallenge {
    pub b_priv: Vec<u8>,
    pub b_pub: Vec<u8>,
}

/// Issue a challenge from the stored verifier: generates the server's ephemeral key pair.
pub fn server_challenge(verifier: &[u8]) -> PersonaResult<SrpServerChallenge> {
    let mut b_priv = vec![0u8; SERVER_EPHEMERAL_LEN];
    rand::rng().fill(&mut b_priv);
    let b_pub = SrpServer::<Sha256>::new(srp_group()).compute_public_ephemeral(&b_priv, verifier);
    Ok(SrpServerChallenge { b_priv, b_pub })
}

/// Server verification result: M2 to send down plus the session key
/// (identical to what the client's [`SrpClientProof::verify_server`]
/// returns).
#[derive(Debug)]
pub struct SrpServerOutcome {
    pub server_proof: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// Verify the client proof M1: on a match, produces the server proof and the
/// session key. An M1 mismatch = wrong password or forgery; returns
/// [`PersonaError::AuthenticationFailed`].
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

    /// RFC 5054 Appendix B interop vector (1024-bit group, SHA-1).
    /// Fixed a/b/salt, cross-checking A, B, and the premaster S — the
    /// regression gate when swapping SRP implementations.
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

        // Both proofs verify against each other + premaster equality (RFC vector S)
        server_v.verify_client(client_v.proof()).unwrap();
        client_v.verify_server(server_v.proof()).unwrap();
        assert_eq!(
            hex::encode(client_v.key()).to_uppercase(),
            "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"
        );
        assert_eq!(client_v.key().to_vec(), server_v.key().to_vec());
    }

    /// Full product-path flow: register -> challenge -> client proof ->
    /// server verification -> mutual verification complete, with both session
    /// keys matching (production group + SHA-256 + Argon2 pre-hash).
    #[test]
    fn product_flow_round_trip_yields_matching_session_keys() {
        let username = "laptop";
        let password = "correct horse battery staple";

        let registration = register_verifier(username, password).unwrap();
        assert_eq!(registration.salt.len(), SRP_SALT_LEN);

        let client_login = SrpClientLogin::new().unwrap();
        // A must be taken out before process consumes the login state (server_verify needs it)
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
        // Contract: the premaster is always the group modulus byte count (4096-bit group = 512B)
        assert_eq!(client_key.len(), 512);
    }

    /// Wrong password: the client can still compute M1 (SRP math has no
    /// "client-side failure"), but the server's verify_client must reject.
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

    /// Tampered server proof: the client's verify_server must reject (guards against a malicious server / man-in-the-middle).
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

    /// Argon2id pre-hash: determinism + domain separation (same salt, same output; different salt, different output).
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
