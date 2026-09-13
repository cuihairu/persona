// WebAuthn software-authenticator primitives (ES256 / P-256 only).
//
// Persona acts as a passkey provider: registration produces a `none`-format
// attestation, authentication produces an assertion over
// `authenticatorData || SHA-256(clientDataJSON)`. COSE/CBOR encoding is
// delegated to the audited `coset` crate and ECDSA to `p256`; the relying
// party side of these flows is exercised in tests against `webauthn-rs`.

use crate::models::passkey::PasskeyItem;
use crate::{PersonaError, PersonaResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use coset::cbor::value::Value;
use coset::{iana, CborSerializable, CoseKey, CoseKeyBuilder};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

/// client data `type` for credential creation (WebAuthn §5.8.1)
pub const CLIENT_DATA_TYPE_CREATE: &str = "webauthn.create";
/// client data `type` for authentication (WebAuthn §5.8.1)
pub const CLIENT_DATA_TYPE_GET: &str = "webauthn.get";

// authenticator data flag bits (WebAuthn §6.1)
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

/// Fixed Persona AAGUID identifying the software authenticator.
pub fn aaguid() -> [u8; 16] {
    PasskeyItem::aaguid()
}

/// 32 random bytes — user handles, challenges and credential IDs.
pub fn random_bytes32() -> [u8; 32] {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).expect("failed to generate random bytes");
    out
}

/// Build a clientDataJSON with a locally generated challenge. CLI-created
/// credentials have no live RP; the challenge only needs to be unpredictable.
pub fn local_client_data(ceremony: &str, origin: &str) -> PersonaResult<Vec<u8>> {
    let challenge = URL_SAFE_NO_PAD.encode(random_bytes32());
    Ok(
        format!(r#"{{"type":"{ceremony}","challenge":"{challenge}","origin":"{origin}"}}"#)
            .into_bytes(),
    )
}

/// Build a clientDataJSON for a self-test assertion ceremony (the challenge
/// is generated here; the RP normally provides it).
pub fn self_test_client_data(origin: &str) -> PersonaResult<Vec<u8>> {
    local_client_data(CLIENT_DATA_TYPE_GET, origin)
}

/// The subset of `PublicKeyCredentialCreationOptions` the authenticator acts on.
#[derive(Debug, Clone)]
pub struct ParsedCreationOptions {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
}

/// Parse the JSON form of `PublicKeyCredentialCreationOptions` as forwarded by
/// the browser extension (bridge protocol v2 `passkey_create`).
///
/// Only ES256 is accepted — a request whose `pubKeyCredParams` lacks
/// `alg: -7` is rejected. When the RP omits `rp.id`, the origin's effective
/// host is used (WebAuthn §5.4). `user.id` must be a base64url string (the
/// extension serializes BufferSource bytes before forwarding).
pub fn parse_creation_options(
    options: &serde_json::Value,
    origin: &str,
) -> PersonaResult<ParsedCreationOptions> {
    let params = options.get("pubKeyCredParams").and_then(|v| v.as_array());
    let es256 = params.is_some_and(|params| {
        params.iter().any(|p| {
            p.get("type").and_then(|v| v.as_str()) == Some("public-key")
                && p.get("alg").and_then(|v| v.as_i64()) == Some(crate::models::passkey::ES256_ALG)
        })
    });
    if !es256 {
        return Err(PersonaError::InvalidInput(
            "passkey_alg_unsupported: pubKeyCredParams must include ES256 (alg -7)".to_string(),
        ));
    }

    let user = options
        .get("user")
        .ok_or_else(|| PersonaError::InvalidInput("invalid_request: missing user".to_string()))?;
    let user_id_b64 = user.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        PersonaError::InvalidInput(
            "invalid_request: user.id must be a base64url string".to_string(),
        )
    })?;
    let user_handle = decode_b64url(user_id_b64)?;
    if user_handle.is_empty() || user_handle.len() > 64 {
        return Err(PersonaError::InvalidInput(
            "invalid_request: user.id must be 1..=64 bytes (WebAuthn §5.4.2)".to_string(),
        ));
    }

    let rp_id = match options
        .get("rp")
        .and_then(|rp| rp.get("id"))
        .and_then(|v| v.as_str())
    {
        Some(id) => id.to_string(),
        None => origin_host(origin)?,
    };

    Ok(ParsedCreationOptions {
        rp_id,
        rp_name: options
            .get("rp")
            .and_then(|rp| rp.get("name"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        user_handle,
        user_name: user
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        user_display_name: user
            .get("displayName")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// Decode base64url with or without padding.
fn decode_b64url(s: &str) -> PersonaResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .map_err(|e| PersonaError::InvalidInput(format!("invalid base64url encoding: {e}")))
}

/// Successful registration: everything an RP needs plus the key to persist.
#[derive(Debug)]
pub struct RegistrationOutput {
    /// Newly generated private key (caller encrypts and stores it)
    pub signing_key: SigningKey,
    /// Random 32-byte credential ID
    pub credential_id: Vec<u8>,
    /// Public key in COSE_Key form (goes into attested credential data)
    pub public_key_cose: Vec<u8>,
    /// Complete `none`-format attestation object
    pub attestation_object: Vec<u8>,
}

/// Successful assertion: the two byte strings an RP verifies.
#[derive(Debug)]
pub struct AssertionOutput {
    /// authenticator data (rpIdHash ‖ flags ‖ signCount)
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ES256 signature over `authenticator_data ‖ SHA256(clientDataJSON)`
    pub signature_der: Vec<u8>,
}

/// Parsed fields of a clientDataJSON blob.
pub struct ParsedClientData {
    /// `origin` as claimed by the client
    pub origin: String,
    /// `challenge` verbatim (base64url string as serialized)
    pub challenge: String,
}

/// Generate a fresh ES256 signing key from OS randomness.
pub fn generate_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("failed to generate random bytes");
    let key = SigningKey::from_slice(&bytes).expect("32 random bytes are a valid P-256 scalar");
    bytes.fill(0);
    key
}

/// Encode a P-256 public key as a WebAuthn COSE_Key (EC2 + P-256 + ES256).
pub fn cose_public_key(verifying_key: &VerifyingKey) -> PersonaResult<Vec<u8>> {
    let point = verifying_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| PersonaError::CryptographicError("Missing x coordinate".to_string()))?;
    let y = point
        .y()
        .ok_or_else(|| PersonaError::CryptographicError("Missing y coordinate".to_string()))?;

    let key = CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        x.as_slice().to_vec(),
        y.as_slice().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .build();

    key.to_vec()
        .map_err(|e| PersonaError::CryptographicError(format!("COSE encoding failed: {e}")))
}

/// Extract and lowercase the host component of a WebAuthn origin.
fn origin_host(origin: &str) -> PersonaResult<String> {
    let after_scheme = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| PersonaError::InvalidInput(format!("Invalid origin: {origin}")))?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return Err(PersonaError::InvalidInput(format!(
            "Origin has no host: {origin}"
        )));
    }
    Ok(host.to_ascii_lowercase())
}

/// Validate an rp_id: a registrable-domain-looking hostname or localhost.
fn validate_rp_id(rp_id: &str) -> PersonaResult<String> {
    let rp_id = rp_id.trim().to_ascii_lowercase();
    if rp_id.is_empty() || rp_id.starts_with('.') || rp_id.ends_with('.') {
        return Err(PersonaError::InvalidInput(format!(
            "Invalid rp_id: {rp_id}"
        )));
    }
    if rp_id.contains("://") || rp_id.contains('/') || rp_id.contains(':') {
        return Err(PersonaError::InvalidInput(format!(
            "rp_id must be a bare hostname, got: {rp_id}"
        )));
    }
    // A public-suffix-only rp_id (e.g. "com") would let any registrant of a
    // subdomain match; browsers refuse such rp_ids, so do we.
    if !rp_id.contains('.') && rp_id != "localhost" {
        return Err(PersonaError::InvalidInput(format!(
            "rp_id must be a registrable domain or localhost, got: {rp_id}"
        )));
    }
    Ok(rp_id)
}

/// Validate the WebAuthn origin ↔ rp_id relationship: the origin's effective
/// domain must equal the rp_id or be a subdomain of it (WebAuthn §5.4).
/// Note: without a full Public Suffix List this is the registrable-suffix
/// approximation; rp_ids on public suffixes are rejected outright above.
pub fn validate_origin_matches_rp_id(origin: &str, rp_id: &str) -> PersonaResult<()> {
    let rp_id = validate_rp_id(rp_id)?;
    let host = origin_host(origin)?;
    if host == rp_id || host.ends_with(&format!(".{rp_id}")) {
        Ok(())
    } else {
        Err(PersonaError::InvalidInput(format!(
            "Origin {origin} does not match rp_id {rp_id}"
        )))
    }
}

/// Parse and sanity-check a clientDataJSON blob: the `type` must match the
/// expected ceremony, `challenge` must be base64url, and the claimed `origin`
/// must equal the transport-verified origin. Returns the parsed fields; the
/// raw bytes stay the source of truth for hashing.
pub fn parse_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    origin: &str,
) -> PersonaResult<ParsedClientData> {
    let value: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid clientDataJSON: {e}")))?;

    let data_type = value
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PersonaError::InvalidInput("clientDataJSON missing type".to_string()))?;
    if data_type != expected_type {
        return Err(PersonaError::InvalidInput(format!(
            "clientDataJSON type mismatch: expected {expected_type}, got {data_type}"
        )));
    }

    let challenge = value
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PersonaError::InvalidInput("clientDataJSON missing challenge".to_string())
        })?;
    URL_SAFE_NO_PAD
        .decode(challenge)
        .map_err(|_| PersonaError::InvalidInput("challenge is not base64url".to_string()))?;

    let data_origin = value
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PersonaError::InvalidInput("clientDataJSON missing origin".to_string()))?;
    if !data_origin.eq_ignore_ascii_case(origin) {
        return Err(PersonaError::InvalidInput(format!(
            "clientDataJSON origin {data_origin} does not match request origin {origin}"
        )));
    }

    Ok(ParsedClientData {
        origin: data_origin.to_string(),
        challenge: challenge.to_string(),
    })
}

/// authenticator data: `rpIdHash ‖ flags ‖ signCount` plus, for registration,
/// the attested credential data (AAGUID ‖ credIdLen ‖ credId ‖ COSE key).
fn authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested_credential: Option<(&[u8], &[u8])>,
) -> PersonaResult<Vec<u8>> {
    let rp_id = validate_rp_id(rp_id)?;
    let mut data = Vec::with_capacity(37 + attested_credential.map_or(0, |(id, _)| 18 + id.len()));
    data.extend_from_slice(Sha256::digest(rp_id.as_bytes()).as_slice());
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((credential_id, cose_key)) = attested_credential {
        data.extend_from_slice(&aaguid());
        let len = u16::try_from(credential_id.len())
            .map_err(|_| PersonaError::InvalidInput("credential_id too long".to_string()))?;
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(cose_key);
    }
    Ok(data)
}

/// `none`-format attestation object: `{fmt: "none", attStmt: {}, authData}`.
fn attestation_object(auth_data: &[u8]) -> PersonaResult<Vec<u8>> {
    // Canonical CTAP2 ordering: "fmt" < "attStmt" < "authData".
    let map = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (Value::Text("attStmt".to_string()), Value::Map(Vec::new())),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut buf = Vec::new();
    coset::cbor::ser::into_writer(&map, &mut buf)
        .map_err(|e| PersonaError::CryptographicError(format!("CBOR encoding failed: {e}")))?;
    Ok(buf)
}

/// Run a registration ceremony: validates the client data against the origin
/// and rp_id, generates a fresh key pair and returns the attestation plus the
/// key material the caller must persist (encrypted).
pub fn register_passkey(
    rp_id: &str,
    origin: &str,
    client_data_json: &[u8],
    user_verification: bool,
) -> PersonaResult<RegistrationOutput> {
    validate_origin_matches_rp_id(origin, rp_id)?;
    parse_client_data(client_data_json, CLIENT_DATA_TYPE_CREATE, origin)?;
    let rp_id = validate_rp_id(rp_id)?;

    let signing_key = generate_signing_key();
    let public_key_cose = cose_public_key(signing_key.verifying_key())?;
    let credential_id = random_credential_id();

    let mut flags = FLAG_UP | FLAG_AT;
    if user_verification {
        flags |= FLAG_UV;
    }
    let auth_data = authenticator_data(
        &rp_id,
        flags,
        0,
        Some((&credential_id, public_key_cose.as_slice())),
    )?;
    let attestation_object = attestation_object(&auth_data)?;

    Ok(RegistrationOutput {
        signing_key,
        credential_id,
        public_key_cose,
        attestation_object,
    })
}

/// Run an assertion ceremony: signs `authenticator_data ‖ SHA256(clientDataJSON)`
/// with the stored key after re-validating origin ↔ rp_id.
pub fn assert_passkey(
    rp_id: &str,
    origin: &str,
    client_data_json: &[u8],
    signing_key: &SigningKey,
    user_verification: bool,
) -> PersonaResult<AssertionOutput> {
    validate_origin_matches_rp_id(origin, rp_id)?;
    parse_client_data(client_data_json, CLIENT_DATA_TYPE_GET, origin)?;
    let rp_id = validate_rp_id(rp_id)?;

    let mut flags = FLAG_UP;
    if user_verification {
        flags |= FLAG_UV;
    }
    let auth_data = authenticator_data(&rp_id, flags, 0, None)?;

    let mut message = Vec::with_capacity(auth_data.len() + 32);
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(Sha256::digest(client_data_json).as_slice());
    let signature: Signature = signing_key.sign(&message);

    Ok(AssertionOutput {
        authenticator_data: auth_data,
        signature_der: signature.to_der().as_bytes().to_vec(),
    })
}

/// Self-check helper (no RP involved): reconstruct the verifying key from a
/// COSE public key and verify an assertion the same way an RP would.
pub fn verify_assertion(
    public_key_cose: &[u8],
    rp_id: &str,
    client_data_json: &[u8],
    authenticator_data_bytes: &[u8],
    signature_der: &[u8],
) -> PersonaResult<()> {
    let verifying_key = verifying_key_from_cose(public_key_cose)?;

    // rpIdHash prefix must match, user presence must be set.
    let rp_id = validate_rp_id(rp_id)?;
    let expected_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if authenticator_data_bytes.len() < 37 || authenticator_data_bytes[..32] != expected_hash {
        return Err(PersonaError::InvalidInput(
            "authenticator data rpIdHash mismatch".to_string(),
        ));
    }
    if authenticator_data_bytes[32] & FLAG_UP == 0 {
        return Err(PersonaError::InvalidInput(
            "user presence flag not set".to_string(),
        ));
    }

    let mut message = Vec::with_capacity(authenticator_data_bytes.len() + 32);
    message.extend_from_slice(authenticator_data_bytes);
    message.extend_from_slice(Sha256::digest(client_data_json).as_slice());

    let signature = Signature::from_der(signature_der)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid DER signature: {e}")))?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| PersonaError::CryptographicError("Assertion signature invalid".to_string()))
}

/// Reconstruct a `VerifyingKey` from a Persona-produced COSE_Key (EC2/P-256).
fn verifying_key_from_cose(cose: &[u8]) -> PersonaResult<VerifyingKey> {
    let key = CoseKey::from_slice(cose)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid COSE key: {e}")))?;

    let mut x: Option<&[u8]> = None;
    let mut y: Option<&[u8]> = None;
    for (label, value) in &key.params {
        match (label, value) {
            (coset::Label::Int(-2), Value::Bytes(b)) => x = Some(b),
            (coset::Label::Int(-3), Value::Bytes(b)) => y = Some(b),
            _ => {}
        }
    }
    let x = x.ok_or_else(|| PersonaError::InvalidInput("COSE key missing x".to_string()))?;
    let y = y.ok_or_else(|| PersonaError::InvalidInput("COSE key missing y".to_string()))?;

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid P-256 point: {e}")))
}

/// 32 random bytes for credential IDs (software authenticator convention).
fn random_credential_id() -> Vec<u8> {
    random_bytes32().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_data(create: bool, challenge: &str, origin: &str) -> Vec<u8> {
        let t = if create {
            CLIENT_DATA_TYPE_CREATE
        } else {
            CLIENT_DATA_TYPE_GET
        };
        format!(r#"{{"type":"{t}","challenge":"{challenge}","origin":"{origin}"}}"#).into_bytes()
    }

    #[test]
    fn registration_round_trip_self_verify() {
        let rp = "example.com";
        let cd = client_data(true, "Y2hhbGxlbmdl", "https://example.com");
        let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();

        // attestation structure: fmt/attStmt/authData, flags UP|AT, signCount 0
        assert_eq!(reg.credential_id.len(), 32);
        let verify = verify_attestation_structure(rp, &reg, &cd);
        assert!(verify.is_ok(), "{verify:?}");

        // assertion + self verification
        let get_cd = client_data(false, "YW5vdGhlcg", "https://example.com");
        let out =
            assert_passkey(rp, "https://example.com", &get_cd, &reg.signing_key, false).unwrap();
        verify_assertion(
            &reg.public_key_cose,
            rp,
            &get_cd,
            &out.authenticator_data,
            &out.signature_der,
        )
        .unwrap();
    }

    fn verify_attestation_structure(
        rp: &str,
        reg: &RegistrationOutput,
        cd: &[u8],
    ) -> Result<(), PersonaError> {
        let cose = CoseKey::from_slice(&reg.public_key_cose)
            .map_err(|e| PersonaError::InvalidInput(format!("bad cose: {e}")))?;
        assert_eq!(
            cose.alg,
            Some(coset::Algorithm::Assigned(iana::Algorithm::ES256))
        );

        // decode attestation object
        let value: coset::cbor::value::Value =
            coset::cbor::de::from_reader(reg.attestation_object.as_slice())
                .map_err(|e| PersonaError::InvalidInput(format!("bad cbor: {e}")))?;
        let coset::cbor::value::Value::Map(entries) = value else {
            panic!("attestation must be a map")
        };
        let get = |k: &str| {
            entries
                .iter()
                .find_map(|(key, v)| match key {
                    coset::cbor::value::Value::Text(t) if t == k => Some(v.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing key {k}"))
        };
        let coset::cbor::value::Value::Text(fmt) = get("fmt") else {
            panic!("fmt must be text")
        };
        assert_eq!(fmt, "none");
        let coset::cbor::value::Value::Map(att_stmt) = get("attStmt") else {
            panic!("attStmt must be a map")
        };
        assert!(att_stmt.is_empty());
        let coset::cbor::value::Value::Bytes(auth_data) = get("authData") else {
            panic!("authData must be bytes")
        };

        // rpIdHash, flags UP|AT, signCount 0, AAGUID, credIdLen 32
        use sha2::{Digest, Sha256};
        let rp_hash: [u8; 32] = Sha256::digest(rp.as_bytes()).into();
        assert_eq!(&auth_data[..32], &rp_hash);
        assert_eq!(auth_data[32], FLAG_UP | FLAG_AT);
        assert_eq!(&auth_data[33..37], &[0, 0, 0, 0]);
        assert_eq!(&auth_data[37..53], &aaguid());
        assert_eq!(&auth_data[53..55], &[0, 32]);
        assert_eq!(&auth_data[55..87], &reg.credential_id[..]);
        // COSE key embedded at the tail
        assert_eq!(auth_data.len(), 87 + reg.public_key_cose.len());
        assert_eq!(&auth_data[87..], &reg.public_key_cose[..]);

        // client data echo checks still pass
        parse_client_data(cd, CLIENT_DATA_TYPE_CREATE, "https://example.com")?;
        Ok(())
    }

    #[test]
    fn rejects_origin_rp_mismatch() {
        let cd = client_data(true, "Y2hhbGxlbmdl", "https://evil.example");
        let err = register_passkey("example.com", "https://evil.example", &cd, false)
            .expect_err("must reject");
        assert!(matches!(err, PersonaError::InvalidInput(_)));
    }

    #[test]
    fn rejects_client_data_origin_mismatch() {
        // Request origin ok, but the clientDataJSON claims a different origin.
        let cd = client_data(true, "Y2hhbGxlbmdl", "https://evil.example");
        let err = register_passkey("example.com", "https://example.com", &cd, false)
            .expect_err("must reject");
        assert!(err.to_string().contains("does not match request origin"));
    }

    #[test]
    fn rejects_wrong_ceremony_type() {
        let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
        let err = register_passkey("example.com", "https://example.com", &cd, false)
            .expect_err("must reject");
        assert!(err.to_string().contains("type mismatch"));
    }

    #[test]
    fn rejects_subdomain_spoof() {
        assert!(validate_origin_matches_rp_id("https://evil-github.com", "github.com").is_err());
        assert!(
            validate_origin_matches_rp_id("https://evilstill.github.com", "github.com").is_ok()
        );
    }

    #[test]
    fn rejects_public_suffix_rp_id() {
        assert!(validate_rp_id("com").is_err());
        assert!(validate_rp_id("github.com").is_ok());
        assert!(validate_rp_id("localhost").is_ok());
    }

    // ============ passkey_create options parsing (bridge protocol v2) ============

    fn es256_options(rp_id: Option<&str>, user_id: Option<&str>) -> serde_json::Value {
        let mut options = serde_json::json!({
            "user": { "id": user_id, "name": "alice@example.com", "displayName": "Alice" },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        });
        if let Some(id) = rp_id {
            options["rp"] = serde_json::json!({ "id": id, "name": "Example" });
        }
        options
    }

    #[test]
    fn parse_options_defaults_rp_id_to_origin_host() {
        // rp.id omitted → the origin's effective host is used (WebAuthn §5.4).
        let parsed =
            parse_creation_options(&es256_options(None, Some("dXNlcg")), "https://example.com")
                .unwrap();
        assert_eq!(parsed.rp_id, "example.com");
        assert_eq!(parsed.user_handle, b"user");
        assert_eq!(parsed.user_name.as_deref(), Some("alice@example.com"));
        assert_eq!(parsed.user_display_name.as_deref(), Some("Alice"));
        assert_eq!(parsed.rp_name.as_deref(), None);
    }

    #[test]
    fn parse_options_rejects_missing_or_invalid_user_id() {
        // user present but id missing / not a string
        let err = parse_creation_options(
            &es256_options(Some("example.com"), None),
            "https://example.com",
        )
        .expect_err("missing user.id must be rejected");
        assert!(err
            .to_string()
            .contains("user.id must be a base64url string"));

        // id decodes to zero bytes
        let err = parse_creation_options(
            &es256_options(Some("example.com"), Some("")),
            "https://example.com",
        )
        .expect_err("empty user.id must be rejected");
        assert!(err.to_string().contains("1..=64 bytes"));

        // id larger than 64 bytes
        let big = URL_SAFE_NO_PAD.encode(vec![0u8; 65]);
        let err = parse_creation_options(
            &es256_options(Some("example.com"), Some(&big)),
            "https://example.com",
        )
        .expect_err("oversized user.id must be rejected");
        assert!(err.to_string().contains("1..=64 bytes"));
    }

    #[test]
    fn parse_options_rejects_invalid_rp_id_and_origin() {
        // rp.id is passed through unvalidated here; registration re-checks it
        // via validate_rp_id (tested below). What IS rejected at parse time:
        // an origin whose authority is empty when no rp.id can be derived.
        let err = parse_creation_options(&es256_options(None, Some("dQ")), "https://")
            .expect_err("hostless origin must be rejected");
        assert!(err.to_string().contains("Origin has no host"));

        // IPv6 origin: the host extraction strips brackets and port.
        let parsed = parse_creation_options(&es256_options(None, Some("dQ")), "https://[::1]:8443")
            .expect("IPv6 host must extract");
        assert_eq!(parsed.rp_id, "::1");
    }

    #[test]
    fn validate_rp_id_shape_rules() {
        // dotted-only and scheme-carrying rp_ids are not hostnames
        let err = validate_rp_id(".").expect_err("dotted rp_id must be rejected");
        assert!(err.to_string().contains("Invalid rp_id"));
        let err = validate_rp_id("https://example.com")
            .expect_err("rp_id with a scheme must be rejected");
        assert!(err.to_string().contains("rp_id must be a bare hostname"));
    }

    #[test]
    fn rejects_client_data_without_challenge() {
        let cd = br#"{"type":"webauthn.create","origin":"https://example.com"}"#;
        let err = register_passkey("example.com", "https://example.com", cd, false)
            .expect_err("clientDataJSON without challenge must be rejected");
        assert!(err.to_string().contains("missing challenge"));
    }

    #[test]
    fn verify_rejects_tampered_authenticator_data() {
        let rp = "example.com";
        let reg = register_passkey(
            rp,
            "https://example.com",
            &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
            false,
        )
        .unwrap();
        let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
        let out = assert_passkey(rp, "https://example.com", &cd, &reg.signing_key, false).unwrap();

        // rpIdHash no longer matches the rp_id
        let mut bad_hash = out.authenticator_data.clone();
        bad_hash[0] ^= 0xFF;
        let err = verify_assertion(&reg.public_key_cose, rp, &cd, &bad_hash, &out.signature_der)
            .expect_err("rpIdHash mismatch must be rejected");
        assert!(err.to_string().contains("rpIdHash mismatch"));

        // user presence flag cleared
        let mut no_up = out.authenticator_data.clone();
        no_up[32] &= !FLAG_UP;
        let err = verify_assertion(&reg.public_key_cose, rp, &cd, &no_up, &out.signature_der)
            .expect_err("cleared UP flag must be rejected");
        assert!(err.to_string().contains("user presence flag not set"));
    }

    #[test]
    fn assertion_signature_binds_client_data() {
        // Tampered client data must fail verification.
        let rp = "example.com";
        let reg = register_passkey(
            rp,
            "https://example.com",
            &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
            false,
        )
        .unwrap();
        let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
        let out = assert_passkey(rp, "https://example.com", &cd, &reg.signing_key, false).unwrap();

        // Untampered client data verifies...
        verify_assertion(
            &reg.public_key_cose,
            rp,
            &cd,
            &out.authenticator_data,
            &out.signature_der,
        )
        .unwrap();

        // ...tampered client data must not.
        let tampered = client_data(false, "dGFtcGVyZWQ", "https://example.com");
        assert!(verify_assertion(
            &reg.public_key_cose,
            rp,
            &tampered,
            &out.authenticator_data,
            &out.signature_der,
        )
        .is_err());
    }

    // ============ malformed attestation objects ============
    //
    // Feed hand-built CBOR through the structure checker so its defensive
    // failure paths are actually exercised, not just compiled in.

    fn cbor_bytes(value: &coset::cbor::value::Value) -> Vec<u8> {
        let mut buf = Vec::new();
        coset::cbor::ser::into_writer(value, &mut buf).unwrap();
        buf
    }

    fn attestation_with(
        fields: Vec<(coset::cbor::value::Value, coset::cbor::value::Value)>,
    ) -> Vec<u8> {
        cbor_bytes(&coset::cbor::value::Value::Map(fields))
    }

    fn assert_panics_on_attestation(attestation: &[u8], expected: &str) {
        let rp = "example.com";
        let reg = register_passkey(
            rp,
            "https://example.com",
            &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
            false,
        )
        .unwrap();
        let broken = RegistrationOutput {
            attestation_object: attestation.to_vec(),
            ..reg
        };
        let result = std::panic::catch_unwind(move || {
            let cd = client_data(true, "cmVnaXN0ZXI", "https://example.com");
            let _ = verify_attestation_structure(rp, &broken, &cd);
        })
        .expect_err("malformed attestation must panic the checker");
        let message = result
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| result.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(message.contains(expected), "panic was: {message}");
    }

    #[test]
    fn attestation_checker_rejects_non_map_root() {
        assert_panics_on_attestation(
            &cbor_bytes(&coset::cbor::value::Value::Text("not a map".to_string())),
            "attestation must be a map",
        );
    }

    #[test]
    fn attestation_checker_rejects_non_text_fmt() {
        assert_panics_on_attestation(
            &attestation_with(vec![
                (
                    coset::cbor::value::Value::Text("fmt".to_string()),
                    coset::cbor::value::Value::Bytes(vec![1]),
                ),
                (
                    coset::cbor::value::Value::Text("attStmt".to_string()),
                    coset::cbor::value::Value::Map(Vec::new()),
                ),
                (
                    coset::cbor::value::Value::Text("authData".to_string()),
                    coset::cbor::value::Value::Bytes(vec![1]),
                ),
            ]),
            "fmt must be text",
        );
    }

    #[test]
    fn attestation_checker_rejects_non_map_att_stmt() {
        assert_panics_on_attestation(
            &attestation_with(vec![
                (
                    coset::cbor::value::Value::Text("fmt".to_string()),
                    coset::cbor::value::Value::Text("none".to_string()),
                ),
                (
                    coset::cbor::value::Value::Text("attStmt".to_string()),
                    coset::cbor::value::Value::Text("nope".to_string()),
                ),
                (
                    coset::cbor::value::Value::Text("authData".to_string()),
                    coset::cbor::value::Value::Bytes(vec![1]),
                ),
            ]),
            "attStmt must be a map",
        );
    }

    #[test]
    fn attestation_checker_rejects_non_bytes_auth_data() {
        assert_panics_on_attestation(
            &attestation_with(vec![
                (
                    coset::cbor::value::Value::Text("fmt".to_string()),
                    coset::cbor::value::Value::Text("none".to_string()),
                ),
                (
                    coset::cbor::value::Value::Text("attStmt".to_string()),
                    coset::cbor::value::Value::Map(Vec::new()),
                ),
                (
                    coset::cbor::value::Value::Text("authData".to_string()),
                    coset::cbor::value::Value::Text("nope".to_string()),
                ),
            ]),
            "authData must be bytes",
        );
    }
}
