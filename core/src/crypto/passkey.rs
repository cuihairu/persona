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
const FLAG_BS: u8 = 0x10;
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
    let point = verifying_key.to_sec1_point(false);
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

/// Verified RP-side registration output: everything an RP persists for a
/// newly attested credential.
#[derive(Debug)]
pub struct VerifiedRegistration {
    /// COSE_Key (EC2/P-256/ES256) to persist as the credential's public key.
    pub public_key_cose: Vec<u8>,
    /// Credential id as attested in the authenticator data.
    pub credential_id: Vec<u8>,
    /// Authenticator signature counter (clone detection at assertion time).
    pub sign_count: u32,
    /// AAGUID from the attested credential data.
    pub aaguid: [u8; 16],
    /// BS flag: the credential currently backs up to a cloud sync service.
    pub backed_up: bool,
}

/// RP-side registration verification: validate the client data against the
/// origin/rp_id and the issued challenge, then parse the `none`-format
/// attestation object — checking rpIdHash and flags, and extracting the
/// attested credential (COSE key, credential id, AAGUID, sign count).
///
/// Only `fmt: "none"` is accepted: the creation options issued by this
/// project request `attestation: "none"`, and other formats carry
/// authenticator attestation statements this verifier does not implement.
pub fn verify_attestation(
    attestation_object: &[u8],
    rp_id: &str,
    origin: &str,
    client_data_json: &[u8],
    expected_challenge: &str,
) -> PersonaResult<VerifiedRegistration> {
    validate_origin_matches_rp_id(origin, rp_id)?;
    let parsed = parse_client_data(client_data_json, CLIENT_DATA_TYPE_CREATE, origin)?;
    if parsed.challenge != expected_challenge {
        return Err(PersonaError::InvalidInput(
            "clientDataJSON challenge does not match the issued challenge".to_string(),
        ));
    }
    let rp_id = validate_rp_id(rp_id)?;

    let value: coset::cbor::value::Value = coset::cbor::de::from_reader(attestation_object)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid attestation object: {e}")))?;
    let coset::cbor::value::Value::Map(entries) = value else {
        return Err(PersonaError::InvalidInput(
            "attestation object must be a CBOR map".to_string(),
        ));
    };

    let fmt = match att_map_get(&entries, "fmt") {
        Some(coset::cbor::value::Value::Text(t)) => t.as_str(),
        _ => {
            return Err(PersonaError::InvalidInput(
                "attestation object missing fmt".to_string(),
            ))
        }
    };
    if fmt != "none" {
        return Err(PersonaError::InvalidInput(format!(
            "unsupported attestation format: {fmt}"
        )));
    }
    match att_map_get(&entries, "attStmt") {
        Some(coset::cbor::value::Value::Map(m)) if m.is_empty() => {}
        _ => {
            return Err(PersonaError::InvalidInput(
                "attStmt must be an empty map for fmt \"none\"".to_string(),
            ))
        }
    }
    let auth_data = match att_map_get(&entries, "authData") {
        Some(coset::cbor::value::Value::Bytes(b)) => b,
        _ => {
            return Err(PersonaError::InvalidInput(
                "attestation object missing authData".to_string(),
            ))
        }
    };

    // rpIdHash ‖ flags ‖ signCount ‖ attested credential data (AT set).
    if auth_data.len() < 55 {
        return Err(PersonaError::InvalidInput(
            "authenticator data too short".to_string(),
        ));
    }
    let expected_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if auth_data[..32] != expected_hash {
        return Err(PersonaError::InvalidInput(
            "authenticator data rpIdHash mismatch".to_string(),
        ));
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 {
        return Err(PersonaError::InvalidInput(
            "user presence flag not set".to_string(),
        ));
    }
    if flags & FLAG_AT == 0 {
        return Err(PersonaError::InvalidInput(
            "attested credential data missing".to_string(),
        ));
    }
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let aaguid: [u8; 16] = auth_data[37..53]
        .try_into()
        .expect("slice length checked above");
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if cred_len == 0 || cred_len > 1023 {
        return Err(PersonaError::InvalidInput(
            "invalid credential id length".to_string(),
        ));
    }
    let cred_end = 55 + cred_len;
    if auth_data.len() <= cred_end {
        return Err(PersonaError::InvalidInput(
            "attested credential data truncated".to_string(),
        ));
    }
    let credential_id = auth_data[55..cred_end].to_vec();
    let cose = &auth_data[cred_end..];

    // Structural checks on the attested key: EC2/P-256/ES256 only, and the
    // point must decode (verifying_key_from_cose rejects off-curve points).
    let key = CoseKey::from_slice(cose)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid COSE key: {e}")))?;
    if key.kty != coset::KeyType::Assigned(iana::KeyType::EC2) {
        return Err(PersonaError::InvalidInput(
            "attested key must be EC2".to_string(),
        ));
    }
    if key.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) {
        return Err(PersonaError::InvalidInput(
            "attested key must be ES256".to_string(),
        ));
    }
    // Curve is pinned by the decode below: P-256 x/y are 32-byte coordinates,
    // so a point on any other curve fails Sec1 decoding.
    verifying_key_from_cose(cose)?;

    Ok(VerifiedRegistration {
        public_key_cose: cose.to_vec(),
        credential_id,
        sign_count,
        aaguid,
        backed_up: flags & FLAG_BS != 0,
    })
}

/// Look up a text key in a CBOR map.
fn att_map_get<'a>(
    entries: &'a [(coset::cbor::value::Value, coset::cbor::value::Value)],
    key: &str,
) -> Option<&'a coset::cbor::value::Value> {
    entries.iter().find_map(|(k, v)| match k {
        coset::cbor::value::Value::Text(t) if t == key => Some(v),
        _ => None,
    })
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

    // ============ RP-side registration verification (verify_attestation) ============

    fn reencode_attestation(fmt: &str, auth_data: Vec<u8>) -> Vec<u8> {
        let map = Value::Map(vec![
            (Value::Text("fmt".to_string()), Value::Text(fmt.to_string())),
            (Value::Text("attStmt".to_string()), Value::Map(Vec::new())),
            (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
        ]);
        let mut buf = Vec::new();
        coset::cbor::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    fn attestation_auth_data(att: &[u8]) -> Vec<u8> {
        let value: Value = coset::cbor::de::from_reader(att).unwrap();
        let Value::Map(entries) = value else {
            panic!("map expected")
        };
        match att_map_get(&entries, "authData") {
            Some(Value::Bytes(b)) => b.clone(),
            _ => panic!("authData expected"),
        }
    }

    #[test]
    fn verify_attestation_accepts_none_format_registration() {
        let rp = "example.com";
        let challenge = "c2VydmVyLWlzc3VlZA";
        let cd = client_data(true, challenge, "https://example.com");
        let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();

        let verified = verify_attestation(
            &reg.attestation_object,
            rp,
            "https://example.com",
            &cd,
            challenge,
        )
        .expect("issued registration must verify");
        assert_eq!(verified.public_key_cose, reg.public_key_cose);
        assert_eq!(verified.credential_id, reg.credential_id);
        assert_eq!(verified.sign_count, 0);
        assert_eq!(verified.aaguid, aaguid());
        assert!(!verified.backed_up);
    }

    #[test]
    fn verify_attestation_rejects_challenge_mismatch() {
        let rp = "example.com";
        let cd = client_data(true, "aXNzdWVkLWNoYWxsZW5nZQ", "https://example.com");
        let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();
        let err = verify_attestation(
            &reg.attestation_object,
            rp,
            "https://example.com",
            &cd,
            "b3RoZXItY2hhbGxlbmdl",
        )
        .expect_err("stale/wrong challenge must be rejected");
        assert!(err.to_string().contains("issued challenge"), "{err}");
    }

    #[test]
    fn verify_attestation_rejects_assertion_client_data() {
        let rp = "example.com";
        let challenge = "cmVnaXN0ZXI";
        let cd = client_data(true, challenge, "https://example.com");
        let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();
        let get_cd = client_data(false, challenge, "https://example.com");
        let err = verify_attestation(
            &reg.attestation_object,
            rp,
            "https://example.com",
            &get_cd,
            challenge,
        )
        .expect_err("webauthn.get client data must not pass registration");
        assert!(err.to_string().contains("type mismatch"), "{err}");
    }

    #[test]
    fn verify_attestation_rejects_non_none_format() {
        let rp = "example.com";
        let challenge = "cGFja2VkLWZtdA";
        let cd = client_data(true, challenge, "https://example.com");
        let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();
        let packed = reencode_attestation("packed", attestation_auth_data(&reg.attestation_object));
        let err = verify_attestation(&packed, rp, "https://example.com", &cd, challenge)
            .expect_err("formats we did not request must be rejected");
        assert!(
            err.to_string().contains("unsupported attestation format"),
            "{err}"
        );
    }

    #[test]
    fn verify_attestation_rejects_tampered_rp_id_hash() {
        let rp = "example.com";
        let challenge = "dGFtcGVyZWQtaGFzaA";
        let cd = client_data(true, challenge, "https://example.com");
        let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();
        let mut auth_data = attestation_auth_data(&reg.attestation_object);
        auth_data[0] ^= 0xFF;
        let tampered = reencode_attestation("none", auth_data);
        let err = verify_attestation(&tampered, rp, "https://example.com", &cd, challenge)
            .expect_err("forged rpIdHash must be rejected");
        assert!(err.to_string().contains("rpIdHash mismatch"), "{err}");
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

    // ============ additional coverage: helpers, UV flag, error paths ========

    #[test]
    fn local_client_data_helpers_produce_parseable_json() {
        let cd = local_client_data(CLIENT_DATA_TYPE_CREATE, "https://example.com").unwrap();
        let parsed = parse_client_data(&cd, CLIENT_DATA_TYPE_CREATE, "https://example.com")
            .expect("locally built client data must parse");
        // The challenge is random 32 bytes of base64url (43 chars).
        assert_eq!(URL_SAFE_NO_PAD.decode(&parsed.challenge).unwrap().len(), 32);

        let self_test = self_test_client_data("https://example.com").unwrap();
        parse_client_data(&self_test, CLIENT_DATA_TYPE_GET, "https://example.com")
            .expect("self-test client data must use the GET ceremony type");
    }

    #[test]
    fn aaguid_and_random_bytes_are_distinct() {
        // The AAGUID is a fixed 16-byte identifier for the software
        // authenticator.
        assert_eq!(aaguid().len(), 16);
        assert_eq!(aaguid(), PasskeyItem::aaguid());

        let a = random_bytes32();
        let b = random_bytes32();
        assert_ne!(a, b);
    }

    #[test]
    fn user_verification_flag_is_carried_into_authenticator_data() {
        let rp = "example.com";
        let origin = "https://example.com";
        let cd_create = client_data(true, "dXZmbGFn", origin);
        let reg = register_passkey(rp, origin, &cd_create, true).unwrap();

        // Registration authData flags must include UP | AT | UV.
        let value: coset::cbor::value::Value =
            coset::cbor::de::from_reader(reg.attestation_object.as_slice()).unwrap();
        let coset::cbor::value::Value::Map(entries) = value else {
            panic!("attestation must be a map")
        };
        let auth_data = entries
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (coset::cbor::value::Value::Text(t), coset::cbor::value::Value::Bytes(b))
                    if t == "authData" =>
                {
                    Some(b.clone())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(auth_data[32], FLAG_UP | FLAG_AT | FLAG_UV);

        // Assertion with UV also sets the flag and still verifies.
        let cd_get = client_data(false, "dXZmbGFn", origin);
        let out = assert_passkey(rp, origin, &cd_get, &reg.signing_key, true).unwrap();
        assert_eq!(out.authenticator_data[32], FLAG_UP | FLAG_UV);
        verify_assertion(
            &reg.public_key_cose,
            rp,
            &cd_get,
            &out.authenticator_data,
            &out.signature_der,
        )
        .unwrap();
    }

    #[test]
    fn parse_creation_options_rejects_missing_or_wrong_alg_params() {
        let origin = "https://example.com";

        // pubKeyCredParams missing entirely.
        let options = serde_json::json!({ "user": { "id": "dXNlcg" } });
        let err = parse_creation_options(&options, origin)
            .expect_err("missing pubKeyCredParams must be rejected");
        assert!(err.to_string().contains("passkey_alg_unsupported"));

        // Only non-ES256 algorithms offered.
        let options = serde_json::json!({
            "user": { "id": "dXNlcg" },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -257 }],
        });
        let err = parse_creation_options(&options, origin)
            .expect_err("non-ES256 params must be rejected");
        assert!(err.to_string().contains("passkey_alg_unsupported"));

        // ES256 present but with a wrong type string.
        let options = serde_json::json!({
            "user": { "id": "dXNlcg" },
            "pubKeyCredParams": [{ "type": "other", "alg": -7 }],
        });
        assert!(parse_creation_options(&options, origin).is_err());

        // user object missing entirely.
        let options =
            serde_json::json!({ "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }] });
        let err =
            parse_creation_options(&options, origin).expect_err("missing user must be rejected");
        assert!(err.to_string().contains("missing user"));
    }

    #[test]
    fn parse_creation_options_accepts_padded_base64url_and_rp_name() {
        // Padded base64url ("dXNlcg==") must decode via the fallback engine.
        let parsed = parse_creation_options(
            &es256_options(Some("example.com"), Some("dXNlcg==")),
            "https://example.com",
        )
        .unwrap();
        assert_eq!(parsed.user_handle, b"user");
        assert_eq!(parsed.rp_name.as_deref(), Some("Example"));
        assert_eq!(parsed.rp_id, "example.com");

        // Invalid base64url (bad alphabet) is rejected.
        let err = parse_creation_options(
            &es256_options(Some("example.com"), Some("!!!not-base64url!!!")),
            "https://example.com",
        )
        .expect_err("invalid base64url must be rejected");
        assert!(err.to_string().contains("invalid base64url encoding"));
    }

    #[test]
    fn origin_host_extraction_rules() {
        // Host is lower-cased; port, path, query and fragment are stripped.
        let parsed = parse_creation_options(
            &es256_options(None, Some("dQ")),
            "https://EXAMPLE.COM:8443/path?q=1#frag",
        )
        .unwrap();
        assert_eq!(parsed.rp_id, "example.com");

        // A scheme-less origin is rejected.
        let err = parse_creation_options(&es256_options(None, Some("dQ")), "example.com")
            .expect_err("scheme-less origin must be rejected");
        assert!(err.to_string().contains("Invalid origin"));
    }

    #[test]
    fn validate_origin_matches_rp_id_rules() {
        // Exact match and subdomain match are fine.
        assert!(validate_origin_matches_rp_id("https://example.com", "example.com").is_ok());
        assert!(validate_origin_matches_rp_id("https://a.b.example.com", "example.com").is_ok());

        // A sibling domain is not a subdomain.
        let err = validate_origin_matches_rp_id("https://example.org", "example.com")
            .expect_err("different domain must be rejected");
        assert!(err.to_string().contains("does not match rp_id"));

        // rp_id shape rules apply to the direct call too.
        assert!(
            validate_origin_matches_rp_id("https://example.com", "https://example.com").is_err()
        );
        assert!(validate_origin_matches_rp_id("https://example.com", "").is_err());
        assert!(validate_origin_matches_rp_id("https://example.com", ".").is_err());
    }

    /// `ParsedClientData` is not `Debug`, so `expect_err` cannot be used.
    fn expect_invalid(result: PersonaResult<ParsedClientData>, msg: &str) -> PersonaError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("{msg}"),
        }
    }

    #[test]
    fn parse_client_data_error_paths() {
        // Malformed JSON.
        let err = expect_invalid(
            parse_client_data(b"{not json", CLIENT_DATA_TYPE_GET, "https://example.com"),
            "malformed JSON must be rejected",
        );
        assert!(err.to_string().contains("Invalid clientDataJSON"));

        // Missing type field.
        let err = expect_invalid(
            parse_client_data(
                br#"{"challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#,
                CLIENT_DATA_TYPE_GET,
                "https://example.com",
            ),
            "missing type must be rejected",
        );
        assert!(err.to_string().contains("missing type"));

        // Challenge that is not base64url.
        let err = expect_invalid(
            parse_client_data(
                br#"{"type":"webauthn.get","challenge":"!!!","origin":"https://example.com"}"#,
                CLIENT_DATA_TYPE_GET,
                "https://example.com",
            ),
            "non-base64url challenge must be rejected",
        );
        assert!(err.to_string().contains("challenge is not base64url"));

        // Missing origin field.
        let err = expect_invalid(
            parse_client_data(
                br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl"}"#,
                CLIENT_DATA_TYPE_GET,
                "https://example.com",
            ),
            "missing origin must be rejected",
        );
        assert!(err.to_string().contains("missing origin"));

        // Origin comparison is ASCII-case-insensitive.
        parse_client_data(
            br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"HTTPS://EXAMPLE.COM"}"#,
            CLIENT_DATA_TYPE_GET,
            "https://example.com",
        )
        .expect("case difference in origin must be tolerated");
    }

    #[test]
    fn verify_assertion_error_paths() {
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

        // Garbage instead of a COSE key.
        let err = verify_assertion(
            b"not a cose key",
            rp,
            &cd,
            &out.authenticator_data,
            &out.signature_der,
        )
        .expect_err("invalid COSE key must be rejected");
        assert!(err.to_string().contains("Invalid COSE key"));

        // Authenticator data shorter than the 37-byte header.
        let err = verify_assertion(
            &reg.public_key_cose,
            rp,
            &cd,
            &out.authenticator_data[..20],
            &out.signature_der,
        )
        .expect_err("truncated authenticator data must be rejected");
        assert!(err.to_string().contains("rpIdHash mismatch"));

        // Not a DER signature.
        let err = verify_assertion(
            &reg.public_key_cose,
            rp,
            &cd,
            &out.authenticator_data,
            b"not der",
        )
        .expect_err("non-DER signature must be rejected");
        assert!(err.to_string().contains("Invalid DER signature"));

        // A valid DER signature made over different bytes.
        let err = verify_assertion(
            &reg.public_key_cose,
            rp,
            &client_data(false, "dGFtcGVyZWQ", "https://example.com"),
            &out.authenticator_data,
            &out.signature_der,
        )
        .expect_err("signature over different client data must fail");
        assert!(err.to_string().contains("Assertion signature invalid"));
    }

    fn cose_key_with_params(params: Vec<(coset::Label, coset::cbor::value::Value)>) -> Vec<u8> {
        let key = CoseKey {
            kty: coset::KeyType::Assigned(iana::KeyType::EC2),
            key_id: Vec::new(),
            alg: Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)),
            key_ops: Default::default(),
            base_iv: Vec::new(),
            params,
        };
        key.to_vec().unwrap()
    }

    #[test]
    fn verify_assertion_rejects_cose_key_missing_coordinates() {
        let reg = register_passkey(
            "example.com",
            "https://example.com",
            &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
            false,
        )
        .unwrap();
        let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
        let out = assert_passkey(
            "example.com",
            "https://example.com",
            &cd,
            &reg.signing_key,
            false,
        )
        .unwrap();

        // Rebuild the real key to harvest a valid x coordinate.
        let real = CoseKey::from_slice(&reg.public_key_cose).unwrap();
        let x = real
            .params
            .iter()
            .find_map(|(l, v)| match (l, v) {
                (coset::Label::Int(-2), Value::Bytes(b)) => Some(b.clone()),
                _ => None,
            })
            .unwrap();
        let y = real
            .params
            .iter()
            .find_map(|(l, v)| match (l, v) {
                (coset::Label::Int(-3), Value::Bytes(b)) => Some(b.clone()),
                _ => None,
            })
            .unwrap();

        // Missing y.
        let missing_y =
            cose_key_with_params(vec![(coset::Label::Int(-2), Value::Bytes(x.clone()))]);
        let err = verify_assertion(
            &missing_y,
            "example.com",
            &cd,
            &out.authenticator_data,
            &out.signature_der,
        )
        .expect_err("COSE key without y must be rejected");
        assert!(err.to_string().contains("missing y"));

        // Missing x.
        let missing_x =
            cose_key_with_params(vec![(coset::Label::Int(-3), Value::Bytes(y.clone()))]);
        let err = verify_assertion(
            &missing_x,
            "example.com",
            &cd,
            &out.authenticator_data,
            &out.signature_der,
        )
        .expect_err("COSE key without x must be rejected");
        assert!(err.to_string().contains("missing x"));

        // Coordinates that are not a valid P-256 point.
        let bad_point = cose_key_with_params(vec![
            (coset::Label::Int(-2), Value::Bytes(vec![0xFF; 32])),
            (coset::Label::Int(-3), Value::Bytes(vec![0xFF; 32])),
        ]);
        let err = verify_assertion(
            &bad_point,
            "example.com",
            &cd,
            &out.authenticator_data,
            &out.signature_der,
        )
        .expect_err("invalid P-256 point must be rejected");
        assert!(err.to_string().contains("Invalid P-256 point"));
    }

    // ============ §12 fuzz list: deterministic malformed-input harness ============
    //
    // docs/PASSKEYS_DESIGN.md §12 puts `clientDataJSON` and creation-options JSON
    // parsing on the fuzz list. This repo has no cargo-fuzz/libFuzzer scaffolding
    // (no fuzz/ dir, no nightly toolchain), so instead of a nightly-only harness
    // these tests drive the three parsing entry points with a hand-written,
    // deterministic PRNG over mutation strategies drawn from real-world parser
    // breakage: bit flips, truncation, span deletion, hostile-byte injection,
    // JSON fragment splicing and wholesale random bytes. The property is always
    // "malformed input yields Err (or a self-consistent Ok), never a panic".
    // When a real fuzz target lands, hook these same entry points and properties.

    /// xorshift64* — hand-rolled so the suite does not depend on any particular
    /// `rand` API; same seed ⇒ same sequence, so failures are reproducible.
    struct DetRng(u64);

    impl DetRng {
        fn new(seed: u64) -> Self {
            // xorshift's only fixed point is 0 — keep the state off it.
            Self(seed | 1)
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        /// Uniform enough in `[0, n)`; callers guarantee `n > 0`.
        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// Bytes that historically break JSON/base64/UTF-8 parsers.
    const HOSTILE_BYTES: [u8; 5] = [0xFF, 0x00, b'\n', b'"', 0x80];

    /// One deterministic mutation of `seed`.
    fn mutate_bytes(rng: &mut DetRng, seed: &[u8]) -> Vec<u8> {
        let mut out = seed.to_vec();
        if out.is_empty() {
            out.push(HOSTILE_BYTES[rng.below(HOSTILE_BYTES.len())]);
            return out;
        }
        match rng.below(6) {
            0 => {
                // Single bit flip.
                let i = rng.below(out.len());
                out[i] ^= 1u8 << rng.below(8);
            }
            1 => {
                // Truncation — mid-JSON cuts.
                out.truncate(rng.below(out.len() + 1));
            }
            2 => {
                // Delete a run.
                let start = rng.below(out.len());
                let end = (start + 1 + rng.below(out.len() - start)).min(out.len());
                out.drain(start..end);
            }
            3 => {
                // Inject hostile bytes.
                let at = rng.below(out.len() + 1);
                let inj: Vec<u8> = (0..1 + rng.below(3))
                    .map(|_| HOSTILE_BYTES[rng.below(HOSTILE_BYTES.len())])
                    .collect();
                out.splice(at..at, inj);
            }
            4 => {
                // Splice in a JSON fragment.
                const FRAGMENTS: [&[u8]; 6] = [
                    br#"{"type":"#,
                    br#""challenge":""#,
                    b"null",
                    b"[",
                    br#""origin":"evil.example""#,
                    b"\"",
                ];
                let frag = FRAGMENTS[rng.below(FRAGMENTS.len())];
                let start = rng.below(out.len());
                let end = (start + rng.below(out.len() - start + 1)).min(out.len());
                out.splice(start..end, frag.iter().copied());
            }
            _ => {
                // Wholesale replacement with random bytes.
                out = (0..1 + rng.below(96))
                    .map(|_| (rng.next_u64() & 0xFF) as u8)
                    .collect();
            }
        }
        out
    }

    /// Mangle the field at `path` (dot-separated, e.g. `"user.id"`) inside
    /// `value`: delete it, or replace it with a hostile-typed value. Returns
    /// `false` (value untouched) if any hop along the path is missing.
    fn mangle_field(rng: &mut DetRng, value: &mut serde_json::Value, path: &str) -> bool {
        const REPLACEMENTS: usize = 4;
        let mut segs: Vec<&str> = path.split('.').collect();
        let Some(leaf) = segs.pop() else {
            return false;
        };
        let mut cur = value;
        for seg in segs {
            match cur.get_mut(seg) {
                Some(next) => cur = next,
                None => return false,
            }
        }
        if cur.get(leaf).is_none() {
            return false;
        }
        match rng.below(5) {
            0 => {
                // Field deletion.
                if let Some(obj) = cur.as_object_mut() {
                    obj.remove(leaf);
                }
            }
            _ => {
                // Wrong-typed replacement.
                let replacement = match rng.below(REPLACEMENTS) {
                    0 => serde_json::Value::Null,
                    1 => serde_json::json!(rng.next_u64() as i64),
                    2 => serde_json::json!("\u{10FFFF}"),
                    _ => serde_json::json!([null, "Y2hhbGxlbmdl", 42]),
                };
                if let Some(slot) = cur.get_mut(leaf) {
                    *slot = replacement;
                }
            }
        }
        true
    }

    /// One deterministic structural mutation of a creation-options Value.
    fn mutate_value(rng: &mut DetRng, base: &serde_json::Value) -> serde_json::Value {
        const PATHS: [&str; 8] = [
            "user",
            "user.id",
            "user.name",
            "user.displayName",
            "rp",
            "rp.id",
            "pubKeyCredParams",
            "pubKeyCredParams.0.alg",
        ];
        let mut out = base.clone();
        let path = PATHS[rng.below(PATHS.len())];
        let _ = mangle_field(rng, &mut out, path);
        out
    }

    /// A deterministic hostile string: scheme/port punctuation plus bytes that
    /// are not valid UTF-8 (lossily converted — the parsers see what a browser
    /// wire would give them).
    fn random_hostile_string(rng: &mut DetRng) -> String {
        const ALPHA: &[u8] = b"abc.-_:/\x80\xFF%?&=";
        let bytes: Vec<u8> = (0..rng.below(40))
            .map(|_| ALPHA[rng.below(ALPHA.len())])
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Self-consistency of a successful `parse_creation_options` result against
    /// the very options value it accepted.
    fn assert_options_ok_invariants(
        iter: usize,
        parsed: &ParsedCreationOptions,
        options: &serde_json::Value,
        origin: &str,
    ) {
        assert!(
            !parsed.user_handle.is_empty() && parsed.user_handle.len() <= 64,
            "iteration {iter}: user_handle must stay within WebAuthn §5.4.2 bounds, got {} bytes",
            parsed.user_handle.len()
        );
        let claimed_rp = options
            .get("rp")
            .and_then(|rp| rp.get("id"))
            .and_then(|v| v.as_str());
        match claimed_rp {
            Some(id) => assert_eq!(
                parsed.rp_id, id,
                "iteration {iter}: rp_id must echo rp.id when present"
            ),
            None => assert_eq!(
                parsed.rp_id,
                origin_host(origin).expect("Ok parse implies origin_host(origin) succeeds"),
                "iteration {iter}: rp_id must default to the origin host when rp.id is absent"
            ),
        }
    }

    #[test]
    fn fuzz_parse_client_data_never_panics_on_malformed_input() {
        const ORIGIN: &str = "https://example.com";
        let mut rng = DetRng::new(0x0FA1_1CE5_EED0_0001);

        // The clean seeds must parse — otherwise the loop below could be vacuous.
        for (create, expected_type) in [
            (true, CLIENT_DATA_TYPE_CREATE),
            (false, CLIENT_DATA_TYPE_GET),
        ] {
            let seed = client_data(create, "Y2hhbGxlbmdl", ORIGIN);
            let parsed = parse_client_data(&seed, expected_type, ORIGIN)
                .expect("clean clientDataJSON must parse");
            assert!(parsed.origin.eq_ignore_ascii_case(ORIGIN));
        }

        let mut accepted = 0usize;
        for i in 0..2_000 {
            let (create, expected_type) = if i % 2 == 0 {
                (true, CLIENT_DATA_TYPE_CREATE)
            } else {
                (false, CLIENT_DATA_TYPE_GET)
            };
            let seed = client_data(create, "Y2hhbGxlbmdl", ORIGIN);
            let input = mutate_bytes(&mut rng, &seed);
            if let Ok(parsed) = parse_client_data(&input, expected_type, ORIGIN) {
                // Accepting a mutated blob is only sound if the acceptance
                // contract still holds: the transport-verified origin matched
                // (case-insensitively, per impl) and the challenge is decodable.
                assert!(
                    parsed.origin.eq_ignore_ascii_case(ORIGIN),
                    "iteration {i}: accepted origin {:?} must equal {ORIGIN}",
                    parsed.origin
                );
                assert!(
                    decode_b64url(&parsed.challenge).is_ok(),
                    "iteration {i}: accepted challenge {:?} must be base64url",
                    parsed.challenge
                );
                accepted += 1;
            }
        }
        // Deterministic seed ⇒ fixed sequence: if this ever drops to zero the
        // mutation mix stopped reaching the acceptance path and the property
        // above has become vacuous.
        assert!(
            accepted > 0,
            "no mutated input was ever accepted — the Ok-path property above is vacuous"
        );

        // Fail-closed anchors: a deterministic checklist from §12's malformed
        // input list — each must produce Err, not a panic and not a pass.
        let anchors: [&[u8]; 7] = [
            b"",
            b"\xFF\xFE\xFD",                                       // invalid UTF-8
            br#"{"type":"webauthn.create","challenge":"Y2hh"#,     // truncated JSON
            br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#, // wrong ceremony
            br#"{"type":"webauthn.create","challenge":"!!not-b64!!","origin":"https://example.com"}"#, // bad base64url
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://evil.example"}"#, // origin mismatch
            br#"{"type":"webauthn.create"}"#, // missing fields
        ];
        for (i, anchor) in anchors.iter().enumerate() {
            assert!(
                parse_client_data(anchor, CLIENT_DATA_TYPE_CREATE, ORIGIN).is_err(),
                "anchor {i} {:?} must be rejected",
                String::from_utf8_lossy(anchor)
            );
        }
    }

    #[test]
    fn fuzz_parse_creation_options_never_panics_on_malformed_input() {
        const ORIGIN: &str = "https://example.com";
        let base = es256_options(Some("example.com"), Some("dXNlcg"));
        let mut rng = DetRng::new(0x0FA1_1CE5_EED0_0002);

        // The clean fixture must parse — otherwise both loops could be vacuous.
        parse_creation_options(&base, ORIGIN).expect("clean options must parse");

        // Layer 1: hostile JSON *text*. Most mutations stop at the serde gate;
        // whenever the text still deserializes, the semantic parser must take
        // the same no-panic guarantee.
        let base_text = serde_json::to_string(&base).expect("fixture serializes");
        let mut text_ok = 0usize;
        for i in 0..1_000 {
            let text = mutate_bytes(&mut rng, base_text.as_bytes());
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&text) {
                if let Ok(parsed) = parse_creation_options(&value, ORIGIN) {
                    assert_options_ok_invariants(i, &parsed, &value, ORIGIN);
                    text_ok += 1;
                }
            }
        }
        // Deterministic seed ⇒ fixed sequence: both counters are vacuity guards
        // for the property above, same rationale as the client-data loop.
        assert!(
            text_ok > 0,
            "no mutated JSON text was ever accepted — layer 1 is vacuous"
        );

        // Layer 2: structurally valid JSON whose fields are hostile — reaches
        // the semantic arms the serde layer cannot filter out.
        let mut struct_ok = 0usize;
        for i in 0..1_000 {
            let value = mutate_value(&mut rng, &base);
            if let Ok(parsed) = parse_creation_options(&value, ORIGIN) {
                assert_options_ok_invariants(i, &parsed, &value, ORIGIN);
                struct_ok += 1;
            }
        }
        assert!(
            struct_ok > 0,
            "no structurally mutated options were ever accepted — layer 2 is vacuous"
        );

        // Fail-closed anchors: semantic rejections the random layers may miss.
        let mut no_es256 = es256_options(Some("example.com"), Some("dXNlcg"));
        no_es256["pubKeyCredParams"] = serde_json::json!([{"type": "public-key", "alg": -257}]);

        let mut empty_id = es256_options(Some("example.com"), Some("dXNlcg"));
        empty_id["user"]["id"] = serde_json::json!("");

        let mut long_id = es256_options(Some("example.com"), Some("dXNlcg"));
        // 87 unpadded b64url chars decode to exactly 65 bytes (§5.4.2 max is 64).
        long_id["user"]["id"] = serde_json::json!("A".repeat(87));

        let mut nonstr_id = es256_options(Some("example.com"), Some("dXNlcg"));
        nonstr_id["user"]["id"] = serde_json::json!(42);

        let mut bad_b64_id = es256_options(Some("example.com"), Some("dXNlcg"));
        bad_b64_id["user"]["id"] = serde_json::json!("!!not-b64!!");

        for (anchor, why) in [
            (serde_json::json!({}), "empty options object"),
            (no_es256, "pubKeyCredParams without ES256 (alg -7)"),
            (empty_id, "user.id empty"),
            (long_id, "user.id decoding to 65 bytes"),
            (nonstr_id, "user.id not a string"),
            (bad_b64_id, "user.id not base64url"),
        ] {
            assert!(
                parse_creation_options(&anchor, ORIGIN).is_err(),
                "anchor [{why}] must be rejected"
            );
        }
    }

    #[test]
    fn fuzz_validate_origin_matches_rp_id_never_panics() {
        let mut rng = DetRng::new(0x0FA1_1CE5_EED0_0003);

        // Anchors around the registrable-domain approximation. The suffix- and
        // prefix-confusion cases are the security-critical ones: an attacker
        // domain must never be accepted for a victim rp_id.
        for (origin, rp, must_pass, why) in [
            ("https://example.com", "example.com", true, "exact match"),
            ("https://sub.example.com", "example.com", true, "subdomain"),
            (
                "http://localhost:8080",
                "localhost",
                true,
                "localhost with port",
            ),
            (
                "https://EXAMPLE.com",
                "example.COM",
                true,
                "case-insensitive match",
            ),
            (
                "https://evil-github.com",
                "github.com",
                false,
                "suffix confusion",
            ),
            (
                "https://github.com.evil.example",
                "github.com",
                false,
                "prefix confusion",
            ),
            (
                "https://github.com",
                "com",
                false,
                "public-suffix-only rp_id",
            ),
            (
                "https://github.com",
                "github.com.",
                false,
                "trailing-dot rp_id",
            ),
            (
                "https://github.com",
                "https://github.com",
                false,
                "rp_id is a URL",
            ),
            ("github.com", "github.com", false, "scheme-less origin"),
            ("https://", "github.com", false, "origin without host"),
            ("", "", false, "empty inputs"),
        ] {
            let result = validate_origin_matches_rp_id(origin, rp);
            assert_eq!(
                result.is_ok(),
                must_pass,
                "origin={origin:?} rp_id={rp:?} ({why}) -> {:?}",
                result.err().map(|e| e.to_string())
            );
        }

        // Random hostile pairs: never panic; acceptance must always satisfy the
        // "host == rp_id or host is a subdomain of rp_id" contract.
        let base_origin = "https://example.com";
        let base_rp = "example.com";
        for i in 0..600 {
            let origin = if i % 3 == 0 {
                String::from_utf8_lossy(&mutate_bytes(&mut rng, base_origin.as_bytes()))
                    .into_owned()
            } else {
                random_hostile_string(&mut rng)
            };
            let rp = if i % 3 == 0 {
                String::from_utf8_lossy(&mutate_bytes(&mut rng, base_rp.as_bytes())).into_owned()
            } else {
                random_hostile_string(&mut rng)
            };
            if validate_origin_matches_rp_id(&origin, &rp).is_ok() {
                let host =
                    origin_host(&origin).expect("Ok verdict implies origin_host(origin) works");
                let rp_checked =
                    validate_rp_id(&rp).expect("Ok verdict implies validate_rp_id(rp) works");
                assert!(
                    host == rp_checked || host.ends_with(&format!(".{rp_checked}")),
                    "iteration {i}: accepted origin={origin:?} rp_id={rp:?} but host={host:?} \
                     is neither equal to nor a subdomain of {rp_checked:?}"
                );
            }
        }
    }
}
