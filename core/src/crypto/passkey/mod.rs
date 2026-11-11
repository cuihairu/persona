// WebAuthn software-authenticator primitives (ES256 / P-256 only).
//
// Persona acts as a passkey provider: registration produces a `none`-format
// attestation, authentication produces an assertion over
// `authenticatorData || SHA-256(clientDataJSON)`. COSE/CBOR encoding is
// delegated to the audited `coset` crate and ECDSA to `p256`; the relying
// party side of these flows is exercised in tests against `webauthn-rs`.

pub mod ceremony;
pub mod client_data;
pub mod options;
pub mod rp;
pub mod seed;
pub mod verify;

/// client data `type` for credential creation (WebAuthn §5.8.1)
pub const CLIENT_DATA_TYPE_CREATE: &str = "webauthn.create";
/// client data `type` for authentication (WebAuthn §5.8.1)
pub const CLIENT_DATA_TYPE_GET: &str = "webauthn.get";

// authenticator data flag bits (WebAuthn §6.1)
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

pub use ceremony::{assert_passkey, register_passkey, AssertionOutput, RegistrationOutput};
pub use client_data::{
    local_client_data, parse_client_data, self_test_client_data, ParsedClientData,
};
pub use options::{parse_creation_options, ParsedCreationOptions};
pub use rp::validate_origin_matches_rp_id;
pub use seed::{aaguid, random_bytes32};
pub use verify::{
    cose_public_key, generate_signing_key, verify_assertion, verify_attestation,
    VerifiedRegistration,
};

#[cfg(test)]
use options::decode_b64url;
#[cfg(test)]
use rp::{origin_host, validate_rp_id};
#[cfg(test)]
use verify::att_map_get;

#[cfg(test)]
mod tests;
