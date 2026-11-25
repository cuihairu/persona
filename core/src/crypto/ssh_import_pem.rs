//! PEM-family private key import (PKCS#8 / PKCS#1 / SEC1) — formats common
//! outside the OpenSSH container.
//!
//! Output from `openssl genpkey`, `genrsa -traditional`, and
//! `ecparam -genkey` all lands here. Decoding is delegated to the audited
//! RustCrypto crates: PKCS#8 via `pkcs8` (including encrypted PBES2
//! unlocking), PKCS#1/SEC1 field-level structures via `pkcs1` and `p256`
//! (no hand-written DER), and Ed25519 assembly via `ed25519-dalek`. This
//! module only does format sniffing (PEM label and PKCS#8 algorithm OID)
//! plus `ssh-key` container assembly (reusing the `ssh_import` storage
//! conventions).
//!
//! Passphrase handling matches OpenSSH import: an encrypted PKCS#8 is
//! unlocked at import time and the vault stores the unlocked OpenSSH PEM.
//! A protected PEM has no plaintext public-key half (unlike the OpenSSH
//! container), so an inspect must decrypt first to compute the
//! fingerprint — an inspect without a passphrase errors out asking for one,
//! and the caller surfaces the prompt.

use crate::{PersonaError, PersonaResult};
use pkcs8::der::asn1::{ObjectIdentifier, OctetStringRef};
use pkcs8::der::Decode;
use pkcs8::{EncryptedPrivateKeyInfoOwned, PrivateKeyInfoOwned, SecretDocument};
use ssh_key::private::{KeypairData, PrivateKey};

/// PKCS#8 algorithm OIDs: rsaEncryption / ecPublicKey / Ed25519.
/// The ecPublicKey parameters carry a named curve; P-256 or not is left to the p256 check.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Result of PEM header sniffing. The OpenSSH container header is not here — it is
/// handled first by the existing ssh_import path (inputs that match no known header
/// also go to that path for the error, keeping the error reporting consistent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PemKind {
    /// `-----BEGIN PRIVATE KEY-----` (plaintext PKCS#8; algorithm determined by OID)
    Pkcs8,
    /// `-----BEGIN ENCRYPTED PRIVATE KEY-----` (PBES2-encrypted PKCS#8)
    EncryptedPkcs8,
    /// `-----BEGIN RSA PRIVATE KEY-----`（PKCS#1 RSAPrivateKey）
    Pkcs1Rsa,
    /// `-----BEGIN EC PRIVATE KEY-----`（SEC1 ECPrivateKey）
    Sec1Ec,
}

/// Recognize a PEM label; returns None for unknown headers.
pub(super) fn sniff_pem(content: &str) -> Option<PemKind> {
    let c = content.trim_start();
    if c.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        Some(PemKind::EncryptedPkcs8)
    } else if c.starts_with("-----BEGIN PRIVATE KEY-----") {
        Some(PemKind::Pkcs8)
    } else if c.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        Some(PemKind::Pkcs1Rsa)
    } else if c.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        Some(PemKind::Sec1Ec)
    } else {
        None
    }
}

/// A dedicated hint for explicitly unsupported formats (distinct from a generic "unrecognized").
pub(super) fn unsupported_format_note(content: &str) -> Option<String> {
    if content.contains("PuTTY-User-Key-File") {
        Some(
            "PuTTY PPK private keys are not supported; \
             convert to OpenSSH format first (PuTTYgen → Conversions → Export OpenSSH key)"
                .to_string(),
        )
    } else {
        None
    }
}

/// Decode a PEM private key into an `ssh-key` container (unlocked plaintext).
pub(super) fn decode(
    kind: PemKind,
    pem: &str,
    passphrase: Option<&str>,
) -> PersonaResult<PrivateKey> {
    match kind {
        PemKind::Pkcs8 => decode_pkcs8(pem, None),
        PemKind::EncryptedPkcs8 => {
            let pass = passphrase.ok_or_else(|| {
                PersonaError::InvalidInput(
                    "Private key is an encrypted PKCS#8 PEM: passphrase required to preview \
                     or import"
                        .to_string(),
                )
            })?;
            decode_pkcs8(pem, Some(pass))
        }
        PemKind::Pkcs1Rsa => {
            // pkcs1's DER structure has no PEM entry point (DecodeRsaPrivateKey is only
            // implemented for the rsa crate's high-level types), so strip the PEM shell
            // ourselves and feed the inner layer through der::Decode
            let der = SecretDocument::from_pem(pem.trim())
                .map_err(|e| {
                    PersonaError::InvalidInput(format!("Failed to parse RSA PKCS#1 PEM: {e}"))
                })?
                .1;
            build_rsa(
                <pkcs1::RsaPrivateKey as pkcs1::der::Decode>::from_der(der.as_bytes()).map_err(
                    |e| PersonaError::InvalidInput(format!("Failed to decode RSA PKCS#1 key: {e}")),
                )?,
            )
        }
        PemKind::Sec1Ec => decode_sec1(pem),
    }
}

/// PKCS#8: unwrap the `PrivateKeyInfo` (decrypting PBES2 first when needed) and
/// dispatch by algorithm OID; the inner `private_key` bytes are a 32B seed wrapped
/// in a DER OCTET STRING for Ed25519 (RFC 8410's double wrapping), SEC1
/// ECPrivateKey DER for EC (RFC 5958/RFC 5915), and RSAPrivateKey DER for RSA
/// (RFC 5208 → PKCS#1).
fn decode_pkcs8(pem: &str, password: Option<&str>) -> PersonaResult<PrivateKey> {
    // PEM → DER via SecretDocument (key material is zeroized before it could ever hit disk)
    let der = SecretDocument::from_pem(pem.trim())
        .map_err(|e| {
            PersonaError::InvalidInput(format!("Failed to parse PKCS#8 private key PEM: {e}"))
        })?
        .1;
    // Plaintext DER is uniformly funneled into SecretDocument (pki borrows its bytes, so both must live equally long)
    let plain = match password {
        Some(pass) => {
            let encrypted =
                EncryptedPrivateKeyInfoOwned::from_der(der.as_bytes()).map_err(|_| {
                    PersonaError::InvalidInput(
                        "Failed to parse encrypted PKCS#8 private key".to_string(),
                    )
                })?;
            encrypted.decrypt(pass).map_err(|_| {
                PersonaError::InvalidInput(
                    "Failed to decrypt PKCS#8 private key: wrong passphrase or corrupted file"
                        .to_string(),
                )
            })?
        }
        None => der,
    };
    let pki = PrivateKeyInfoOwned::from_der(plain.as_bytes()).map_err(|e| {
        PersonaError::InvalidInput(format!("Failed to parse PKCS#8 private key: {e}"))
    })?;

    match pki.algorithm.oid {
        OID_ED25519 => {
            // RFC 8410 §7: inside privateKey's outer OCTET STRING is another DER
            // OCTET STRING (04 20 ‖ seed); both layers must be stripped to reach the 32B seed
            // der 0.8: the reference type's DecodeValue lands on &OctetStringRef
            let seed_ref =
                <&OctetStringRef as pkcs8::der::Decode>::from_der(pki.private_key.as_bytes())
                    .map_err(|e| {
                        PersonaError::InvalidInput(format!("Malformed Ed25519 PKCS#8 key: {e}"))
                    })?;
            let seed_bytes = seed_ref.as_bytes();
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                PersonaError::InvalidInput("Ed25519 private key seed must be 32 bytes".to_string())
            })?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            let keypair = ssh_key::private::Ed25519Keypair {
                public: ssh_key::public::Ed25519PublicKey(sk.verifying_key().to_bytes()),
                private: ssh_key::private::Ed25519PrivateKey::from(sk),
            };
            PrivateKey::new(KeypairData::Ed25519(keypair), "").map_err(|e| {
                PersonaError::CryptographicError(format!("Failed to build SSH key: {e}"))
            })
        }
        OID_EC_PUBLIC_KEY => {
            let secret =
                p256::SecretKey::from_sec1_der(pki.private_key.as_bytes()).map_err(|e| {
                    PersonaError::InvalidInput(format!(
                        "Failed to decode EC private key (only NIST P-256 is supported): {e}"
                    ))
                })?;
            Ok(build_ecdsa_p256(secret))
        }
        // pkcs1 0.7 stays on der 0.7 (pkcs8 0.11 is already der 0.8), so from_der resolves
        // each crate's own Decode trait; the pkcs1 side is specified explicitly here to avoid ambiguity
        OID_RSA_ENCRYPTION => build_rsa(
            <pkcs1::RsaPrivateKey as pkcs1::der::Decode>::from_der(pki.private_key.as_bytes())
                .map_err(|e| {
                    PersonaError::InvalidInput(format!("Failed to decode RSA private key: {e}"))
                })?,
        ),
        other => Err(PersonaError::InvalidInput(format!(
            "Unsupported private key algorithm OID: {other}"
        ))),
    }
}

/// SEC1 `ECPrivateKey` (`BEGIN EC PRIVATE KEY`); non-P-256 curves error out here.
fn decode_sec1(pem: &str) -> PersonaResult<PrivateKey> {
    let secret = p256::SecretKey::from_sec1_pem(pem.trim()).map_err(|e| {
        PersonaError::InvalidInput(format!(
            "Failed to decode SEC1 EC private key (only NIST P-256 is supported): {e}"
        ))
    })?;
    Ok(build_ecdsa_p256(secret))
}

fn build_ecdsa_p256(secret: p256::SecretKey) -> PrivateKey {
    let keypair = ssh_key::private::EcdsaKeypair::NistP256 {
        // ssh-key's field type is sec1::EncodedPoint<U32>; From<PublicKey> yields the uncompressed point
        public: secret.public_key().into(),
        private: ssh_key::private::EcdsaPrivateKey::from(secret),
    };
    // Assembly errors can only come from a curve/size mismatch, which was already validated as P-256 above
    PrivateKey::new(KeypairData::Ecdsa(keypair), "").expect("P-256 keypair validated by decode")
}

/// RSA (PKCS#8 / PKCS#1 unified here): pkcs1's field-level structure exposes n/e/d/p/q/
/// dp/dq/iqmp; the SSH wire format needs exactly d/iqmp/p/q + n/e, the coefficient is
/// iqmp, and no big-number is computed by hand. Multi-prime RSA (>2 primes) is rejected explicitly.
fn build_rsa(der_key: pkcs1::RsaPrivateKey<'_>) -> PersonaResult<PrivateKey> {
    if der_key.other_prime_infos.is_some() {
        return Err(PersonaError::InvalidInput(
            "Multi-prime RSA private keys are not supported".to_string(),
        ));
    }
    // ssh-key 0.7 switched all Mpint/public-private-key constructors to canonical-checking new()s:
    // from_positive_bytes returns an Mpint directly, and range checks are concentrated in one error path in new().
    let mp = ssh_key::Mpint::from_positive_bytes;
    let public = ssh_key::public::RsaPublicKey::new(
        mp(der_key.public_exponent.as_bytes()),
        mp(der_key.modulus.as_bytes()),
    )
    .map_err(|e| PersonaError::InvalidInput(format!("Invalid RSA public key: {e}")))?;
    let private = ssh_key::private::RsaPrivateKey::new(
        mp(der_key.private_exponent.as_bytes()),
        mp(der_key.coefficient.as_bytes()),
        mp(der_key.prime1.as_bytes()),
        mp(der_key.prime2.as_bytes()),
    )
    .map_err(|e| PersonaError::InvalidInput(format!("Invalid RSA private key: {e}")))?;
    let keypair = ssh_key::private::RsaKeypair::new(public, private)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid RSA keypair: {e}")))?;
    PrivateKey::new(KeypairData::Rsa(keypair), "")
        .map_err(|e| PersonaError::CryptographicError(format!("Failed to build SSH key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ssh_import::{import_private_key_file, inspect_private_key_file};
    use ssh_key::HashAlg;

    // One-shot openssl-generated test keys (never used in any real scenario):
    //   openssl genpkey -algorithm ed25519 / RSA 2048 / ecparam prime256v1
    //   openssl rsa -traditional; encrypted ones with -aes-128-cbc -pass pass:fixture-pass-1
    // Fingerprints obtained independently via ssh-keygen -lf and pinned here as a third-party referee.
    const ED25519_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKMDimteeX8+ZNEj5dWYYmLfi6CqdX8cZsKWyvXSUGTb
-----END PRIVATE KEY-----";
    const ED25519_PKCS8_FP: &str = "SHA256:dFtKDRZeeRorFCOVKXSjEDzH0cBmeRzSzwml+F8ISDY";

    const RSA_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2rkrELap3k1XW
jiBH4+FPPYyqNQYtca4l5LF3edVql87fMFW+qrQycVIzSz+l7C8EnXXVYW9Py5fU
hN0JfPlKkbQIbq+UwVvBYgHqS6TM/fNiLb5+UEpmGLkpW2E2JtgvETrmvMV5p4C4
4Z494G8hDf1JKj0AfGGZgRUqRvD/aqlp4yEOaKgi0QPWvzNomzRHbYOTjmjXmRns
VxubjFEyU/Mr7eZJ+8yqfEnJCuF111WWBrIJ465g7WN6HtutQz0+X+2jO0Zs3J6x
n6Yfo/Vsj9f3mKSE0K5WfVnpJoUYW/V/WI85r37CcqHD5wUPFEIIwlIglv8xA/cs
8853jh7fAgMBAAECggEANpzvhCukyT+2S0DNHMDfJEnhyia09JQGPJTcizvUlhvR
QD8aezhcS7I+IVCPNCLiQY5zYjnRRbk3aFTaIdKHUogxms3AVwfhTvRmXy2DFLec
8c58IxYMz+33OQp1CvPc8GFFyyJHJSHy5RKqNJRqlKaygJOMjh8hLHt/INb5iFnQ
g/qT0kv8N2Q8SPfqCk/wq64QWDiK1q1O7ur6vjriaIN1aDq+dFQVn6MkvUy5K4SW
NiT+mIdiizwgEbY1JZBJLM4VsNY8MwZMMJRnss0xt0ck03IzV5DxLkxJJuoCBM4H
cT20hXfNRbg7bXEOZfdt1/Op83XfZTWnZ/kQvoTKbQKBgQDsF9sCH48v6rOTTE4o
G3XIQ/50aZCWLNkqO2AJe2iUhNRZumy4jqLCg76om6wLaX0y8s38apqRXjifJief
w+WfNNQ+Q8MAAFBc5n7IKy9LV233BuJSVHqekBjmwEK5zzE/JtB82O4NYlryfRD8
Q4vt7N1zToOdM2acaekuBflvPQKBgQDGFYOodpPR5p10IZ8pSQ6EXgaCb+QHh7Kb
eE+lBsAQ6RUIRMU5oluvqjJQBg3+7DthhbVxaozyF85NBb2+lwKZ90nqkF8C1ehM
mdCyEBDo+iiw/G6n0/DyBs2CbMynmQ2Y9oAQt14O2xJfD5X0AaKvg+oFDqqFjKFg
ntQu+A0oSwKBgCCUmjCM0mG2bdmh6hc20uY0G+VMvBs9TSq6zuIAGcqFGhjX1TES
3fsh2ynBcdiRUim5wBtZSsNM0VuFFGrDyehSjgeZqktRv8VSOaS98OTgx9gTJyBd
cB55nDYbyhmCMjWY0aSo+xD1xb846yMk3yaSTW0gJKGI+lwTcY5cXLOxAoGBAKn3
R/NDW+9dvHkraFCamVRHAbrmm3lCnKT+hQiLVD6uYRepOroLcDS5C1bS+ytkNEen
3VqmHK6WcrRwWrGxDdBi+g/FNWFPfnZL/WDsnDXsgQHseF6VY0epQqnJBYpBsAMy
cAzn6lNA8vCShQ7MYHXN8P3J6dOSKd6oKlTrDw8lAoGBAMv+ZdAjDproi1J1fUL6
1L9cju6oN1QOR/x1R4Wrnlaxx2KMz1AmjkQtJFBHrO7LthZo90Pl6dWNH74dNlO1
k051WEQm94prEoDGejqZl5uO+f73YqgklNaNsR6gZa+XsNbcdnEHHSwVuxEIfWmb
DsPqD4LAXSTZdo7t96i5GcOy
-----END PRIVATE KEY-----";
    const RSA_PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtq5KxC2qd5NV1o4gR+PhTz2MqjUGLXGuJeSxd3nVapfO3zBV
vqq0MnFSM0s/pewvBJ111WFvT8uX1ITdCXz5SpG0CG6vlMFbwWIB6kukzP3zYi2+
flBKZhi5KVthNibYLxE65rzFeaeAuOGePeBvIQ39SSo9AHxhmYEVKkbw/2qpaeMh
DmioItED1r8zaJs0R22Dk45o15kZ7Fcbm4xRMlPzK+3mSfvMqnxJyQrhdddVlgay
CeOuYO1jeh7brUM9Pl/toztGbNyesZ+mH6P1bI/X95ikhNCuVn1Z6SaFGFv1f1iP
Oa9+wnKhw+cFDxRCCMJSIJb/MQP3LPPOd44e3wIDAQABAoIBADac74QrpMk/tktA
zRzA3yRJ4comtPSUBjyU3Is71JYb0UA/Gns4XEuyPiFQjzQi4kGOc2I50UW5N2hU
2iHSh1KIMZrNwFcH4U70Zl8tgxS3nPHOfCMWDM/t9zkKdQrz3PBhRcsiRyUh8uUS
qjSUapSmsoCTjI4fISx7fyDW+YhZ0IP6k9JL/DdkPEj36gpP8KuuEFg4itatTu7q
+r464miDdWg6vnRUFZ+jJL1MuSuEljYk/piHYos8IBG2NSWQSSzOFbDWPDMGTDCU
Z7LNMbdHJNNyM1eQ8S5MSSbqAgTOB3E9tIV3zUW4O21xDmX3bdfzqfN132U1p2f5
EL6Eym0CgYEA7BfbAh+PL+qzk0xOKBt1yEP+dGmQlizZKjtgCXtolITUWbpsuI6i
woO+qJusC2l9MvLN/GqakV44nyYnn8PlnzTUPkPDAABQXOZ+yCsvS1dt9wbiUlR6
npAY5sBCuc8xPybQfNjuDWJa8n0Q/EOL7ezdc06DnTNmnGnpLgX5bz0CgYEAxhWD
qHaT0eaddCGfKUkOhF4Ggm/kB4eym3hPpQbAEOkVCETFOaJbr6oyUAYN/uw7YYW1
cWqM8hfOTQW9vpcCmfdJ6pBfAtXoTJnQshAQ6PoosPxup9Pw8gbNgmzMp5kNmPaA
ELdeDtsSXw+V9AGir4PqBQ6qhYyhYJ7ULvgNKEsCgYAglJowjNJhtm3ZoeoXNtLm
NBvlTLwbPU0qus7iABnKhRoY19UxEt37IdspwXHYkVIpucAbWUrDTNFbhRRqw8no
Uo4HmapLUb/FUjmkvfDk4MfYEycgXXAeeZw2G8oZgjI1mNGkqPsQ9cW/OOsjJN8m
kk1tICShiPpcE3GOXFyzsQKBgQCp90fzQ1vvXbx5K2hQmplURwG65pt5Qpyk/oUI
i1Q+rmEXqTq6C3A0uQtW0vsrZDRHp91aphyulnK0cFqxsQ3QYvoPxTVhT352S/1g
7Jw17IEB7HhelWNHqUKpyQWKQbADMnAM5+pTQPLwkoUOzGB1zfD9yenTkineqCpU
6w8PJQKBgQDL/mXQIw6a6ItSdX1C+tS/XI7uqDdUDkf8dUeFq55WscdijM9QJo5E
LSRQR6zuy7YWaPdD5enVjR++HTZTtZNOdVhEJveKaxKAxno6mZebjvn+92KoJJTW
jbEeoGWvl7DW3HZxBx0sFbsRCH1pmw7D6g+CwF0k2XaO7feouRnDsg==
-----END RSA PRIVATE KEY-----";
    const RSA_FP: &str = "SHA256:IVojBIR5zu1jlmWCOTC5ZHycjS7xrLWORTWVZN/QXO4";

    const EC_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFtYnHE9oaiIxJJ8hKvzPoUDJ50joAeohJKSVBtMTxdRoAoGCCqGSM49
AwEHoUQDQgAEWoAsrEJ6xfEyIfhv1E7aDKbIuxRJkAgww6uLGKPj7TejQG28qc6X
aPFZWt6j8Yk+Hv0necdm9z6Rhk1uepkj4g==
-----END EC PRIVATE KEY-----";
    const EC_FP: &str = "SHA256:TDpOFgHyZfNP3O192D0azqBHZGq2VEcxyqaZoN5fGUY";

    const ED25519_ENCRYPTED_PKCS8: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCrwkz0De3qYTGcS24y
qSCaAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBAgQQOMVVNthVrncZEDiI
GwkpzgRArm28dVEj732Z5SfPnv2AtlHHfOAMbYkQE0Zk8ZLzJJNlJh2l3CAot6uu
qkbvrvWWzBSQPEC0FxGXt6QnwJvTdA==
-----END ENCRYPTED PRIVATE KEY-----";
    const ED25519_ENCRYPTED_FP: &str = "SHA256:ho2O69nQ2o6hszOuYlGNyb+uA4y8c5fLh3h6ZHFwOCc";
    const ENCRYPTED_PASS: &str = "fixture-pass-1";

    fn assert_roundtrip(imported: &crate::crypto::ssh_import::ImportedSshKey, fp: &str) {
        assert_eq!(imported.fingerprint, fp);
        // Independent referee: the stored OpenSSH PEM must re-parse natively under ssh-key with a matching fingerprint
        let reparsed = PrivateKey::from_openssh(&imported.private_key_pem)
            .expect("converted PEM must re-parse as OpenSSH");
        assert_eq!(
            reparsed
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string(),
            fp
        );
    }

    #[test]
    fn pkcs8_ed25519_imports_with_openssl_fingerprint() {
        let imported = import_private_key_file(ED25519_PKCS8, None).unwrap();
        assert_eq!(imported.key_type, "ed25519");
        assert_eq!(imported.ssh_algorithm, "ssh-ed25519");
        assert!(imported.public_key.starts_with("ssh-ed25519 "));
        assert_roundtrip(&imported, ED25519_PKCS8_FP);
    }

    #[test]
    fn pkcs8_rsa_imports_with_openssl_fingerprint() {
        let imported = import_private_key_file(RSA_PKCS8, None).unwrap();
        assert_eq!(imported.key_type, "rsa");
        assert!(imported.public_key.starts_with("ssh-rsa "));
        assert_roundtrip(&imported, RSA_FP);
    }

    #[test]
    fn pkcs1_rsa_imports_to_same_key_as_pkcs8() {
        let imported = import_private_key_file(RSA_PKCS1, None).unwrap();
        assert_eq!(imported.key_type, "rsa");
        assert_roundtrip(&imported, RSA_FP);
        let via_pkcs8 = import_private_key_file(RSA_PKCS8, None).unwrap();
        assert_eq!(imported.public_key, via_pkcs8.public_key);
    }

    #[test]
    fn sec1_ec_p256_imports_with_openssl_fingerprint() {
        let imported = import_private_key_file(EC_SEC1, None).unwrap();
        assert_eq!(imported.key_type, "ecdsa");
        assert_eq!(imported.ssh_algorithm, "ecdsa-sha2-nistp256");
        assert_roundtrip(&imported, EC_FP);
    }

    #[test]
    fn encrypted_pkcs8_imports_with_passphrase() {
        let imported = import_private_key_file(ED25519_ENCRYPTED_PKCS8, Some(ENCRYPTED_PASS))
            .expect("correct passphrase must unlock");
        assert_roundtrip(&imported, ED25519_ENCRYPTED_FP);
        // Storage convention: the unlocked plaintext OpenSSH PEM; the encrypted shell does not travel along
        assert!(!imported.private_key_pem.contains("ENCRYPTED"));
    }

    #[test]
    fn encrypted_pkcs8_requires_passphrase() {
        let err = import_private_key_file(ED25519_ENCRYPTED_PKCS8, None).unwrap_err();
        assert!(err.to_string().contains("passphrase required"), "{err}");
    }

    #[test]
    fn encrypted_pkcs8_rejects_wrong_passphrase() {
        let err = import_private_key_file(ED25519_ENCRYPTED_PKCS8, Some("wrong-pass")).unwrap_err();
        assert!(err.to_string().contains("wrong passphrase"), "{err}");
    }

    #[test]
    fn inspect_on_encrypted_pem_asks_for_passphrase() {
        let err = inspect_private_key_file(ED25519_ENCRYPTED_PKCS8).unwrap_err();
        assert!(err.to_string().contains("passphrase required"), "{err}");
    }

    #[test]
    fn inspect_on_plaintext_pem_previews_without_passphrase() {
        let inspection = inspect_private_key_file(ED25519_PKCS8).unwrap();
        assert_eq!(inspection.fingerprint, ED25519_PKCS8_FP);
        assert!(!inspection.encrypted);
    }

    #[test]
    fn putty_ppk_gets_dedicated_hint() {
        let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: \n";
        let err = import_private_key_file(ppk, None).unwrap_err();
        assert!(err.to_string().contains("PuTTY"), "{err}");
    }

    #[test]
    fn unrecognized_content_lists_supported_formats() {
        let err = import_private_key_file("hello world", None).unwrap_err();
        let msg = err.to_string();
        // No PEM header: say plainly it is not a PEM + list the full expected-format roster
        assert!(msg.contains("not a PEM private key file"), "{msg}");
        assert!(msg.contains("BEGIN OPENSSH PRIVATE KEY"), "{msg}");
        assert!(msg.contains("BEGIN RSA PRIVATE KEY"), "{msg}");
    }

    #[test]
    fn sniffer_maps_labels() {
        assert_eq!(
            sniff_pem("-----BEGIN PRIVATE KEY-----\nx"),
            Some(PemKind::Pkcs8)
        );
        assert_eq!(
            sniff_pem("  -----BEGIN ENCRYPTED PRIVATE KEY-----\nx"),
            Some(PemKind::EncryptedPkcs8)
        );
        assert_eq!(
            sniff_pem("-----BEGIN RSA PRIVATE KEY-----\nx"),
            Some(PemKind::Pkcs1Rsa)
        );
        assert_eq!(
            sniff_pem("-----BEGIN EC PRIVATE KEY-----\nx"),
            Some(PemKind::Sec1Ec)
        );
        assert_eq!(sniff_pem("-----BEGIN OPENSSH PRIVATE KEY-----\nx"), None);
        assert_eq!(sniff_pem("garbage"), None);
    }
}
