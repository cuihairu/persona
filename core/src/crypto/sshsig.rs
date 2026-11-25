//! SSHSIG (`ssh-keygen -Y`) signatures: the wire format and armor used for
//! git commit signing.
//!
//! The contract is OpenSSH PROTOCOL.sshsig (openssh-portable repository). Only
//! ssh-ed25519 signing keys are supported, to stay consistent with the rest of
//! this repo's SSH surface (`ssh generate`, agents/ssh-agent); RSA/ECDSA come
//! later once the key layer is extended.
//!
//! Key property: pure RFC 8032 ed25519 is **deterministic** — the same seed +
//! namespace + message must yield output byte-identical to
//! `ssh-keygen -Y sign`. [`sshsig_signs_byte_identical_to_openssh`] pins real
//! ssh-keygen output as the reference vector (how it was produced:
//! `ssh-keygen -t ed25519 -N ""` -> parse the OpenSSH private-key container to
//! get the seed -> `ssh-keygen -Y sign -n git` -> copy the full text verbatim
//! into the test).
//!
//! Wire layout (big-endian): `magic "SSHSIG" | version u32=1 | string
//! pubkey_blob | string namespace | string reserved="" |
//! string hash_algo="sha512" | string signature_blob`. `string` = an SSH wire
//! string (u32 length + bytes). **Signed payload**:
//! `magic || namespace || reserved || hash_algo || sha512(message)` —
//! version does not participate in the signature.
//! Armor: base64 between BEGIN/END SSH SIGNATURE, wrapped at 70 characters
//! (matching ssh-keygen); the parser tolerates any line breaks and whitespace.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use sha2::{Digest, Sha512};

const MAGIC: &[u8] = b"SSHSIG";
const VERSION: u32 = 1;
const ALGO: &[u8] = b"ssh-ed25519";
const HASH_ALGO: &[u8] = b"sha512";
const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";
const ARMOR_LINE_WIDTH: usize = 70;

fn wire_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

fn take_wire_string(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    if bytes.len() < 4 {
        bail!("truncated SSH wire string");
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let rest = &bytes[4..];
    if rest.len() < len {
        bail!("SSH wire string overruns the buffer");
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Public-key blob in OpenSSH wire format (string algorithm name + string
/// 32-byte public key).
pub fn ed25519_pubkey_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut out = wire_string(ALGO);
    out.extend_from_slice(&wire_string(public));
    out
}

/// The authorized_keys line (for comparing against the public-key literal or
/// file passed to `-f`).
pub fn ed25519_authorized_line(public: &[u8; 32], comment: Option<&str>) -> String {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    let b64 = BASE64.encode(ed25519_pubkey_blob(public));
    match comment {
        Some(comment) if !comment.trim().is_empty() => format!("ssh-ed25519 {b64} {comment}"),
        _ => format!("ssh-ed25519 {b64}"),
    }
}

fn signed_payload(namespace: &str, message: &[u8]) -> Vec<u8> {
    // PROTOCOL.sshsig: every field of the signed payload carries a u32 length prefix
    let mut payload = MAGIC.to_vec();
    payload.extend_from_slice(&wire_string(namespace.as_bytes()));
    payload.extend_from_slice(&wire_string(b""));
    payload.extend_from_slice(&wire_string(HASH_ALGO));
    payload.extend_from_slice(&wire_string(&Sha512::digest(message)));
    payload
}

/// Produce the SSHSIG signature blob for `message` (unarmored; feed it to
/// [`armor`] for the file contents).
pub fn sign(seed: &[u8; 32], namespace: &str, message: &[u8]) -> Vec<u8> {
    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key().to_bytes();
    let signature = signing.sign(&signed_payload(namespace, message));

    let mut blob = MAGIC.to_vec();
    blob.extend_from_slice(&VERSION.to_be_bytes());
    blob.extend_from_slice(&wire_string(&ed25519_pubkey_blob(&public)));
    blob.extend_from_slice(&wire_string(namespace.as_bytes()));
    blob.extend_from_slice(&wire_string(b""));
    blob.extend_from_slice(&wire_string(HASH_ALGO));
    let mut signature_blob = wire_string(ALGO);
    signature_blob.extend_from_slice(&wire_string(&signature.to_bytes()));
    blob.extend_from_slice(&wire_string(&signature_blob));
    blob
}

/// Parse an SSHSIG blob and verify it; on success returns the public-key blob
/// carried by the signature. The namespace must match the signature (namespace
/// binding is SSHSIG's defense against cross-protocol replay, and
/// `ssh-keygen -Y verify` enforces it too).
pub fn verify(blob: &[u8], namespace: &str, message: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < MAGIC.len() + 4 {
        bail!("signature is too short to be an SSHSIG blob");
    }
    if &blob[..MAGIC.len()] != MAGIC {
        bail!("missing SSHSIG magic");
    }
    let mut rest = &blob[MAGIC.len()..];
    // version is a bare u32, not a wire string
    let version = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    rest = &rest[4..];
    if version != VERSION {
        bail!("unsupported SSHSIG version {version}");
    }
    let (public_key_blob, r) = take_wire_string(rest)?;
    let (signed_namespace, r) = take_wire_string(r)?;
    if signed_namespace != namespace.as_bytes() {
        bail!(
            "signature namespace {:?} does not match expected {:?}",
            String::from_utf8_lossy(signed_namespace),
            namespace
        );
    }
    let (reserved, r) = take_wire_string(r)?;
    if !reserved.is_empty() {
        bail!("non-empty reserved field is not supported");
    }
    let (hash_algo, r) = take_wire_string(r)?;
    if hash_algo != HASH_ALGO {
        bail!(
            "unsupported hash algorithm {:?}",
            String::from_utf8_lossy(hash_algo)
        );
    }
    let (signature_blob, r) = take_wire_string(r)?;
    if !r.is_empty() {
        bail!("trailing bytes after the signature blob");
    }
    let (sig_algo, r) = take_wire_string(signature_blob)?;
    if sig_algo != ALGO {
        bail!(
            "unsupported signature algorithm {:?}",
            String::from_utf8_lossy(sig_algo)
        );
    }
    let (sig_bytes, r) = take_wire_string(r)?;
    if !r.is_empty() {
        bail!("trailing bytes inside the signature blob");
    }
    let signature = Signature::from_slice(sig_bytes).context("malformed ed25519 signature")?;
    let public: [u8; 32] = {
        let (algo, rest) = take_wire_string(public_key_blob)?;
        if algo != ALGO {
            bail!(
                "unsupported public key algorithm {:?}",
                String::from_utf8_lossy(algo)
            );
        }
        let (key_bytes, rest) = take_wire_string(rest)?;
        if !rest.is_empty() || key_bytes.len() != 32 {
            bail!("public key blob is not a valid ssh-ed25519 key");
        }
        key_bytes.try_into().expect("length checked above")
    };
    let verifying =
        ed25519_dalek::VerifyingKey::from_bytes(&public).context("malformed ed25519 public key")?;
    verifying
        .verify(&signed_payload(namespace, message), &signature)
        .context("signature verification failed")?;
    Ok(public_key_blob.to_vec())
}

/// Armor the blob (base64 between BEGIN/END, wrapped at 70 characters plus a
/// trailing newline, matching ssh-keygen).
pub fn armor(blob: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
    let mut out = String::with_capacity(BEGIN.len() + encoded.len() + END.len() + 4);
    out.push_str(BEGIN);
    out.push('\n');
    for chunk in encoded.as_bytes().chunks(ARMOR_LINE_WIDTH) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// Parse armor: strip the BEGIN/END markers and all whitespace, then decode
/// (no restriction on the line structure).
pub fn disarmor(text: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    if !text.contains(BEGIN) || !text.contains(END) {
        bail!("no SSH signature armor found");
    }
    let body: String = text
        .replace(BEGIN, "")
        .replace(END, "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        bail!("no SSH signature armor found");
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .context("SSH signature armor is not valid base64")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real ssh-keygen reference vectors (see the module comment for how they were
    /// produced). Ed25519 signatures are deterministic, so our implementation
    /// is correct iff these bytes match exactly; any formatting deviation
    /// (wire, hashing, payload assembly) would break the vectors.
    const REF_SEED: [u8; 32] = [
        0x59, 0xd9, 0x98, 0xd6, 0xdb, 0x19, 0xcc, 0x8f, 0x7f, 0xe2, 0x45, 0xfa, 0x8a, 0x04, 0xe6,
        0x10, 0xd8, 0x84, 0x5d, 0xff, 0x80, 0xdb, 0xec, 0x8d, 0xfc, 0x88, 0x15, 0xe1, 0x8e, 0xa0,
        0x83, 0x8d,
    ];
    const REF_PUBLIC_HEX: &str = "268b101e70186ddcf6cedab6fc4bdc59d43d9f86c2aa7f60eb0b7d0ab325e360";
    const REF_MESSAGE: &[u8] = b"hello persona\nsecond line\n";
    const REF_ARMOR: &str = concat!(
        "-----BEGIN SSH SIGNATURE-----\n",
        "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJosQHnAYbdz2ztq2/EvcWdQ9n4\n",
        "bCqn9g6wt9CrMl42AAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5\n",
        "AAAAQJt/PJ1nuI6ToAzsanR3MLYqM2qiVC5IWESIGbXh6o4hiHoB8ng7N1/2nUDiqAq55b\n",
        "nM36bAlsZrid+A5TX5agU=\n",
        "-----END SSH SIGNATURE-----\n",
    );

    #[test]
    fn sshsig_signs_byte_identical_to_openssh() {
        let blob = sign(&REF_SEED, "git", REF_MESSAGE);
        assert_eq!(
            armor(&blob),
            REF_ARMOR,
            "must match ssh-keygen byte-for-byte"
        );
    }

    #[test]
    fn verify_accepts_the_reference_signature() {
        let blob = disarmor(REF_ARMOR).unwrap();
        let public_key = verify(&blob, "git", REF_MESSAGE).unwrap();
        use base64::Engine as _;
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&public_key),
            "AAAAC3NzaC1lZDI1NTE5AAAAICaLEB5wGG3c9s7atvxL3FnUPZ+Gwqp/YOsLfQqzJeNg",
        );
    }

    #[test]
    fn verify_binds_namespace_and_detects_tampering() {
        let blob = disarmor(REF_ARMOR).unwrap();
        // Namespace binding: a different namespace must be rejected (defense against
        // cross-protocol replay)
        let err = verify(&blob, "file", REF_MESSAGE).unwrap_err().to_string();
        assert!(err.contains("namespace"), "{err}");
        // A single byte of message tampering must be rejected
        let tampered = b"hello persona\nsecond line!\n";
        let err = verify(&blob, "git", tampered).unwrap_err().to_string();
        assert!(err.contains("verification failed"), "{err}");
    }

    #[test]
    fn signatures_from_a_different_seed_carry_a_different_public_key() {
        // verify() only checks the self-consistency of the public key embedded in the
        // blob (the step in `ssh-keygen -Y verify` that precedes
        // allowed_signers); key ownership is established by the caller
        // comparing the returned public-key blob — the CLI layer is exactly
        // what compares it against the key in the vault.
        let mut other_seed = REF_SEED;
        other_seed[0] ^= 1;
        let blob = sign(&other_seed, "git", REF_MESSAGE);
        let other_key = verify(&blob, "git", REF_MESSAGE).unwrap();
        let reference_key = verify(&disarmor(REF_ARMOR).unwrap(), "git", REF_MESSAGE).unwrap();
        assert_ne!(other_key, reference_key);
        // And it does not match the reference key's hex
        assert_ne!(hex::encode(&other_key), REF_PUBLIC_HEX);
    }

    #[test]
    fn armor_round_trips_and_parses_lenient_whitespace() {
        let blob = disarmor(REF_ARMOR).unwrap();
        assert_eq!(armor(&blob), REF_ARMOR);
        // CRLF, a missing trailing newline and inter-line whitespace must all parse
        let crlf = REF_ARMOR.replace('\n', "\r\n");
        assert_eq!(disarmor(&crlf).unwrap(), blob);
        let single_line = REF_ARMOR.replace('\n', " ");
        assert_eq!(disarmor(&single_line).unwrap(), blob);
        assert!(disarmor("no armor here").is_err());
    }

    #[test]
    fn authorized_line_matches_the_reference_public_key() {
        let mut public = [0u8; 32];
        for (i, byte) in hex::decode(REF_PUBLIC_HEX).unwrap().iter().enumerate() {
            public[i] = *byte;
        }
        assert_eq!(
            ed25519_authorized_line(&public, None),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaLEB5wGG3c9s7atvxL3FnUPZ+Gwqp/YOsLfQqzJeNg",
        );
    }
}
