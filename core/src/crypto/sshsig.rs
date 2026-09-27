//! SSHSIG（`ssh-keygen -Y`）签名：git commit 签名的 wire 格式与装甲。
//!
//! 契约 = OpenSSH PROTOCOL.sshsig（openssh-portable 仓库）。签名密钥只支持
//! ssh-ed25519——与本仓其余 SSH 面（`ssh generate`、agents/ssh-agent）一致；
//! RSA/ECDSA 待密钥层扩展后再补。
//!
//! 关键性质：RFC 8032 纯 ed25519 是**确定性**签名——同一 seed + namespace +
//! 消息必须产出与 `ssh-keygen -Y sign` 逐字节相同的结果。
//! [`sshsig_signs_byte_identical_to_openssh`] 把真 ssh-keygen 的输出钉成参照
//! 向量（生成方式：`ssh-keygen -t ed25519 -N ""` → 解析 OpenSSH 私钥容器取
//! seed → `ssh-keygen -Y sign -n git` → 全文照抄进测试）。
//!
//! wire 布局（大端）：`magic "SSHSIG" | version u32=1 | string pubkey_blob |
//! string namespace | string reserved="" | string hash_algo="sha512" |
//! string signature_blob`。`string` = SSH wire string（u32 长度 + 字节）。
//! **被签载荷**：`magic || namespace || reserved || hash_algo ||
//! sha512(message)`——version 不参与签名。
//! 装甲：BEGIN/END SSH SIGNATURE 之间 base64，70 字符换行（与 ssh-keygen
//! 一致）；解析端宽容处理任意换行/空白。

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

/// OpenSSH wire 格式的公钥 blob（string 算法名 + string 32 字节公钥）。
pub fn ed25519_pubkey_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut out = wire_string(ALGO);
    out.extend_from_slice(&wire_string(public));
    out
}

/// authorized_keys 行（与 `-f` 传入的公钥字面量/文件比对用）。
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
    // PROTOCOL.sshsig：被签载荷的每个字段都带 u32 长度前缀
    let mut payload = MAGIC.to_vec();
    payload.extend_from_slice(&wire_string(namespace.as_bytes()));
    payload.extend_from_slice(&wire_string(b""));
    payload.extend_from_slice(&wire_string(HASH_ALGO));
    payload.extend_from_slice(&wire_string(&Sha512::digest(message)));
    payload
}

/// 对 message 产生 SSHSIG 签名 blob（未装甲；接 [`armor`] 出文件内容）。
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

/// 解析 SSHSIG blob 并验证；成功返回签名里的公钥 blob。
/// namespace 必须与签名一致（namespace 绑定是 SSHSIG 的防跨协议重放设计，
/// ssh-keygen -Y verify 同样强制）。
pub fn verify(blob: &[u8], namespace: &str, message: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < MAGIC.len() + 4 {
        bail!("signature is too short to be an SSHSIG blob");
    }
    if &blob[..MAGIC.len()] != MAGIC {
        bail!("missing SSHSIG magic");
    }
    let mut rest = &blob[MAGIC.len()..];
    // version 是裸 u32，不是 wire string
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

/// 装甲化（BEGIN/END 之间 base64，70 字符换行 + 尾换行，与 ssh-keygen 一致）。
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

/// 解析装甲：剥掉 BEGIN/END 标记与所有空白后解码（不限行结构）。
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

    /// 真 ssh-keygen 参照向量（见模块注释的生成方式）。ed25519 确定性签名
    /// 意味着我们实现正确 ⇔ 这些字节完全一致；任何格式偏差（wire、哈希、
    /// 载荷拼装）都会让向量对不上。
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
        // namespace 绑定：换 namespace 必须拒（防跨协议重放）
        let err = verify(&blob, "file", REF_MESSAGE).unwrap_err().to_string();
        assert!(err.contains("namespace"), "{err}");
        // 消息被改一字节必须拒
        let tampered = b"hello persona\nsecond line!\n";
        let err = verify(&blob, "git", tampered).unwrap_err().to_string();
        assert!(err.contains("verification failed"), "{err}");
    }

    #[test]
    fn signatures_from_a_different_seed_carry_a_different_public_key() {
        // verify() 只校验 blob 内嵌公钥的自洽性（对应 ssh-keygen -Y verify 的
        // allowed_signers 之前的步骤）；密钥归属由调用方比对返回的公钥 blob——
        // CLI 层正是拿它和保险库里的 key 比对。
        let mut other_seed = REF_SEED;
        other_seed[0] ^= 1;
        let blob = sign(&other_seed, "git", REF_MESSAGE);
        let other_key = verify(&blob, "git", REF_MESSAGE).unwrap();
        let reference_key = verify(&disarmor(REF_ARMOR).unwrap(), "git", REF_MESSAGE).unwrap();
        assert_ne!(other_key, reference_key);
        // 换回参照密钥即对不上
        assert_ne!(hex::encode(&other_key), REF_PUBLIC_HEX);
    }

    #[test]
    fn armor_round_trips_and_parses_lenient_whitespace() {
        let blob = disarmor(REF_ARMOR).unwrap();
        assert_eq!(armor(&blob), REF_ARMOR);
        // CRLF、缺尾换行、行间空白都要能解析
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
