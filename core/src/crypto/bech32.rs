// Bech32 / Bech32m encoding per BIP-173 and BIP-350.
//
// Used for Bitcoin native SegWit (witness v0, bech32) and Taproot
// (witness v1+, bech32m) addresses. Implemented locally to avoid adding a
// new dependency; verified against the test vectors from both BIPs.

use crate::{PersonaError, PersonaResult};

/// Checksum variant (BIP-350).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bech32Variant {
    /// Original bech32 checksum (BIP-173), witness version 0.
    Bech32,
    /// Bech32m checksum (BIP-350), witness version 1+.
    Bech32m,
}

impl Bech32Variant {
    fn checksum_const(self) -> u32 {
        match self {
            Self::Bech32 => 1,
            Self::Bech32m => BECH32M_CONST,
        }
    }
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Encode a SegWit address (witness program) for the given human-readable
/// part. Witness version 0 uses bech32, versions 1+ use bech32m.
pub fn encode_witness_address(hrp: &str, version: u8, program: &[u8]) -> PersonaResult<String> {
    if version > 16 {
        return Err(PersonaError::InvalidInput(format!(
            "Invalid witness version: {}",
            version
        )));
    }
    if program.len() < 2 || program.len() > 40 {
        return Err(PersonaError::InvalidInput(
            "Witness program length must be 2-40 bytes".to_string(),
        ));
    }

    let variant = if version == 0 {
        Bech32Variant::Bech32
    } else {
        Bech32Variant::Bech32m
    };

    let mut data = vec![version];
    data.extend_from_slice(&convert_bits(program, 8, 5, true)?);
    encode_with_hrp(hrp, &data, variant)
}

/// Decode a SegWit address into `(hrp, witness_version, witness_program)`.
/// Enforces the BIP-173/350 rules: version 0 must be bech32, 1+ must be
/// bech32m, program length 2-40, and valid checksum.
pub fn decode_witness_address(address: &str) -> PersonaResult<(String, u8, Vec<u8>)> {
    let (hrp, data) = decode_no_limit(address)?;
    if data.is_empty() {
        return Err(PersonaError::InvalidInput("Empty witness data".to_string()));
    }
    let version = data[0];
    let expected = if version == 0 {
        Bech32Variant::Bech32
    } else if version <= 16 {
        Bech32Variant::Bech32m
    } else {
        return Err(PersonaError::InvalidInput(format!(
            "Invalid witness version: {}",
            version
        )));
    };
    if verify_checksum(&hrp, &data) != expected.checksum_const() {
        return Err(PersonaError::InvalidInput(
            "Invalid witness address checksum variant".to_string(),
        ));
    }
    // Drop the witness version byte and the 6 checksum symbols before
    // regrouping the payload.
    let payload = &data[1..data.len() - 6];
    let program = convert_bits(payload, 5, 8, false)?;
    if program.len() < 2 || program.len() > 40 {
        return Err(PersonaError::InvalidInput(
            "Witness program length must be 2-40 bytes".to_string(),
        ));
    }
    Ok((hrp, version, program))
}

fn encode_with_hrp(hrp: &str, data: &[u8], variant: Bech32Variant) -> PersonaResult<String> {
    if hrp.chars().any(|c| !('!'..='~').contains(&c)) {
        return Err(PersonaError::InvalidInput(
            "HRP contains invalid characters".to_string(),
        ));
    }
    let hrp_lower = hrp.to_lowercase();
    let mut combined = data.to_vec();
    combined.extend_from_slice(&create_checksum(&hrp_lower, data, variant));
    let mut out = String::with_capacity(hrp_lower.len() + 1 + combined.len());
    out.push_str(&hrp_lower);
    out.push('1');
    for &d in &combined {
        let c = CHARSET[d as usize];
        out.push(c as char);
    }
    Ok(out)
}

fn create_checksum(hrp: &str, data: &[u8], variant: Bech32Variant) -> [u8; 6] {
    let mut polymod_input = hrp_expand(hrp);
    polymod_input.extend_from_slice(data);
    polymod_input.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = poly_mod(&polymod_input) ^ variant.checksum_const();
    let mut checksum = [0u8; 6];
    for (i, item) in checksum.iter_mut().enumerate() {
        *item = ((polymod >> (5 * (5 - i))) & 31) as u8;
    }
    checksum
}

fn verify_checksum(hrp: &str, data: &[u8]) -> u32 {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    poly_mod(&values)
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|b| b & 31));
    v
}

fn poly_mod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ value as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> PersonaResult<Vec<u8>> {
    if !(1..=8).contains(&from) || !(1..=8).contains(&to) {
        return Err(PersonaError::InvalidInput("Invalid bit width".to_string()));
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let max_out_value = (1u32 << to) - 1;
    // Mask the accumulator so stale high bits cannot leak into the
    // padding check (matches the BIP-173 reference implementation).
    let max_acc_value = (1u32 << (from + to - 1)) - 1;
    for &value in data {
        let value = value as u32;
        if (value >> from) != 0 {
            return Err(PersonaError::InvalidInput(
                "Value exceeds input bit width".to_string(),
            ));
        }
        acc = ((acc << from) | value) & max_acc_value;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max_out_value) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max_out_value) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max_out_value) != 0 {
        return Err(PersonaError::InvalidInput(
            "Invalid padding in bech32 data".to_string(),
        ));
    }
    Ok(out)
}

/// Parse an address into `(hrp, data)` and verify its checksum, selecting the
/// variant from the checksum constant itself.
fn decode_no_limit(address: &str) -> PersonaResult<(String, Vec<u8>)> {
    if address.len() > 1023 {
        return Err(PersonaError::InvalidInput("Address too long".to_string()));
    }
    if address.chars().any(|c| c.is_ascii_uppercase()) && address.chars().any(|c| c.is_lowercase())
    {
        return Err(PersonaError::InvalidInput("Mixed-case address".to_string()));
    }
    let lower = address.to_lowercase();
    let pos = lower.rfind('1').ok_or_else(|| {
        PersonaError::InvalidInput("Missing separator in bech32 address".to_string())
    })?;
    if pos == 0 || pos + 7 > lower.len() {
        return Err(PersonaError::InvalidInput(
            "Invalid HRP or data length".to_string(),
        ));
    }
    let hrp = &lower[..pos];
    let mut data = Vec::with_capacity(lower.len() - pos - 1);
    for c in lower[pos + 1..].bytes() {
        let value = CHARSET
            .iter()
            .position(|&charset_char| charset_char == c)
            .ok_or_else(|| {
                PersonaError::InvalidInput("Invalid character in bech32 address".to_string())
            })?;
        data.push(value as u8);
    }
    let checksum = verify_checksum(hrp, &data);
    if checksum != Bech32Variant::Bech32.checksum_const() && checksum != BECH32M_CONST {
        return Err(PersonaError::InvalidInput(
            "Invalid bech32 checksum".to_string(),
        ));
    }
    Ok((hrp.to_string(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).unwrap()
    }

    // BIP-173 test vector: P2WPKH
    #[test]
    fn test_bip173_p2wpkh_vector() {
        let p = program("751e76e8199196d454941c45d1b3a323f1433bd6");
        let addr = encode_witness_address("bc", 0, &p).unwrap();
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

        let (hrp, version, decoded) = decode_witness_address(&addr).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(version, 0);
        assert_eq!(decoded, p);
    }

    // BIP-173 test vector: P2WSH (32-byte witness v0 program)
    #[test]
    fn test_bip173_p2wsh_vector() {
        let expected = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
        let (hrp, version, decoded) = decode_witness_address(expected).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(version, 0);
        assert_eq!(decoded.len(), 32);
        assert_eq!(encode_witness_address("bc", 0, &decoded).unwrap(), expected);
    }

    // BIP-341 / BIP-350 test vector for a v1 (taproot) output
    #[test]
    fn test_bip350_p2tr_vector() {
        let p = program("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let addr = encode_witness_address("bc", 1, &p).unwrap();
        assert_eq!(
            addr,
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        );

        let (hrp, version, decoded) = decode_witness_address(&addr).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(version, 1);
        assert_eq!(decoded, p);
    }

    #[test]
    fn test_rejects_bad_checksum() {
        let p = program("751e76e8199196d454941c45d1b3a323f1433bd6");
        let addr = encode_witness_address("bc", 0, &p).unwrap();
        let mut tampered = addr.clone();
        tampered.replace_range(
            addr.len() - 1..,
            if addr.ends_with('q') { "p" } else { "q" },
        );
        assert_ne!(tampered, addr);
        assert!(decode_witness_address(&tampered).is_err());

        // A v1 program must use bech32m; bech32 checksum fails to verify
        assert!(decode_witness_address(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqhsltpn"
        )
        .is_err());
    }

    #[test]
    fn test_rejects_invalid_program_length() {
        assert!(encode_witness_address("bc", 0, &[0u8; 1]).is_err());
        assert!(encode_witness_address("bc", 0, &[0u8; 41]).is_err());
        assert!(encode_witness_address("bc", 17, &[0u8; 20]).is_err());
    }

    #[test]
    fn test_roundtrip_testnet_hrp() {
        let p = program("751e76e8199196d454941c45d1b3a323f1433bd6");
        let addr = encode_witness_address("tb", 0, &p).unwrap();
        assert!(addr.starts_with("tb1q"));
        let (hrp, _, _) = decode_witness_address(&addr).unwrap();
        assert_eq!(hrp, "tb");
    }
}
