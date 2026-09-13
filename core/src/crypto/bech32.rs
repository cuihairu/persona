// Bech32 / Bech32m encoding per BIP-173 and BIP-350.
//
// Segwit witness programs only; the checksummed encoding itself is
// delegated to the audited `bech32` crate. Witness version 0 uses bech32,
// versions 1+ (e.g. Taproot) use bech32m.

use crate::{PersonaError, PersonaResult};
use bech32::{Fe32, Hrp};

/// Encode a SegWit address (witness program) for the given human-readable
/// part. Witness version 0 uses bech32, versions 1+ use bech32m (BIP-350),
/// as enforced by the crate's segwit encoder.
pub fn encode_witness_address(hrp: &str, version: u8, program: &[u8]) -> PersonaResult<String> {
    if version > 16 {
        return Err(PersonaError::InvalidInput(format!(
            "Invalid witness version: {version}"
        )));
    }
    if program.len() < 2 || program.len() > 40 {
        return Err(PersonaError::InvalidInput(
            "Witness program length must be 2-40 bytes".to_string(),
        ));
    }

    let hrp =
        Hrp::parse(hrp).map_err(|e| PersonaError::InvalidInput(format!("Invalid HRP: {e}")))?;
    let version = Fe32::try_from(version)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid witness version: {e}")))?;
    bech32::segwit::encode(hrp, version, program)
        .map_err(|e| PersonaError::InvalidInput(format!("Bech32 encoding failed: {e}")))
}

/// Decode a SegWit address into `(hrp, witness_version, witness_program)`.
/// The crate enforces the BIP-173/350 rules (variant per witness version,
/// program length 2-40, valid checksum).
pub fn decode_witness_address(address: &str) -> PersonaResult<(String, u8, Vec<u8>)> {
    let (hrp, version, program) = bech32::segwit::decode(address.trim())
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid bech32 address: {e}")))?;
    Ok((hrp.to_string(), version.to_u8(), program))
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
