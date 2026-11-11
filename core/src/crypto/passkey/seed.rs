use crate::models::passkey::PasskeyItem;

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
