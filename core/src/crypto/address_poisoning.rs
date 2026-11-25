//! Heuristic detection of address poisoning — an enforced check at the backend
//! signing entry points.
//!
//! The usual attack: the attacker sends a zero-value / dust transaction so that
//! the transaction history contains a forged address whose prefix and suffix
//! almost match an address the user uses, luring the user into copying the wrong
//! address from the history.
//!
//! Detection rule (kept consistent with the desktop
//! `utils/addressPoisoning.ts`): a candidate is treated as a suspected spoof
//! when it matches any known address in **the first 6 and last 6 characters
//! exactly, but differs in the middle**. Comparisons are lowercased
//! (unambiguous for EVM hex addresses; conservative for base58 — a false
//! positive is preferable to a miss). A hit refuses to sign unless the caller
//! explicitly confirms (CLI `--confirm-poisoning-check` / desktop second
//! confirmation), per invariant #3 in WALLET_DESIGN.md §5.

use crate::{PersonaError, PersonaResult};

pub const POISON_HEAD_CHARS: usize = 6;
pub const POISON_TAIL_CHARS: usize = 6;

/// Detect whether `candidate` mimics any address in `known`.
///
/// Returns the mimicked known address (so the error can tell the user which
/// one to double-check); returns `None` when nothing looks suspicious.
/// `candidate` is compared against each entry in `known` (an address does not
/// count as mimicking itself). Lengths are counted in Unicode characters, so
/// for pure ASCII addresses characters == bytes; non-ASCII input is split by
/// character and can never panic.
pub fn detect_address_poisoning(candidate: &str, known: &[String]) -> Option<String> {
    let t = candidate.trim().to_lowercase();
    let t_chars: Vec<char> = t.chars().collect();
    if t_chars.len() < POISON_HEAD_CHARS + POISON_TAIL_CHARS {
        return None;
    }
    let head: Vec<char> = t_chars[..POISON_HEAD_CHARS].to_vec();
    let tail: Vec<char> = t_chars[t_chars.len() - POISON_TAIL_CHARS..].to_vec();

    for k in known {
        let kx = k.trim().to_lowercase();
        if kx == t {
            continue; // an identical address is not a mimicry
        }
        let k_chars: Vec<char> = kx.chars().collect();
        if k_chars.len() < POISON_HEAD_CHARS + POISON_TAIL_CHARS {
            continue;
        }
        if k_chars[..POISON_HEAD_CHARS] == head
            && k_chars[k_chars.len() - POISON_TAIL_CHARS..] == tail
        {
            return Some(k.clone());
        }
    }
    None
}

/// Enforced check for the backend signing entry points: refuse when the
/// poisoning heuristic fires and nothing has been confirmed.
///
/// `confirmed` = the caller explicitly acknowledged it (the CLI
/// `--confirm-poisoning-check` flag, or the desktop second confirmation whose
/// ack is written into metadata).
pub fn enforce_poisoning_check(
    to_address: &str,
    known_addresses: &[String],
    confirmed: bool,
) -> PersonaResult<()> {
    if confirmed {
        return Ok(());
    }
    if let Some(mimicked) = detect_address_poisoning(to_address, known_addresses) {
        return Err(PersonaError::InvalidInput(format!(
            "Refusing to sign: '{to_address}' looks like an address-poisoning spoof of your known address '{mimicked}' (same first {POISON_HEAD_CHARS} and last {POISON_TAIL_CHARS} characters). Re-check every character or paste the address from a trusted source; re-run with explicit confirmation only if you are sure."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline known address: first 6 characters `0x1234`, last 6 characters
    /// `345678`.
    const KNOWN: &str = "0x1234567890abcdef1234567890abcdef12345678";
    /// A spoof address with an all-zero middle: same head and tail as KNOWN, a
    /// different middle.
    const SPOOF: &str = "0x1234000000000000000000000000000000345678";

    #[test]
    fn detects_head_and_tail_match_with_different_middle() {
        let known = vec![KNOWN.to_string()];
        assert_eq!(
            detect_address_poisoning(SPOOF, &known).as_deref(),
            Some(KNOWN)
        );
    }

    #[test]
    fn accepts_identical_address_and_no_known_addresses() {
        let known = vec![KNOWN.to_string()];
        assert_eq!(detect_address_poisoning(KNOWN, &known), None);
        assert_eq!(detect_address_poisoning(SPOOF, &[]), None);
    }

    #[test]
    fn rejects_partial_match_and_short_candidates() {
        let known = vec![KNOWN.to_string()];
        // same head, different tail
        assert_eq!(
            detect_address_poisoning("0x1234000000000000000000000000000ffffffff", &known),
            None
        );
        // different head, same tail
        assert_eq!(
            detect_address_poisoning("0x9999567890abcdef1234567890abcdef12345678", &known),
            None
        );
        // shorter than head+tail
        assert_eq!(detect_address_poisoning("0x1234", &known), None);
        // known too short
        assert_eq!(detect_address_poisoning(KNOWN, &["0x12".to_string()]), None);
    }

    #[test]
    fn is_case_insensitive_and_conservative_for_base58() {
        // base58 lookalike: same first/last 6 chars, different middle
        let known = vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string()];
        let spoof = "1A1zP1zzzzzzzzzzzzzzzzzzzzzzDivfNa";
        assert_eq!(
            detect_address_poisoning(spoof, &known).as_deref(),
            Some("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        );
        // uppercase input matches lowercase known (EIP-55 mixed case ignored)
        assert!(detect_address_poisoning(
            "0X1234567890ABCDEF1234567890ABCDEF12345678",
            &known.iter().map(|_| KNOWN.to_string()).collect::<Vec<_>>()
        )
        .is_none()); // identical after lowercasing
        assert!(detect_address_poisoning(SPOOF, &[KNOWN.to_string()]).is_some());
    }

    #[test]
    fn picks_first_mimicked_known_address() {
        let other = "0x1234111111111111111111111111111111345678";
        let known = vec![KNOWN.to_string(), other.to_string()];
        assert_eq!(
            detect_address_poisoning(SPOOF, &known).as_deref(),
            Some(KNOWN)
        );
    }

    #[test]
    fn never_panics_on_non_ascii_input() {
        let known = vec![KNOWN.to_string()];
        assert_eq!(
            detect_address_poisoning("0x1234567890abcdefé", &known),
            None
        );
        assert_eq!(
            detect_address_poisoning("0x1234567890abcdefé", &["0x12é".to_string()]),
            None
        );
    }

    #[test]
    fn enforce_blocks_spoof_and_allows_when_confirmed() {
        let known = vec![KNOWN.to_string()];
        let err = enforce_poisoning_check(SPOOF, &known, false).unwrap_err();
        assert!(err.to_string().contains("address-poisoning"));
        assert!(err.to_string().contains(KNOWN));
        // confirmed passes
        assert!(enforce_poisoning_check(SPOOF, &known, true).is_ok());
        // clean address passes without confirmation
        assert!(enforce_poisoning_check(
            "0x999900000000000000000000000000000345678",
            &known,
            false
        )
        .is_ok());
    }
}
