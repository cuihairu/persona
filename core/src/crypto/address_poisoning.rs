//! 地址投毒（address poisoning）启发式检测——后端签名入口的强制检查。
//!
//! 常见攻击：攻击者发送 0 转账/粉尘交易，让历史记录里出现一个「前缀+尾缀
//! 与用户常用地址几乎相同」的伪造地址，诱导用户从交易历史复制错误地址。
//!
//! 检测规则（与桌面 `utils/addressPoisoning.ts` 保持一致口径）：与任一已知
//! 地址 **前 6 个字符和后 6 个字符完全相同但中段不同** 即视为疑似投毒。
//! 比较统一转小写（EVM hex 地址无歧义；对 base58 会偏保守——宁可误报也不
//! 放过）。命中即拒绝签名，除非调用方显式确认（CLI `--confirm-poisoning-check`
//! / 桌面二次确认），与 WALLET_DESIGN.md §5 第 3 条不变量一致。

use crate::{PersonaError, PersonaResult};

pub const POISON_HEAD_CHARS: usize = 6;
pub const POISON_TAIL_CHARS: usize = 6;

/// 检测 `candidate` 是否模仿了 `known` 中的任一地址。
///
/// 返回被模仿的那个已知地址（便于错误提示用户去核对）；无嫌疑返回 `None`。
/// `candidate` 与 `known` 逐项比较（已知地址自身不构成模仿）。字符数按
/// Unicode 计，纯 ASCII 地址即字符数=字节数；非 ASCII 输入按字符切分，
/// 永不 panic。
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
            continue; // 同一地址不构成模仿
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

/// 后端签名入口的强制检查：命中投毒启发式且未确认即拒绝。
///
/// `confirmed` = 调用方已显式确认（CLI `--confirm-poisoning-check` 或桌面
/// 二次确认后写入 metadata 的 ack）。
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

    /// 基准已知地址：前 6 字符 `0x1234`、后 6 字符 `345678`。
    const KNOWN: &str = "0x1234567890abcdef1234567890abcdef12345678";
    /// 中段全零的仿冒地址：与 KNOWN 头尾相同、中段不同。
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
