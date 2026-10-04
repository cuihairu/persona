//! 服务器 seq 游标编解码（`v1:{seq}:{op_id}` 的 base64url no-pad）。
//!
//! 编码与解析各一份实现，server（events/backups/oplog 三条分页线）与本
//! crate 的 engine 共用——engine 要把本地 `last_pull_cursor` 解回 seq 得到
//! 「本机已同步水位」（sync-group-mode §二.5.5），格式必须与 server 完全
//! 一致，单一真相源放在这里。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// 游标格式版本前缀；升级格式时递增并在解析侧拒绝旧前缀。
const VERSION: &str = "v1";

/// 把 `(seq, op_id)` 编成不透明游标串。
pub fn encode_cursor(seq: i64, op_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{VERSION}:{seq}:{op_id}"))
}

/// 游标解析失败（格式/版本/字段不合法）。不携带原因——游标要么可解，
/// 要么整体作废；错误文案由调用方决定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorError;

/// 解析游标；格式/版本/字段不合法一律 `Err(CursorError)`。
pub fn decode_cursor(raw: &str) -> Result<(i64, String), CursorError> {
    let invalid = || CursorError;
    let decoded = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?;
    let text = String::from_utf8(decoded).map_err(|_| invalid())?;
    let rest = text
        .strip_prefix(&format!("{VERSION}:"))
        .ok_or_else(invalid)?;
    let (seq, op_id) = rest.split_once(':').ok_or_else(invalid)?;
    let seq: i64 = seq.parse().map_err(|_| invalid())?;
    if op_id.is_empty() {
        return Err(invalid());
    }
    Ok((seq, op_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_seq_and_op_id() {
        let encoded = encode_cursor(1_758_182_400_123, "0e2c5a6b-1c2d-3e4f-5a6b-7c8d9e0f1a2b");
        let (seq, op_id) = decode_cursor(&encoded).unwrap();
        assert_eq!(seq, 1_758_182_400_123);
        assert_eq!(op_id, "0e2c5a6b-1c2d-3e4f-5a6b-7c8d9e0f1a2b");
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(decode_cursor("not-a-cursor").is_err());
        assert!(decode_cursor("").is_err());
        assert!(decode_cursor("aXY6").is_err());
        assert!(decode_cursor("djE6MTIz").is_err()); // "v1:123" 无 id 段
    }
}
