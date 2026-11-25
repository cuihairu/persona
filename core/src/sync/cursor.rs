//! Encoding and decoding of the server seq cursor (base64url no-pad of
//! `v1:{seq}:{op_id}`).
//!
//! Encoding and parsing are each implemented once and shared between the
//! server (the three pagination lanes: events/backups/oplog) and this crate's
//! engine——the engine decodes the local `last_pull_cursor` back to a seq to
//! obtain "the synced watermark of this device" (sync-group-mode §2.5.5), so
//! the format must match the server exactly. The single source of truth lives
//! here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Cursor format version prefix; increment it when the format changes and
/// reject the old prefix on the parsing side.
const VERSION: &str = "v1";

/// Encode `(seq, op_id)` into an opaque cursor string.
pub fn encode_cursor(seq: i64, op_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{VERSION}:{seq}:{op_id}"))
}

/// Cursor parsing failed (malformed format/version/field). Carries no reason
///——a cursor either decodes or is void in its entirety; the caller decides the
/// error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorError;

/// Parse a cursor; any malformed format/version/field yields `Err(CursorError)`.
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
        assert!(decode_cursor("djE6MTIz").is_err()); // "v1:123" has no id segment
    }
}
