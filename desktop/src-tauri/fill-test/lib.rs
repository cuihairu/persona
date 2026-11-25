//! Test-only crate (see the header comment in Cargo.toml; the library code is
//! just READBACK frame encoding/decoding — platform-independent pure functions
//! shared by the host bin and the cross-process suite, with unit tests runnable
//! on both platforms).
//!
//! # READBACK frame protocol (the format the target process `fill-test-host`
//! sends back for the `readback` command)
//!
//! **Historical defect (closed out in round four)**: the frame used to be
//! "`READBACK` + two space-separated UTF-16 hex fields". An empty field encoded
//! to an empty token, and whitespace-separated parsing collapsed consecutive
//! spaces — a frame with "empty username + non-empty password" had only 2
//! segments, so it was treated as a malformed frame and always handled as double
//! empty: a single-field residue (the very shape most in need of detection) could
//! not be detected, and the "zero residue" assertion did not hold (red first: the
//! regression test failing under the old semantics was recorded, see the
//! run4-red log).
//!
//! **Current protocol (length-prefixed)**:
//! `READBACK <unit-count>:<hex> <unit-count>:<hex>`, where hex is 4 lowercase
//! digits per UTF-16 unit; an empty field encodes as `0:` (no hex digits), the
//! segment count does not vary with field content, and the empty-field
//! information is preserved by the length prefix; a wrong field count or invalid
//! prefix always reports a protocol error, never silently swallowed as double
//! empty.

/// Encode the username/password UTF-16 hex text into a READBACK frame.
pub fn encode_readback_frame(user_hex: &str, pwd_hex: &str) -> String {
    format!(
        "READBACK {}:{} {}:{}",
        user_hex.len() / 4,
        user_hex,
        pwd_hex.len() / 4,
        pwd_hex
    )
}

/// Parse a READBACK frame -> (username, password).
///
/// The frame payload is always two `unit-count:hex` fields (an empty field is
/// `0:`, with no hex digits) — the segment count does not vary with field
/// content, so the empty-field information is preserved by the length prefix; a
/// wrong field count or an invalid prefix always reports a protocol error (no
/// longer silently swallowed as double empty — that would misjudge a
/// "single-field residue" as "zero residue").
pub fn parse_readback_frame(line: &str) -> Result<(String, String), String> {
    let malformed = || format!("malformed READBACK frame: {line:?}");
    let Some(payload) = line.strip_prefix("READBACK") else {
        return Err(malformed());
    };
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(malformed());
    }
    let decode_field = |field: &str| -> Result<String, String> {
        let Some((count, hex)) = field.split_once(':') else {
            return Err(malformed());
        };
        let count: usize = count.parse().map_err(|_| malformed())?;
        if hex.len() != count * 4 {
            return Err(malformed());
        }
        Ok(decode_utf16_hex(hex))
    };
    Ok((decode_field(parts[0])?, decode_field(parts[1])?))
}

/// UTF-16 hex (4 lowercase hex digits per unit) -> String
pub fn decode_utf16_hex(hex: &str) -> String {
    let units: Vec<u16> = (0..hex.len() / 4)
        .map(|i| u16::from_str_radix(&hex[4 * i..4 * i + 4], 16).expect("hex unit"))
        .collect();
    String::from_utf16_lossy(&units)
}

/// String -> UTF-16 hex (4 lowercase hex digits per unit), using the same
/// encoding as `fill-test-host`'s `control_text_hex`.
pub fn encode_utf16_hex(value: &str) -> String {
    value.encode_utf16().map(|u| format!("{u:04x}")).collect()
}

#[cfg(test)]
mod readback_frame_tests {
    use super::{decode_utf16_hex, encode_readback_frame, encode_utf16_hex, parse_readback_frame};

    /// Both fields non-empty: the most common shape (regression protection)
    #[test]
    fn both_fields_non_empty_parse_through() {
        let line = encode_readback_frame(
            &encode_utf16_hex("alice@example.com"),
            &encode_utf16_hex("s3cret-Пароль⚡"),
        );
        let (u, p) = parse_readback_frame(&line).expect("frame");
        assert_eq!(u, "alice@example.com");
        assert_eq!(p, "s3cret-Пароль⚡");
    }

    /// **Regression (closed out in round four)**: empty username + non-empty
    /// password — a single-field residue is the shape most in need of detection
    /// for the "zero residue" proof. The old space-separated protocol encoded an
    /// empty field as an empty token, and after collapsing consecutive spaces the
    /// whole frame had only 2 segments with the non-empty field swallowed into
    /// double empty; under the length-prefixed protocol an empty field is `0:`,
    /// so parsing must return ("", "pw") faithfully.
    #[test]
    fn empty_username_non_empty_password_must_be_detected() {
        let line = encode_readback_frame("", &encode_utf16_hex("pw"));
        let (u, p) = parse_readback_frame(&line).expect("frame");
        assert_eq!(u, "", "empty username must stay empty");
        assert_eq!(
            p, "pw",
            "a non-empty password residue must be detected, not swallowed"
        );
    }

    /// **Regression (closed out in round four)**: non-empty username + empty
    /// password — by the same argument a username residue must be detected (the
    /// old protocol gave 2 segments -> double empty).
    #[test]
    fn non_empty_username_empty_password_must_be_detected() {
        let line = encode_readback_frame(&encode_utf16_hex("alice"), "");
        let (u, p) = parse_readback_frame(&line).expect("frame");
        assert_eq!(
            u, "alice",
            "a non-empty username residue must be detected, not swallowed"
        );
        assert_eq!(p, "", "empty password must stay empty");
    }

    /// Length-prefixed protocol invariant: the frame segment count is constant
    /// (always 3 segments: READBACK + 2 `count:hex` fields), and the field
    /// content (including empty) does not change the structure
    #[test]
    fn length_prefixed_protocol_preserves_empty_fields() {
        let line = encode_readback_frame("", &encode_utf16_hex("pw"));
        assert_eq!(
            line,
            format!("READBACK 0: 2:{}", encode_utf16_hex("pw")),
            "empty username encodes as `0:`; password keeps its unit-count prefix"
        );
        assert_eq!(line.split_whitespace().count(), 3);
        let (u, p) = parse_readback_frame(&line).expect("frame");
        assert_eq!(u, "");
        assert_eq!(p, "pw");
    }

    /// Double-empty frame (the expected outcome for the race case):
    /// `READBACK 0: 0:` is a legal protocol frame that parses to double empty;
    /// **a bare `READBACK` (the old truncated-frame shape) must report a
    /// protocol error** — no longer silently handled as double empty
    #[test]
    fn both_empty_frame_parses_to_double_empty_and_bare_frame_is_an_error() {
        let (u, p) = parse_readback_frame(&encode_readback_frame("", "")).expect("frame");
        assert_eq!((u.as_str(), p.as_str()), ("", ""));
        assert!(parse_readback_frame("READBACK").is_err());
        assert!(parse_readback_frame("READBACK 2:0061").is_err());
        assert!(parse_readback_frame("READBACK x:y").is_err());
        assert!(parse_readback_frame("READBACK 1:00 1:0").is_err());
    }

    /// hex encode/decode round-trip (including non-BMP characters, where two units
    /// form one code point)
    #[test]
    fn utf16_hex_roundtrip() {
        for value in ["", "alice", "s3cret-Пароль⚡", "\u{1F512}\u{10FFFF}"] {
            assert_eq!(decode_utf16_hex(&encode_utf16_hex(value)), value);
        }
    }
}
