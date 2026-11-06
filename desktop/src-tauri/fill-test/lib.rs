//! test-only crate（见 Cargo.toml 头注释；库代码只有 READBACK 帧编解码——
//! 平台无关纯函数，宿主 bin 与跨进程套件共用，单元测试两平台都能跑）。
//!
//! # READBACK 帧协议（靶进程 `fill-test-host` 的 `readback` 命令打回格式）
//!
//! **历史缺陷（第四轮收口）**：帧曾是「`READBACK` + 两个空格分隔的 UTF-16
//! hex 字段」。空字段编码为空 token，空格分隔解析把连续空格折叠——
//! 「username 空 + password 非空」的帧只有 2 段，被当成协议残帧一律按
//! 双空处理：单字段残留（最需要检出的形态）无法被检出，「零残留」断言
//! 不成立（红先行：回归测试在旧语义上失败入档，见 run4-red 日志）。
//!
//! **现协议（长度前缀）**：`READBACK <unit-count>:<hex> <unit-count>:<hex>`，
//! hex 为每 UTF-16 单元 4 位小写；空字段编码为 `0:`（无 hex 位），段数
//! 不随字段内容变化，空字段信息被长度前缀保住；字段数不对/前缀非法一律
//! 报协议错，绝不静默吞成双空。

/// 把 username/password 的 UTF-16 hex 文本编码为 READBACK 帧。
pub fn encode_readback_frame(user_hex: &str, pwd_hex: &str) -> String {
    format!(
        "READBACK {}:{} {}:{}",
        user_hex.len() / 4,
        user_hex,
        pwd_hex.len() / 4,
        pwd_hex
    )
}

/// 解析 READBACK 帧 → (username, password)。
///
/// 帧载荷恒为两个 `unit-count:hex` 字段（空字段 = `0:`，无 hex 位）——
/// 段数不随字段内容变化，空字段信息被长度前缀保住；字段数不对/前缀
/// 非法一律报协议错（不再静默吞成双空——那会把「单字段残留」误判成
/// 「零残留」）。
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

/// UTF-16 hex（每单元 4 位小写十六进制）→ String
pub fn decode_utf16_hex(hex: &str) -> String {
    let units: Vec<u16> = (0..hex.len() / 4)
        .map(|i| u16::from_str_radix(&hex[4 * i..4 * i + 4], 16).expect("hex unit"))
        .collect();
    String::from_utf16_lossy(&units)
}

/// String → UTF-16 hex（每单元 4 位小写十六进制），与
/// `fill-test-host` 的 `control_text_hex` 同一编码。
pub fn encode_utf16_hex(value: &str) -> String {
    value.encode_utf16().map(|u| format!("{u:04x}")).collect()
}

#[cfg(test)]
mod readback_frame_tests {
    use super::{decode_utf16_hex, encode_readback_frame, encode_utf16_hex, parse_readback_frame};

    /// 双框非空：最常见形态（回归保护）
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

    /// **回归（第四轮收口）**：username 空 + password 非空——单字段残留
    /// 是「零残留」证明最需要检出的形态。旧空格分隔协议把空字段编码为
    /// 空 token，连续空格折叠后整帧只剩 2 段、非空字段被吞成双空；长度
    /// 前缀协议下空字段 = `0:`，解析必须如实返回 ("", "pw")。
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

    /// **回归（第四轮收口）**：username 非空 + password 空——同理必须
    /// 检出 username 残留（旧协议 2 段 → 双空）。
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

    /// 长度前缀协议不变量：帧段数恒定（恒为 3 段：READBACK + 2 个
    /// `count:hex` 字段），字段内容（含空）不改变结构
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

    /// 双空帧（竞态用例的预期结局）：`READBACK 0: 0:` 是合法协议帧，
    /// 解析为双空；**裸 `READBACK`（旧残帧形态）必须报协议错**——不再
    /// 静默按双空处理
    #[test]
    fn both_empty_frame_parses_to_double_empty_and_bare_frame_is_an_error() {
        let (u, p) = parse_readback_frame(&encode_readback_frame("", "")).expect("frame");
        assert_eq!((u.as_str(), p.as_str()), ("", ""));
        assert!(parse_readback_frame("READBACK").is_err());
        assert!(parse_readback_frame("READBACK 2:0061").is_err());
        assert!(parse_readback_frame("READBACK x:y").is_err());
        assert!(parse_readback_frame("READBACK 1:00 1:0").is_err());
    }

    /// hex 编解码 round-trip（含非 BMP 字符，两单元组成一个码点）
    #[test]
    fn utf16_hex_roundtrip() {
        for value in ["", "alice", "s3cret-Пароль⚡", "\u{1F512}\u{10FFFF}"] {
            assert_eq!(decode_utf16_hex(&encode_utf16_hex(value)), value);
        }
    }
}
