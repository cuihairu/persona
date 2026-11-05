//! test-only crate（见 Cargo.toml 头注释；库代码只有 READBACK 帧编解码——
//! 平台无关纯函数，宿主 bin 与跨进程套件共用，单元测试两平台都能跑）。
//!
//! # READBACK 帧协议（靶进程 `fill-test-host` 的 `readback` 命令打回格式）
//!
//! **历史缺陷（第四轮收口，红先行）**：帧为「`READBACK` + 两个空格分隔的
//! UTF-16 hex 字段」。空字段编码为空 token，空格分隔解析把连续空格折叠——
//! 「username 空 + password 非空」的帧只有 2 段，被当成协议残帧一律按
//! 双空处理：单字段残留（最需要检出的形态）无法被检出，「零残留」断言
//! 不成立。`parse_readback_frame` 现以**现实现语义**入库（不足 3 段按
//! 双空），配套回归测试钉住「单字段非空必须能被检出」——在现语义下这些
//! 断言**失败（RED）**，协议改为长度前缀后转 GREEN。
//!
//! 帧格式（GREEN 后）：`READBACK <unit-count>:<hex> <unit-count>:<hex>`，
//! hex 为每 UTF-16 单元 4 位小写；空字段编码为 `0:`（无 hex 位），长度
//! 前缀保住空字段信息，任何字段内容都不再改变帧的段数。

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
/// **现实现语义（RED 态，历史行为原样移植）**：`READBACK` 后按空格分隔，
/// 不足 3 段一律返回双空——单字段非空被误判双空（见模块头注释）。
pub fn parse_readback_frame(line: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // 历史行为：在途竞态用例的预期结局（宿主销毁重建后两框皆为空）打回
    // `READBACK` / `READBACK  `——不足 3 段按全空处理
    if parts.len() < 3 {
        return Ok((String::new(), String::new()));
    }
    if parts.len() != 3 {
        return Err(format!("malformed READBACK frame: {line:?}"));
    }
    Ok((decode_utf16_hex(parts[1]), decode_utf16_hex(parts[2])))
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

    /// 双框非空：空格分隔解析 historically 正常的形态（回归保护）
    #[test]
    fn both_fields_non_empty_parse_through() {
        let user = encode_utf16_hex("alice@example.com");
        let pwd = encode_utf16_hex("s3cret-Пароль⚡");
        let line = format!("READBACK {user} {pwd}");
        let (u, p) = parse_readback_frame(&line).expect("frame");
        assert_eq!(u, "alice@example.com");
        assert_eq!(p, "s3cret-Пароль⚡");
    }

    /// **回归（RED）**：username 空 + password 非空——单字段残留是
    /// 「零残留」证明最需要检出的形态。空字段的 hex 为空 token，空格
    /// 分隔折叠连续空格后整帧只有 2 段；解析**必须**如实返回
    /// ("", "pw")，不得把非空字段吞成双空。现实现按双空处理 → 失败。
    #[test]
    fn empty_username_non_empty_password_must_be_detected() {
        let pwd = encode_utf16_hex("pw");
        // 历史宿主打回格式：空 hex 字段 = 空串，帧里出现连续空格
        let line = format!("READBACK  {pwd}");
        let (u, p) = parse_readback_frame(&line).expect("frame");
        assert_eq!(u, "", "empty username must stay empty");
        assert_eq!(p, "pw", "a non-empty password residue must be detected, not swallowed");
    }

    /// **回归（RED）**：username 非空 + password 空——同理必须检出
    /// username 残留。现实现 2 段 → 双空 → 失败。
    #[test]
    fn non_empty_username_empty_password_must_be_detected() {
        let user = encode_utf16_hex("alice");
        let line = format!("READBACK {user} ");
        let (u, p) = parse_readback_frame(&line).expect("frame");
        assert_eq!(u, "alice", "a non-empty username residue must be detected, not swallowed");
        assert_eq!(p, "", "empty password must stay empty");
    }

    /// **回归（GREEN 后启用的协议断言）**：长度前缀协议下空字段编码为
    /// `0:`——空帧也是合法的 3 段协议帧，段数不再随字段内容变化。
    /// 现实现（无长度前缀）下此断言失败。
    #[test]
    fn length_prefixed_protocol_preserves_empty_fields() {
        let line = encode_readback_frame("", &encode_utf16_hex("pw"));
        assert_eq!(line, format!("READBACK 0: {}", encode_utf16_hex("pw")));
        let (u, p) = parse_readback_frame(&line).expect("frame");
        assert_eq!(u, "");
        assert_eq!(p, "pw");
    }

    /// 双空帧（竞态用例的预期结局）：协议上仍可解析，结果为双空
    #[test]
    fn both_empty_frame_parses_to_double_empty() {
        let (u, p) = parse_readback_frame(&encode_readback_frame("", "")).expect("frame");
        assert_eq!((u.as_str(), p.as_str()), ("", ""));
        let (u, p) = parse_readback_frame("READBACK").expect("frame");
        assert_eq!((u.as_str(), p.as_str()), ("", ""));
    }

    /// hex 编解码 round-trip（含非 BMP 字符，两单元组成一个码点）
    #[test]
    fn utf16_hex_roundtrip() {
        for value in ["", "alice", "s3cret-Пароль⚡", "\u{1F512}\u{10FFFF}"] {
            assert_eq!(decode_utf16_hex(&encode_utf16_hex(value)), value);
        }
    }
}
