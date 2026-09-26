//! 硬件绑定的密钥包裹层（biometric key wrapping）。
//!
//! 设计全文见 `docs/biometric-unlock-design.md`。与 [`super::biometric`]
//! 的门禁层（OS 弹框 + keyring 托管主密码）不同，本层把 vault 主密钥
//! 用平台硬件密钥（Secure Enclave / TPM / Android Keystore）**加密包裹**
//! ——生物识别在"解密那一刻"由硬件强制弹出，私钥永不导出；keyring 里
//! 只落打不开的包裹 blob。
//!
//! 平台无关部分（信封编解码、enrollment 指纹比对、trait 契约）在 core，
//! 平台私有密文（payload）完全交给 [`BiometricKeyWrapper`] 实现方；
//! 中间值一律 `Zeroizing` 包裹。未实现平台返回 [`BiometricWrapError::Unsupported`]
//! 而非 panic。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::PersonaError;

/// 包裹信封 magic + 版本（BIOWRAP1；格式变更换 magic 尾数字）
const WRAP_MAGIC: &[u8; 8] = b"BIOWRAP1";

/// 定长头部长度：`magic(8) | platform_tag(1) | enrollment_fp(32) | payload_len(4)`
const WRAP_HEADER_LEN: usize = 8 + 1 + 32 + 4;

/// 平台标识（信封头字段；解包时 tag 不匹配 = blob 不是本平台产出）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WrapPlatform {
    /// 测试/CI mock
    Mock = 0,
    /// macOS Secure Enclave（路线 B'，见设计文档 §5）
    MacSecureEnclave = 1,
    /// Windows TPM / Passport Key（规划中，设计文档 §6）
    WindowsTpm = 2,
    /// Linux（保留——当前定格 OsGateOnly 档，设计文档 §7.1）
    Linux = 3,
}

impl WrapPlatform {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Mock),
            1 => Some(Self::MacSecureEnclave),
            2 => Some(Self::WindowsTpm),
            3 => Some(Self::Linux),
            _ => None,
        }
    }

    /// 信封里的 `u8` 编码（`from_u8` 的逆运算；枚举值即线格式）
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// 生物识别解锁的能力档位（三档，设计文档 §1）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiometricWrapCapability {
    /// 硬件绑定：私钥不可导出，解密由硬件强制用户认证
    HardwareBound,
    /// 仅系统门禁：keyring 托管 + OS 弹框（Linux 现状 / 硬件层未启用的平台）
    OsGateOnly,
    /// 无生物硬件或系统认证栈，功能整体隐藏
    Unsupported,
}

/// 包裹层的结构化错误（桌面按此分流回退链，设计文档 §3.4）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricWrapError {
    /// 平台/硬件不支持硬件绑定档
    Unsupported,
    /// 硬件或生物注册当前不可用
    NotAvailable,
    /// 用户取消系统弹框（静默回解锁屏）
    UserCancelled,
    /// 生物注册集已变化（换指纹等），包裹永久失效 → 自动降级主密码
    EnrollmentChanged,
    /// 包裹 blob 损坏/被替换/非本平台产出
    WrapInvalid,
    /// 平台实现报错（OSStatus / HRESULT 等原文进字符串）
    Platform(String),
}

impl BiometricWrapError {
    /// 映射进 PersonaError（服务层签名统一走 crate::Result）
    pub fn to_persona_error(&self) -> PersonaError {
        PersonaError::AuthenticationFailed(self.to_string())
    }
}

impl std::fmt::Display for BiometricWrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(
                f,
                "biometric key wrapping is not supported on this platform"
            ),
            Self::NotAvailable => write!(f, "biometric hardware is not currently available"),
            Self::UserCancelled => write!(f, "biometric prompt was cancelled by the user"),
            Self::EnrollmentChanged => write!(
                f,
                "biometric enrollment changed since the key was wrapped; the wrap is invalid"
            ),
            Self::WrapInvalid => write!(f, "biometric wrap blob is invalid or corrupted"),
            Self::Platform(msg) => write!(f, "biometric platform error: {msg}"),
        }
    }
}

/// 平台硬件包裹器（平台实现 payload 密文；信封与指纹比对在 core）。
///
/// 实现方约定：
/// - `wrap_payload`/`unwrap_payload` 是仅有的两个接触明文密钥的方法，
///   平台应在硬件认证通过后原位加解密，私钥不落内存之外的任何地方；
/// - `enrollment_fingerprint` 返回当前生物注册集的稳定指纹
///   （硬件已强制 biometryCurrentSet 的平台可返回固定占位值）；
/// - 不支持的平台实现 [`MockKeyWrapper`] 同款：capability 报
///   `Unsupported`，方法返回 [`BiometricWrapError::Unsupported`]。
pub trait BiometricKeyWrapper: Send + Sync {
    fn capability(&self) -> BiometricWrapCapability;

    /// 硬件/生物注册当前是否可用（探测失败 fail-closed 为 false）
    fn is_available(&self) -> bool;

    fn platform(&self) -> WrapPlatform;

    fn enrollment_fingerprint(&self) -> std::result::Result<[u8; 32], BiometricWrapError>;

    /// 包裹主密钥（payload 密文；core 负责加信封头）
    fn wrap_payload(
        &self,
        master_key: &[u8; 32],
        prompt: &str,
    ) -> std::result::Result<Vec<u8>, BiometricWrapError>;

    /// 解开 payload（硬件此刻强制生物识别；返回 Zeroizing 包裹的密钥）
    fn unwrap_payload(
        &self,
        payload: &[u8],
        prompt: &str,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError>;

    /// 删除硬件侧持久化的密钥/凭据（禁用与失效自愈时调用；尽力而为，
    /// 平台无持久化时返回 Ok）
    fn delete_wrap_payload(&self, payload: &[u8]) -> std::result::Result<(), BiometricWrapError>;
}

/// 组装完整包裹信封（`BIOWRAP1 | tag | enrollment_fp | payload_len | payload`）。
///
/// 供宿主在 enable 时调用：capability 探测 → 指纹 → payload → 信封。
/// 非 HardwareBound 的 wrapper 一律 `Unsupported`（配置操作不允许静默
/// 降级到弱档——降级与否是用户可见的显式决策，见设计文档 §4）。
pub fn wrap_master_key(
    wrapper: &dyn BiometricKeyWrapper,
    master_key: &[u8; 32],
    prompt: &str,
) -> std::result::Result<Vec<u8>, BiometricWrapError> {
    if wrapper.capability() != BiometricWrapCapability::HardwareBound {
        return Err(BiometricWrapError::Unsupported);
    }
    if !wrapper.is_available() {
        return Err(BiometricWrapError::NotAvailable);
    }
    let enrollment_fp = wrapper.enrollment_fingerprint()?;
    let payload = wrapper.wrap_payload(master_key, prompt)?;
    let payload_len = envelope_payload_len(payload.len())?;
    let mut out = Vec::with_capacity(WRAP_HEADER_LEN + payload.len());
    out.extend_from_slice(WRAP_MAGIC);
    out.push(wrapper.platform().as_u8());
    out.extend_from_slice(&enrollment_fp);
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// payload 字节数 → 信封里的 `u32` 长度字段。超过 `u32::MAX` 的 payload
/// 无法编码进定长头，视为平台实现错误（报 `Platform` 让宿主显式失败，
/// 绝不静默截断长度——截断会让解包侧读到越界密文）。
fn envelope_payload_len(len: usize) -> std::result::Result<u32, BiometricWrapError> {
    u32::try_from(len).map_err(|_| {
        BiometricWrapError::Platform(format!(
            "wrap payload of {len} bytes exceeds envelope limit"
        ))
    })
}

/// 解开完整包裹信封：校验 magic/平台 → 比对 enrollment 指纹 → 交平台
/// 解 payload（硬件在此刻弹生物识别）。
///
/// 指纹比对是纵深防御第二道：即使平台层漏拦注册集漂移
/// （`biometryCurrentSet` 语义缺失），这里也会以
/// [`BiometricWrapError::EnrollmentChanged`] 拒绝，宿主据此自动删除
/// blob 并回退主密码。
pub fn unwrap_master_key(
    wrapper: &dyn BiometricKeyWrapper,
    envelope: &[u8],
    prompt: &str,
) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
    if wrapper.capability() != BiometricWrapCapability::HardwareBound {
        return Err(BiometricWrapError::Unsupported);
    }
    if !wrapper.is_available() {
        return Err(BiometricWrapError::NotAvailable);
    }
    let (tag, enrollment_fp, payload) = parse_wrap_envelope(envelope)?;
    if tag != wrapper.platform() {
        return Err(BiometricWrapError::WrapInvalid);
    }
    if wrapper.enrollment_fingerprint()? != enrollment_fp {
        return Err(BiometricWrapError::EnrollmentChanged);
    }
    wrapper.unwrap_payload(payload, prompt)
}

/// 解析信封头，返回（平台，指纹，payload 切片）。任何形状不符都是
/// [`BiometricWrapError::WrapInvalid`]。
///
/// `payload_len` 与实际剩余字节必须**精确相等**：不等即意味着 blob 被
/// 截断或被追加了尾随垃圾，两种情况都拒绝——平台 payload 密文后面多出
/// 任何字节都属于被改写的证据。
pub fn parse_wrap_envelope(
    envelope: &[u8],
) -> std::result::Result<(WrapPlatform, [u8; 32], &[u8]), BiometricWrapError> {
    if envelope.len() < WRAP_HEADER_LEN {
        return Err(BiometricWrapError::WrapInvalid);
    }
    if &envelope[..WRAP_MAGIC.len()] != WRAP_MAGIC {
        return Err(BiometricWrapError::WrapInvalid);
    }
    let tag =
        WrapPlatform::from_u8(envelope[WRAP_MAGIC.len()]).ok_or(BiometricWrapError::WrapInvalid)?;
    let fp_start = WRAP_MAGIC.len() + 1;
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&envelope[fp_start..fp_start + 32]);
    let len_start = fp_start + 32;
    let declared_len = u32::from_le_bytes(
        envelope[len_start..len_start + 4]
            .try_into()
            .map_err(|_| BiometricWrapError::WrapInvalid)?,
    ) as usize;
    let payload = &envelope[WRAP_HEADER_LEN..];
    if declared_len == 0 || declared_len != payload.len() {
        return Err(BiometricWrapError::WrapInvalid);
    }
    Ok((tag, fp, payload))
}

// ---------------------------------------------------------------------------
// Mock 实现（CI / 测试 / 非 HardwareBound 平台的占位行为基准）
// ---------------------------------------------------------------------------

/// 内存 mock：payload = 16 字节随机 id，包裹表存进程内存。
/// 失败注入位覆盖回退链全部分支（设计文档 §3.4）。
#[derive(Default)]
struct MockInner {
    available: bool,
    fail_wrap: bool,
    fail_unwrap: bool,
    fail_delete: bool,
    user_cancelled: bool,
    enrollment: [u8; 32],
    wraps: HashMap<[u8; 16], Zeroizing<[u8; 32]>>,
}

/// 硬件绑定的 mock wrapper（core/service 测试与 CI 用；生产平台实现
/// 各自的后端）。
pub struct MockKeyWrapper {
    inner: Mutex<MockInner>,
}

impl Default for MockKeyWrapper {
    fn default() -> Self {
        let mut enrollment = [0u8; 32];
        getrandom::fill(&mut enrollment).expect("failed to generate mock enrollment fingerprint");
        Self {
            inner: Mutex::new(MockInner {
                available: true,
                enrollment,
                ..MockInner::default()
            }),
        }
    }
}

impl MockKeyWrapper {
    /// 模拟用户在生物注册里删除/新增指纹：旧包裹全部失效
    pub fn rotate_enrollment(&self) {
        let mut inner = self.inner.lock().unwrap();
        getrandom::fill(&mut inner.enrollment).expect("failed to rotate mock enrollment");
    }

    /// 模拟用户在系统弹框点了取消
    pub fn set_user_cancelled(&self, cancelled: bool) {
        self.inner.lock().unwrap().user_cancelled = cancelled;
    }

    /// 注入硬件错误（wrap / unwrap / delete 三个方向）
    pub fn set_fail(&self, target: MockFailTarget, fail: bool) {
        let mut inner = self.inner.lock().unwrap();
        match target {
            MockFailTarget::Wrap => inner.fail_wrap = fail,
            MockFailTarget::Unwrap => inner.fail_unwrap = fail,
            MockFailTarget::Delete => inner.fail_delete = fail,
        }
    }

    /// 模拟硬件不可用（无 SE 的旧 Mac / 生物注册清空）
    pub fn set_available(&self, available: bool) {
        self.inner.lock().unwrap().available = available;
    }

    /// 破坏一个包裹 payload 的完整性（模拟 blob 被改写/换平台）
    pub fn corrupt(&self, envelope: &mut [u8]) {
        let last = envelope.len() - 1;
        envelope[last] = envelope[last].wrapping_add(1);
    }
}

/// [`MockKeyWrapper::set_fail`] 的注入方向
#[derive(Debug, Clone, Copy)]
pub enum MockFailTarget {
    Wrap,
    Unwrap,
    Delete,
}

impl BiometricKeyWrapper for MockKeyWrapper {
    fn capability(&self) -> BiometricWrapCapability {
        BiometricWrapCapability::HardwareBound
    }

    fn is_available(&self) -> bool {
        self.inner.lock().unwrap().available
    }

    fn platform(&self) -> WrapPlatform {
        WrapPlatform::Mock
    }

    fn enrollment_fingerprint(&self) -> std::result::Result<[u8; 32], BiometricWrapError> {
        Ok(self.inner.lock().unwrap().enrollment)
    }

    fn wrap_payload(
        &self,
        master_key: &[u8; 32],
        _prompt: &str,
    ) -> std::result::Result<Vec<u8>, BiometricWrapError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_wrap {
            return Err(BiometricWrapError::Platform("mock wrap failure".into()));
        }
        if inner.user_cancelled {
            return Err(BiometricWrapError::UserCancelled);
        }
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("failed to generate mock wrap id");
        inner.wraps.insert(id, Zeroizing::new(*master_key));
        Ok(id.to_vec())
    }

    fn unwrap_payload(
        &self,
        payload: &[u8],
        _prompt: &str,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
        let inner = self.inner.lock().unwrap();
        if inner.fail_unwrap {
            return Err(BiometricWrapError::Platform("mock unwrap failure".into()));
        }
        if inner.user_cancelled {
            return Err(BiometricWrapError::UserCancelled);
        }
        if payload.len() != 16 {
            return Err(BiometricWrapError::WrapInvalid);
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(payload);
        inner
            .wraps
            .get(&id)
            .cloned()
            .ok_or(BiometricWrapError::WrapInvalid)
    }

    fn delete_wrap_payload(&self, payload: &[u8]) -> std::result::Result<(), BiometricWrapError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_delete {
            return Err(BiometricWrapError::Platform("mock delete failure".into()));
        }
        if payload.len() == 16 {
            let mut id = [0u8; 16];
            id.copy_from_slice(payload);
            inner.wraps.remove(&id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(v: u8) -> [u8; 32] {
        [v; 32]
    }

    #[test]
    fn wrap_and_unwrap_roundtrip() {
        let wrapper = MockKeyWrapper::default();
        let envelope = wrap_master_key(&wrapper, &key(7), "enable").unwrap();
        let unlocked = unwrap_master_key(&wrapper, &envelope, "unlock").unwrap();
        assert_eq!(*unlocked, key(7));
    }

    #[test]
    fn envelope_layout_is_stable() {
        let wrapper = MockKeyWrapper::default();
        let envelope = wrap_master_key(&wrapper, &key(1), "enable").unwrap();
        // magic + tag + fp + payload_len(4) + 16B mock id
        assert_eq!(envelope.len(), WRAP_HEADER_LEN + 16);
        assert_eq!(&envelope[..8], b"BIOWRAP1");
        assert_eq!(envelope[8], 0);
        // payload_len 以 u32le 写在 fp 之后
        assert_eq!(&envelope[41..45], &16u32.to_le_bytes());
        // 头部长度与设计文档 §3.3 的字段表一致
        assert_eq!(WRAP_HEADER_LEN, 8 + 1 + 32 + 4);
    }

    #[test]
    fn payload_len_mismatch_is_rejected() {
        let wrapper = MockKeyWrapper::default();
        let envelope = wrap_master_key(&wrapper, &key(9), "enable").unwrap();

        // 截断：实际 payload 比声明短
        let mut truncated = envelope.clone();
        truncated.truncate(truncated.len() - 1);
        assert_eq!(
            parse_wrap_envelope(&truncated).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );

        // 尾随垃圾：实际 payload 比声明长
        let mut extended = envelope.clone();
        extended.push(0xAB);
        assert_eq!(
            parse_wrap_envelope(&extended).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );

        // 声明长度为零
        let mut zero_len = envelope.clone();
        zero_len[41..45].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_wrap_envelope(&zero_len).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );

        // 声明长度溢出（u32::MAX，实际 16 字节）
        let mut overflow = envelope.clone();
        overflow[41..45].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            parse_wrap_envelope(&overflow).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );

        // 未改动的信封仍然可解（确认上面的构造没有误伤）
        assert!(parse_wrap_envelope(&envelope).is_ok());
    }

    #[test]
    fn parse_rejects_malformed_envelopes() {
        // 过短
        assert_eq!(
            parse_wrap_envelope(&[0u8; 10]).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
        // 魔数错误
        let mut bad = vec![b'X'; 8 + 1 + 32 + 4];
        assert_eq!(
            parse_wrap_envelope(&bad).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
        // 未知平台 tag
        bad[..8].copy_from_slice(WRAP_MAGIC);
        bad[8] = 99;
        assert_eq!(
            parse_wrap_envelope(&bad).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
        // 空 payload：头部长度齐全但 payload_len = 0
        let mut empty_payload = vec![0u8; WRAP_HEADER_LEN];
        empty_payload[..8].copy_from_slice(WRAP_MAGIC);
        empty_payload[8] = 0;
        empty_payload[41..45].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_wrap_envelope(&empty_payload).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    #[test]
    fn wrap_rejects_non_hardware_bound_capability() {
        struct GateOnly;
        impl BiometricKeyWrapper for GateOnly {
            fn capability(&self) -> BiometricWrapCapability {
                BiometricWrapCapability::OsGateOnly
            }
            fn is_available(&self) -> bool {
                true
            }
            fn platform(&self) -> WrapPlatform {
                WrapPlatform::Linux
            }
            fn enrollment_fingerprint(&self) -> std::result::Result<[u8; 32], BiometricWrapError> {
                Ok([0; 32])
            }
            fn wrap_payload(
                &self,
                _k: &[u8; 32],
                _p: &str,
            ) -> std::result::Result<Vec<u8>, BiometricWrapError> {
                Err(BiometricWrapError::Unsupported)
            }
            fn unwrap_payload(
                &self,
                _p: &[u8],
                _prompt: &str,
            ) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
                Err(BiometricWrapError::Unsupported)
            }
            fn delete_wrap_payload(
                &self,
                _p: &[u8],
            ) -> std::result::Result<(), BiometricWrapError> {
                Err(BiometricWrapError::Unsupported)
            }
        }

        let gate = GateOnly;
        // 配置面：非 HardwareBound 显式 Unsupported（不静默降档）
        assert_eq!(
            wrap_master_key(&gate, &key(1), "enable").unwrap_err(),
            BiometricWrapError::Unsupported
        );
        assert_eq!(
            unwrap_master_key(&gate, &[0u8; 64], "unlock").unwrap_err(),
            BiometricWrapError::Unsupported
        );
        // 门禁档的元信息照常可读（前端要显示"当前档位"），只是没有任何
        // 硬件能力可言
        assert_eq!(gate.capability(), BiometricWrapCapability::OsGateOnly);
        assert!(gate.is_available(), "gate-only stubs report their own axis");
        assert_eq!(gate.platform(), WrapPlatform::Linux);
        assert_eq!(gate.enrollment_fingerprint().unwrap(), [0u8; 32]);
        // 门禁档 wrapper 的每个原语本身也都是 Unsupported——宿主若绕过
        // capability 检查直接调，一样拿不到密钥（fail-closed 到方法级）
        assert_eq!(
            gate.wrap_payload(&key(1), "p").unwrap_err(),
            BiometricWrapError::Unsupported
        );
        assert_eq!(
            gate.unwrap_payload(&[0u8; 4], "p").unwrap_err(),
            BiometricWrapError::Unsupported
        );
        assert_eq!(
            gate.delete_wrap_payload(&[0u8; 4]).unwrap_err(),
            BiometricWrapError::Unsupported
        );
    }

    /// 信封头的长度字段是 `u32`：超过 `u32::MAX` 的 payload 无法编码，
    /// 必须显式报错（而不是截断——截断会让解包侧读到越界密文）。
    #[test]
    fn oversized_payload_is_rejected_before_encoding() {
        assert_eq!(envelope_payload_len(0).unwrap(), 0);
        assert_eq!(envelope_payload_len(u32::MAX as usize).unwrap(), u32::MAX);
        let err = envelope_payload_len(u32::MAX as usize + 1).unwrap_err();
        assert!(
            matches!(&err, BiometricWrapError::Platform(msg) if msg.contains("exceeds envelope limit")),
            "unexpected error: {err:?}"
        );
    }

    /// 每个平台 tag 都能被 `parse_wrap_envelope` 认回（线格式 round-trip：
    /// 枚举值即 tag，`from_u8`/`as_u8` 不能漂移）。
    #[test]
    fn platform_tags_round_trip() {
        for (tag, expected) in [
            (0u8, WrapPlatform::Mock),
            (1, WrapPlatform::MacSecureEnclave),
            (2, WrapPlatform::WindowsTpm),
            (3, WrapPlatform::Linux),
        ] {
            assert_eq!(expected.as_u8(), tag);
            let mut envelope = vec![0u8; WRAP_HEADER_LEN + 4];
            envelope[..8].copy_from_slice(WRAP_MAGIC);
            envelope[8] = tag;
            envelope[41..45].copy_from_slice(&4u32.to_le_bytes());
            let (parsed, _, payload) = parse_wrap_envelope(&envelope).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(payload.len(), 4);
        }
    }

    /// Mock 后端的 `unwrap_payload` 自身也要挡长度不符的 payload（即便
    /// 信封头声称长度正确——平台后端是最后一道，不做假设）。
    #[test]
    fn mock_unwrap_rejects_wrong_length_payload() {
        let wrapper = MockKeyWrapper::default();
        assert_eq!(
            wrapper.unwrap_payload(&[0u8; 15], "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
        assert_eq!(
            wrapper.unwrap_payload(&[0u8; 17], "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    /// `delete_wrap_payload` 幂等：payload 形状不对时也不报错（禁用操作
    /// 必须永远能成功，形状不匹配只是"没有可删的东西"）。
    #[test]
    fn mock_delete_ignores_unparsable_payload() {
        let wrapper = MockKeyWrapper::default();
        assert!(wrapper.delete_wrap_payload(&[0u8; 3]).is_ok());
        assert!(wrapper.delete_wrap_payload(&[]).is_ok());
    }

    #[test]
    fn wrap_fails_when_unavailable() {
        let wrapper = MockKeyWrapper::default();
        wrapper.set_available(false);
        assert_eq!(
            wrap_master_key(&wrapper, &key(1), "enable").unwrap_err(),
            BiometricWrapError::NotAvailable
        );
        let envelope = {
            wrapper.set_available(true);
            wrap_master_key(&wrapper, &key(1), "enable").unwrap()
        };
        wrapper.set_available(false);
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::NotAvailable
        );
    }

    #[test]
    fn enrollment_rotation_invalidates_wrap() {
        let wrapper = MockKeyWrapper::default();
        let envelope = wrap_master_key(&wrapper, &key(2), "enable").unwrap();
        wrapper.rotate_enrollment();
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::EnrollmentChanged
        );
    }

    #[test]
    fn platform_tag_mismatch_is_wrap_invalid() {
        let wrapper = MockKeyWrapper::default();
        let mut envelope = wrap_master_key(&wrapper, &key(3), "enable").unwrap();
        envelope[8] = WrapPlatform::MacSecureEnclave as u8; // 冒充别的平台产出
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    #[test]
    fn corrupted_payload_is_wrap_invalid() {
        let wrapper = MockKeyWrapper::default();
        let mut envelope = wrap_master_key(&wrapper, &key(4), "enable").unwrap();
        wrapper.corrupt(&mut envelope);
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    #[test]
    fn user_cancellation_propagates_from_both_directions() {
        let wrapper = MockKeyWrapper::default();
        wrapper.set_user_cancelled(true);
        assert_eq!(
            wrap_master_key(&wrapper, &key(1), "enable").unwrap_err(),
            BiometricWrapError::UserCancelled
        );
        // 解包方向的取消：先关掉 enable 方向的取消注入，拿到合法信封
        wrapper.set_user_cancelled(false);
        let envelope = wrap_master_key(&wrapper, &key(1), "enable").unwrap();
        wrapper.set_user_cancelled(true);
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::UserCancelled
        );
    }

    #[test]
    fn injected_hardware_failures_propagate() {
        let wrapper = MockKeyWrapper::default();
        wrapper.set_fail(MockFailTarget::Wrap, true);
        assert_matches_platform(
            &wrap_master_key(&wrapper, &key(1), "enable"),
            "mock wrap failure",
        );

        wrapper.set_fail(MockFailTarget::Wrap, false);
        let envelope = wrap_master_key(&wrapper, &key(1), "enable").unwrap();

        wrapper.set_fail(MockFailTarget::Unwrap, true);
        assert_matches_platform(
            &unwrap_master_key(&wrapper, &envelope, "unlock"),
            "mock unwrap failure",
        );
        wrapper.set_fail(MockFailTarget::Unwrap, false);

        let (.., payload) = parse_wrap_envelope(&envelope).unwrap();
        wrapper.set_fail(MockFailTarget::Delete, true);
        assert_matches_platform(&wrapper.delete_wrap_payload(payload), "mock delete failure");
        wrapper.set_fail(MockFailTarget::Delete, false);
        assert!(wrapper.delete_wrap_payload(payload).is_ok());
        // 删除后再解包 → WrapInvalid
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    fn assert_matches_platform(
        result: &std::result::Result<impl std::fmt::Debug, BiometricWrapError>,
        needle: &str,
    ) {
        match result {
            Err(BiometricWrapError::Platform(msg)) => assert!(msg.contains(needle)),
            other => panic!("expected Platform error containing {needle}, got {other:?}"),
        }
    }

    #[test]
    fn error_display_and_persona_conversion() {
        // 每个变体都要有可读文案（错误直接进前端提示），且都映射成
        // AuthenticationFailed（服务层签名统一走 crate::Result）
        for (err, needle) in [
            (BiometricWrapError::Unsupported, "not supported"),
            (BiometricWrapError::NotAvailable, "not currently available"),
            (BiometricWrapError::UserCancelled, "cancelled"),
            (BiometricWrapError::EnrollmentChanged, "enrollment changed"),
            (BiometricWrapError::WrapInvalid, "invalid or corrupted"),
            (
                BiometricWrapError::Platform("os_status=-34018".into()),
                "os_status=-34018",
            ),
        ] {
            let text = err.to_string();
            assert!(
                text.contains(needle),
                "{err:?} should mention {needle:?}, got {text:?}"
            );
            let persona = err.to_persona_error();
            assert!(persona.to_string().contains("Authentication failed"));
        }
    }

    /// `assert_matches_platform` 这类断言助手自身也要被断言：给它一个
    /// 非 Platform 错误必须 panic 而不是悄悄放过。
    #[test]
    #[should_panic(expected = "expected Platform error")]
    fn assert_matches_platform_rejects_other_variants() {
        assert_matches_platform(&Err::<(), _>(BiometricWrapError::WrapInvalid), "boom");
    }
}
