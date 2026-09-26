//! Windows：Microsoft Passport Key Storage Provider（TPM 硬件包裹）——
//! `docs/biometric-unlock-design.md` §6 首选路线。
//!
//! **spike 门控**：仅在环境变量 `PERSONA_BIOMETRIC_TPM_SPIKE=1` 时由
//! [`super::key_wrapper`] 装配（`biometric_tpm_spike` 命令在真机上逐项
//! 探测并回报 HRESULT）。生产 unlock 主链路默认不含本模块——Passport KSP
//! 的实际行为（UI policy 是否真在每次私钥使用时弹 Hello、finalize 静默
//! 语义、删指纹后的表现）只能真机验证，未验证前不切换默认行为。
//!
//! 机制：NCrypt 打开 `MS_KEY_STORAGE_PROVIDER`（Passport KSP，密钥私钥
//! 由 TPM 保护、不可导出），在其下建一把 2048 位 RSA 用户密钥，三个属性
//! 钉死：
//! - `NCRYPT_KEY_USAGE_PROPERTY = NCRYPT_ALLOW_DECRYPT_FLAG`——只开私钥的
//!   「解密」方向（即包裹/解包裹），不授予签名权；
//! - `NCRYPT_UI_POLICY_PROPERTY = NCRYPT_UI_PROTECT_KEY_FLAG`，**带
//!   `NCRYPT_PERSIST_FLAG` 落盘**——私钥每次使用都须经 Windows Hello 用户
//!   验证才由 TPM 放行。不持久化的话该 policy 只在本进程有效，重启后
//!   解包裹不再弹 Hello（静默的安全降级，必须钉住）；
//! - `NCRYPT_LENGTH_PROPERTY = 2048`。
//!
//! 包裹 = `NCryptEncrypt`（RSA 公钥方向，**无提示**）；解包裹 =
//! `NCryptDecrypt`（私钥方向，**Hello 在此刻弹**）。与 macOS 路线 B'
//! 同属设计文档 §1 的 `HardwareBound` 档：秘密真值在硬件私钥里，keyring
//! 里只剩打不开的密文。
//!
//! ## 与 macOS B' 的能力差（诚实边界，勿在文档里含糊）
//!
//! **注册集漂移（T2）在 Windows 侧拿不到平台级强制**：Apple 的
//! `biometryCurrentSet` 会在换指纹后让旧 SE 密钥永久失效；Windows 没有
//! 对应 API——`NCRYPT_UI_PROTECT_KEY_FLAG` 强制的是「每次使用都要用户
//! 验证」，验证者换成一个新指纹**不会**让旧密钥失效。因此
//! [`TpmKeyWrapper::enrollment_fingerprint`] 只能返回固定占位（与 macOS
//! 的占位同形，但 macOS 是「平台已强制、这里只是第二道防线」，Windows
//! 是「平台压根不管、这里也没有第二道」）。
//!
//! 残余风险：拿到本机登录态的攻击者若能完成一次 Windows Hello 验证
//! （已注册过任一指纹/PIN），就能解开旧包裹——换指纹这个「反胁迫」性质
//! 在 Windows 上不成立。缓解是主密码兜底 + 包裹 blob 本身在 keyring 里
//! 只是密文（同用户进程读走也打不开，除非它能让 Hello 通过）。
//!
//! ## 验证状态
//!
//! **编译**由 Linux 交叉 check 把关（`x86_64-pc-windows-msvc` + 空
//! `CC`/`llvm-ar` 桩，见设计文档 §5.3 同款手法）与 `desktop-build` 的
//! Windows job；**运行时**行为以真机 spike 输出为准（§6.1 探针未跑过，
//! 结论待回填）。本仓库无 Windows 实机。

use windows::core::{w, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    ERROR_NOT_FOUND, NTE_BAD_KEYSET, NTE_USER_CANCELLED, SCARD_W_CANCELLED_BY_USER,
};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
    NCryptFreeObject, NCryptIsAlgSupported, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, CERT_KEY_SPEC, MS_KEY_STORAGE_PROVIDER, NCRYPT_ALLOW_DECRYPT_FLAG,
    NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY,
    NCRYPT_LENGTH_PROPERTY, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PERSIST_FLAG,
    NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, NCRYPT_SILENT_FLAG, NCRYPT_UI_POLICY_PROPERTY,
    NCRYPT_UI_PROTECT_KEY_FLAG,
};
use zeroize::Zeroizing;

use persona_core::{
    BiometricKeyWrapper, BiometricWrapCapability, BiometricWrapError, WrapPlatform,
};

/// KSP 内的密钥名（用户级；同名密钥在本机用户档案下唯一）
const KEY_NAME: PCWSTR = w!("persona.vault-wrap.v1");

/// 2048 位 RSA + PKCS#1 v1.5：明文上限 245 字节，vault 主密钥 32 字节
/// 远在其下；不升到 3072/4096 是为了 TPM 侧延迟（解包裹是用户可感知路径）
const KEY_BITS: u32 = 2048;

/// NCrypt 句柄的 RAII 包装（provider 与 key 两种句柄共用同一释放函数）
struct OwnedHandle(NCRYPT_HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // drop 里无处上抛：释放失败只能放弃（句柄表泄漏一个条目，与进程
        // 生命周期同长，可接受）；不 panic——析构路径 panic 会变 abort
        // SAFETY: 句柄来自成功的 NCrypt 调用，本 RAII 恰好释放一次
        let _ = unsafe { NCryptFreeObject(self.0) };
    }
}

/// NCrypt 错误 → 包裹层错误。用户在 Hello 弹框点取消走 `UserCancelled`
/// （静默回解锁屏），其余一律 `Platform` 原文带 HRESULT（宿主据此自动
/// 删 blob 回主密码，见设计文档 §3.4）。
fn map_ncrypt_err(err: windows::core::Error, step: &str) -> BiometricWrapError {
    let code = err.code();
    // Passport KSP 走 WinRT 层时取消是 NTE_USER_CANCELLED，走 smart-card 层
    // 时是 SCARD_W_CANCELLED_BY_USER——两个都收
    if code == NTE_USER_CANCELLED || code == SCARD_W_CANCELLED_BY_USER {
        return BiometricWrapError::UserCancelled;
    }
    BiometricWrapError::Platform(format!(
        "{step}: hr=0x{:08x} {}",
        code.0 as u32,
        err.message()
    ))
}

/// 打开 Passport KSP
fn open_provider() -> Result<OwnedHandle, BiometricWrapError> {
    let mut provider = NCRYPT_PROV_HANDLE(0);
    // SAFETY: out 指针由本函数持有；provider 名是框架常量
    unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) }
        .map_err(|e| map_ncrypt_err(e, "NCryptOpenStorageProvider (MSKSP)"))?;
    Ok(OwnedHandle(NCRYPT_HANDLE(provider.0)))
}

/// KSP 是否支持 RSA 私钥解密方向（包裹层唯一需要的算法能力）
fn provider_supports_rsa(provider: &OwnedHandle) -> bool {
    // NCryptIsAlgSupported 以失败码表达「不支持」，这里只要布尔
    // SAFETY: provider 句柄有效；算法标识是框架常量
    unsafe {
        NCryptIsAlgSupported(
            NCRYPT_PROV_HANDLE(provider.0 .0),
            NCRYPT_RSA_ALGORITHM,
            NCRYPT_ALLOW_DECRYPT_FLAG,
        )
    }
    .is_ok()
}

/// 「密钥不存在」的两种 HRESULT：MSKSP 通常回 `NTE_BAD_KEYSET`，部分系统
/// 版本/后端回 `ERROR_NOT_FOUND`(1168)。两者都是「没有」而非「坏了」——
/// 只有这两种才允许自动重建密钥，其余错误一律上抛（不掩盖真实故障）。
fn is_key_absent(code: HRESULT) -> bool {
    code == NTE_BAD_KEYSET || code == HRESULT::from_win32(ERROR_NOT_FOUND.0)
}

/// 打开已存在的包裹密钥；不存在返回 `Ok(None)`
fn open_key(provider: &OwnedHandle) -> Result<Option<OwnedHandle>, BiometricWrapError> {
    let mut key = NCRYPT_KEY_HANDLE(0);
    // SAFETY: provider 句柄有效；out 指针由本函数持有；密钥名是常量
    match unsafe {
        NCryptOpenKey(
            NCRYPT_PROV_HANDLE(provider.0 .0),
            &mut key,
            KEY_NAME,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    } {
        Ok(()) => Ok(Some(OwnedHandle(NCRYPT_HANDLE(key.0)))),
        Err(e) if is_key_absent(e.code()) => Ok(None),
        Err(e) => Err(map_ncrypt_err(e, "NCryptOpenKey")),
    }
}

fn set_u32_property(
    key: &OwnedHandle,
    name: PCWSTR,
    value: u32,
    flags: NCRYPT_FLAGS,
) -> Result<(), BiometricWrapError> {
    // SAFETY: 句柄有效；value 是本函数栈上的 4 字节，NCryptSetProperty
    // 同步读取不保存指针
    unsafe { NCryptSetProperty(NCRYPT_HANDLE(key.0 .0), name, &value.to_ne_bytes(), flags) }
        .map_err(|e| map_ncrypt_err(e, "NCryptSetProperty"))
}

/// 建包裹密钥：RSA-2048 / 仅解密用途 / 每次使用须 Hello（policy 持久化）
///
/// `NCRYPT_OVERWRITE_KEY_FLAG`：重建时覆盖同名残留（用户清过 Passport
/// 密钥、或上次 enable 在 finalize 前失败留下的半态），避免重建永久卡在
/// 「打开得到一个坏密钥」。
fn create_key(provider: &OwnedHandle) -> Result<OwnedHandle, BiometricWrapError> {
    let mut key = NCRYPT_KEY_HANDLE(0);
    // SAFETY: provider 句柄有效；out 指针由本函数持有；算法名/密钥名是常量
    unsafe {
        NCryptCreatePersistedKey(
            NCRYPT_PROV_HANDLE(provider.0 .0),
            &mut key,
            NCRYPT_RSA_ALGORITHM,
            KEY_NAME,
            CERT_KEY_SPEC(0),
            NCRYPT_OVERWRITE_KEY_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptCreatePersistedKey"))?;
    let key = OwnedHandle(NCRYPT_HANDLE(key.0));

    set_u32_property(&key, NCRYPT_LENGTH_PROPERTY, KEY_BITS, NCRYPT_FLAGS(0))?;
    set_u32_property(
        &key,
        NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_ALLOW_DECRYPT_FLAG,
        NCRYPT_FLAGS(0),
    )?;
    // policy 必须带 NCRYPT_PERSIST_FLAG 才随密钥落盘（见模块头）
    set_u32_property(
        &key,
        NCRYPT_UI_POLICY_PROPERTY,
        NCRYPT_UI_PROTECT_KEY_FLAG,
        NCRYPT_PERSIST_FLAG,
    )?;

    // 静默 finalize：enable 路径上一步（commands.rs 的 biometric_enable
    // 第 2 步）已经走过 Hello ceremony，建钥过程不再弹第二次框
    // SAFETY: 句柄有效；finalize 后句柄仍然合法
    unsafe { NCryptFinalizeKey(NCRYPT_KEY_HANDLE(key.0 .0), NCRYPT_SILENT_FLAG) }
        .map_err(|e| map_ncrypt_err(e, "NCryptFinalizeKey"))?;
    Ok(key)
}

/// 找到或建出包裹密钥（仅 enable/包裹路径用——解包裹走 open_key_only）
fn generate_or_find_key() -> Result<OwnedHandle, BiometricWrapError> {
    let provider = open_provider()?;
    if let Some(key) = open_key(&provider)? {
        return Ok(key);
    }
    create_key(&provider)
}

/// 解包裹路径专用：**只**打开，不存在即 `WrapInvalid`。
///
/// 与 macOS B' 的差异是刻意的：那边解包裹也走 generate_or_find，密钥
/// 不存在时会先建一把新密钥再在 ECIES 上失败——留下一个没人用的孤儿
/// 密钥，还把「blob 来自别的机器 / 用户清过 Passport 密钥」这个真实
/// 故障伪装成一次解密错误。宿主对 `WrapInvalid` 的处置是删 blob 回主密码
/// （设计文档 §3.4），语义正好。
fn open_key_only() -> Result<OwnedHandle, BiometricWrapError> {
    let provider = open_provider()?;
    open_key(&provider)?.ok_or(BiometricWrapError::WrapInvalid)
}

/// RSA 公钥方向包裹（无用户交互）
fn rsa_wrap(key: &OwnedHandle, plaintext: &[u8]) -> Result<Vec<u8>, BiometricWrapError> {
    let mut len = 0u32;
    // SAFETY: 句柄有效；定长查询按 NCrypt 约定传 pboutput=None 拿长度
    unsafe {
        NCryptEncrypt(
            NCRYPT_KEY_HANDLE(key.0 .0),
            Some(plaintext),
            None,
            None,
            &mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptEncrypt (size)"))?;
    let mut out = vec![0u8; len as usize];
    // SAFETY: out 恰好是上一步报告的长度
    unsafe {
        NCryptEncrypt(
            NCRYPT_KEY_HANDLE(key.0 .0),
            Some(plaintext),
            None,
            Some(&mut out),
            &mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptEncrypt"))?;
    out.truncate(len as usize);
    Ok(out)
}

/// RSA 私钥方向解包裹（Windows Hello 在此刻由 TPM/KSP 弹出）
fn rsa_unwrap(key: &OwnedHandle, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, BiometricWrapError> {
    let mut len = 0u32;
    // SAFETY: 句柄有效；定长查询传 pboutput=None
    unsafe {
        NCryptDecrypt(
            NCRYPT_KEY_HANDLE(key.0 .0),
            Some(payload),
            None,
            None,
            &mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptDecrypt (size)"))?;
    // 明文缓冲区全程 Zeroizing：解出的就是 vault 主密钥
    let mut plain = Zeroizing::new(vec![0u8; len as usize]);
    // SAFETY: 缓冲区恰好是上一步报告的长度
    unsafe {
        NCryptDecrypt(
            NCRYPT_KEY_HANDLE(key.0 .0),
            Some(payload),
            None,
            Some(plain.as_mut_slice()),
            &mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|e| map_ncrypt_err(e, "NCryptDecrypt"))?;
    plain.truncate(len as usize);
    Ok(plain)
}

/// 删除 KSP 里的包裹密钥（幂等：不存在也算成功）
fn delete_tpm_key() -> Result<(), BiometricWrapError> {
    let provider = open_provider()?;
    match open_key(&provider)? {
        Some(key) => {
            let handle = NCRYPT_KEY_HANDLE(key.0 .0);
            // SAFETY: 句柄来自 NCryptOpenKey
            let result = unsafe { NCryptDeleteKey(handle, 0) }
                .map_err(|e| map_ncrypt_err(e, "NCryptDeleteKey"));
            // `NCryptDeleteKey` 自己会处置句柄（成功后必然已释放，失败时
            // MSDN 未承诺句柄是否仍归调用方所有）。这里**一律**放弃 RAII
            // 释放权：猜错方向的代价是不对称的——多释放一次是 UB（句柄表
            // 损坏，可能变成对别处的 wild pointer），少释放一次只是泄漏一
            // 个句柄，且只发生在删除失败这条本就要上抛的路径上。
            std::mem::forget(key);
            result
        }
        None => Ok(()),
    }
}

pub fn spike_enabled() -> bool {
    std::env::var_os("PERSONA_BIOMETRIC_TPM_SPIKE").is_some_and(|v| v == "1")
}

/// spike 门控的装配入口（`biometric::key_wrapper` 调用）
pub fn spike_wrapper_if_enabled() -> Option<TpmKeyWrapper> {
    if spike_enabled() {
        Some(TpmKeyWrapper)
    } else {
        None
    }
}

/// Windows Hello availability（门禁层探测；包裹层的用户验证实际由 KSP
/// 自己做，这里只做「本机装了 Hello」的前置判断）
fn hello_available() -> bool {
    super::windows_hello::available()
}

/// Microsoft Passport KSP 的硬件包裹器
pub struct TpmKeyWrapper;

impl BiometricKeyWrapper for TpmKeyWrapper {
    fn capability(&self) -> BiometricWrapCapability {
        BiometricWrapCapability::HardwareBound
    }

    fn is_available(&self) -> bool {
        // 三者缺一即不可用（fail-closed）：KSP 打不开、算法不支持、
        // 本机没有可用的 Windows Hello
        match open_provider() {
            Ok(provider) => provider_supports_rsa(&provider) && hello_available(),
            Err(_) => false,
        }
    }

    fn platform(&self) -> WrapPlatform {
        WrapPlatform::WindowsTpm
    }

    fn enrollment_fingerprint(&self) -> Result<[u8; 32], BiometricWrapError> {
        // 平台层没有「生物注册集指纹」这回事（见模块头「与 macOS B' 的
        // 能力差」）：换指纹不会让旧包裹失效，core 的第二道比对在这里
        // 只能是占位。返回全零——不伪造注册集状态，宁可让这一道失效也
        // 不谎报一个会随环境漂移的值。
        Ok([0u8; 32])
    }

    fn wrap_payload(
        &self,
        master_key: &[u8; 32],
        _prompt: &str,
    ) -> Result<Vec<u8>, BiometricWrapError> {
        let key = generate_or_find_key()?;
        rsa_wrap(&key, master_key)
    }

    fn unwrap_payload(
        &self,
        payload: &[u8],
        prompt: &str,
    ) -> Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
        // 弹框文案由 KSP 的 UI policy 机制管（NCrypt 层不接受调用方文案），
        // Rust 侧仅审计
        let _ = prompt;
        let key = open_key_only()?;
        let plain = rsa_unwrap(&key, payload)?;
        let arr: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| BiometricWrapError::WrapInvalid)?;
        Ok(Zeroizing::new(arr))
    }

    fn delete_wrap_payload(&self, _payload: &[u8]) -> Result<(), BiometricWrapError> {
        delete_tpm_key()
    }
}

// ---------------------------------------------------------------------------
// spike 探针（`biometric_tpm_spike` 命令消费）
// ---------------------------------------------------------------------------

/// spike 专用探针输出：逐步骤的 HRESULT/结论，真机上跑完贴回设计文档 §6.1
pub struct SpikeStep {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// 跑 spike 全部探针（对应设计文档 §6.1 的表）。
///
/// 「删一条指纹后解包裹」与「重启后再跑一次看密钥还在不在」是两个**手动**
/// 对照：本函数跑完做掉操作再跑一次，探针 5b 必须失败、探针 6 必须 still
/// found 才算通过。
pub fn run_spike() -> Vec<SpikeStep> {
    let mut steps = Vec::new();

    // 1. KSP 能否打开
    let provider = match open_provider() {
        Ok(p) => {
            steps.push(SpikeStep {
                name: "1. NCryptOpenStorageProvider (Microsoft Passport KSP)",
                ok: true,
                detail: "provider opened".into(),
            });
            p
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "1. NCryptOpenStorageProvider (Microsoft Passport KSP)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };

    // 2. 算法能力
    let rsa_ok = provider_supports_rsa(&provider);
    steps.push(SpikeStep {
        name: "2. NCryptIsAlgSupported (RSA, NCRYPT_ALLOW_DECRYPT_FLAG)",
        ok: rsa_ok,
        detail: if rsa_ok {
            "RSA decrypt supported".into()
        } else {
            "provider cannot do RSA private-key decrypt".to_string()
        },
    });
    if !rsa_ok {
        return steps;
    }

    // 3. Windows Hello 前置条件
    let hello = hello_available();
    steps.push(SpikeStep {
        name: "3. Windows Hello availability (UserConsentVerifier)",
        ok: hello,
        detail: if hello {
            "hello available".into()
        } else {
            "UserConsentVerifier reports unavailable — no enrolled PIN/fingerprint?".to_string()
        },
    });

    // 4. 建钥（含 UI policy 持久化）+ 建后可查
    let key = match generate_or_find_key() {
        Ok(k) => {
            steps.push(SpikeStep {
                name: "4. NCryptCreatePersistedKey (RSA-2048, UI policy persisted)",
                ok: true,
                detail: "created or found".into(),
            });
            k
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "4. NCryptCreatePersistedKey (RSA-2048, UI policy persisted)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };
    steps.push(match open_key(&provider) {
        Ok(Some(_)) => SpikeStep {
            name: "4b. NCryptOpenKey after create",
            ok: true,
            detail: "key found right after creation".into(),
        },
        Ok(None) => SpikeStep {
            name: "4b. NCryptOpenKey after create",
            ok: false,
            detail: "key not found right after creation".into(),
        },
        Err(e) => SpikeStep {
            name: "4b. NCryptOpenKey after create",
            ok: false,
            detail: e.to_string(),
        },
    });

    // 5. roundtrip：包裹（公钥方向，应无提示）→ 解包裹（私钥方向，应弹 Hello）
    let probe = b"persona-spike-probe";
    let ciphertext = match rsa_wrap(&key, probe) {
        Ok(c) => {
            steps.push(SpikeStep {
                name: "5a. NCryptEncrypt (public key, must not prompt)",
                ok: true,
                detail: format!("{} bytes", c.len()),
            });
            c
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "5a. NCryptEncrypt (public key, must not prompt)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };
    steps.push(match rsa_unwrap(&key, &ciphertext) {
        Ok(plain) => {
            let ok = plain.as_slice() == probe;
            SpikeStep {
                name: "5b. NCryptDecrypt (must prompt Windows Hello)",
                ok,
                detail: if ok {
                    "roundtrip ok — confirm the Hello prompt actually appeared".into()
                } else {
                    "content mismatch".into()
                },
            }
        }
        Err(e) => SpikeStep {
            name: "5b. NCryptDecrypt (must prompt Windows Hello)",
            ok: false,
            detail: e.to_string(),
        },
    });

    // 6. 持久性：本进程能重开既有密钥；完整的「重启后」验证 = 结束本进程
    //    后再跑一次 spike，本步仍 found
    steps.push(match open_key(&provider) {
        Ok(Some(_)) => SpikeStep {
            name: "6. NCryptOpenKey (persistence probe)",
            ok: true,
            detail:
                "run this spike again after restarting the app to prove cross-restart persistence"
                    .into(),
        },
        Ok(None) => SpikeStep {
            name: "6. NCryptOpenKey (persistence probe)",
            ok: false,
            detail: "key disappeared within the same process".into(),
        },
        Err(e) => SpikeStep {
            name: "6. NCryptOpenKey (persistence probe)",
            ok: false,
            detail: e.to_string(),
        },
    });

    // 7. 删除幂等：连删两次都必须成功（禁用/失效自愈共用这条路径）
    let first = delete_tpm_key();
    let second = delete_tpm_key();
    let ok = first.is_ok() && second.is_ok();
    steps.push(SpikeStep {
        name: "7. NCryptDeleteKey (idempotent, called twice)",
        ok,
        detail: if ok {
            "deleted; second delete returned Ok (not-found is success)".into()
        } else {
            format!(
                "first={:?} second={:?}",
                first.err().map(|e| e.to_string()),
                second.err().map(|e| e.to_string())
            )
        },
    });

    steps
}
