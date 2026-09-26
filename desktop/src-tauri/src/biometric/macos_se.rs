//! macOS：Secure Enclave 路线 B'——永久 SE 密钥 + ECIES 包裹 vault 主密钥
//! （`docs/biometric-unlock-design.md` §5）。
//!
//! **spike 门控**：仅在环境变量 `PERSONA_BIOMETRIC_SE_SPIKE=1` 时由
//! [`super::key_wrapper`] 装配（`biometric_wrap_spike` 命令在真机上逐项
//! 探测并回报 OSStatus）。生产 unlock 主链路默认不含本模块——路线 B'
//! 是否被 ad-hoc 签名挡住（`errSecMissingEntitlement -34018`）只能真机
//! 验证，未验证前不切换默认行为。
//!
//! 机制：`SecKeyCreateRandomKey` 生成 256 位 EC 密钥（`kSecAttrTokenID
//! SecureEnclave` + `IsPermanent: true` + AccessControl
//! `.privateKeyUsage | .biometryCurrentSet`）。包裹 = 公钥 ECIES 加密
//! （无提示）；解包 = 私钥 ECIES 解密——SE 在此刻强制生物识别/系统密码，
//! 私钥永不导出。`biometryCurrentSet` 使换指纹后旧密钥永久失效。
//!
//! 算法族说明：objc2-security 0.3 暴露的 ECIES 常量只有 AESGCM 一族
//! （`...SHA256AESGCM`）；Apple 早年标注为 legacy 的 `...SHA256AEAD`
//! 在该 crate 里已不导出。取 AESGCM 变体：同样是 SE 硬件内的
//! ECDH + HKDF + AES-GCM，无自造密文。
//!
//! 验证状态：**编译**由 `desktop-build` 工作流的 macOS job（macos-latest
//! runner 上 `tauri build`）把关——本仓库无 macOS 实机，Linux 上无法
//! 编译 objc2 系 crate（`objc2` 显式拒绝非 Apple target，连
//! `cargo check` 都跑不过）；**运行时**行为以真机 spike 输出为准
//! （§5.2 的探针未跑过，结论待回填）。

// CF 基础类型走直接依赖 objc2-core-foundation（objc2-foundation 不在
// 根上重导出它们）。
use objc2_core_foundation::{CFBoolean, CFData, CFDictionary, CFRetained, CFType};
use objc2_security::{
    kSecAttrAccessControl, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAttrApplicationTag,
    kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, kSecReturnRef,
    SecAccessControl, SecAccessControlCreateFlags, SecItemCopyMatching, SecItemDelete, SecKey,
    SecKeyAlgorithm,
};
use std::ptr::NonNull;
use zeroize::Zeroizing;

use persona_core::{
    BiometricKeyWrapper, BiometricWrapCapability, BiometricWrapError, WrapPlatform,
};

/// SE 密钥的 application tag（keychain 内唯一标识本应用的包裹密钥）
const KEY_TAG: &[u8] = b"persona.vault-wrap.v1";

/// ECIES 算法：cofactor + 变长 IV + X9.63 KDF + SHA-256 + AES-GCM
/// （1Password/age 系的 SE 包裹同款算法族）
///
/// 本文件里所有 `unsafe { kSec… }` 静态读取的统一 SAFETY 前提：这些
/// extern static 是 Security.framework 导出的进程级常量（指向不可变
/// CFString 的引用），框架保证其有效性与永生——读取本身按 Rust 规则
/// 需 unsafe，值语义无风险。
fn ecies_algorithm() -> &'static SecKeyAlgorithm {
    unsafe { kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM }
}

pub fn spike_enabled() -> bool {
    std::env::var_os("PERSONA_BIOMETRIC_SE_SPIKE").is_some_and(|v| v == "1")
}

/// spike 门控的装配入口（`biometric::key_wrapper` 调用）
pub fn spike_wrapper_if_enabled() -> Option<SeKeyWrapper> {
    if spike_enabled() {
        Some(SeKeyWrapper)
    } else {
        None
    }
}

/// CFError 文案。`errSecMissingEntitlement (-34018)`、`errSecUserCanceled
/// (-25293)` 这些码从 CFError 的 code 读出（Security 框架把 OSStatus
/// 原样塞进 CFError code）——spike 报告与错误分流都依赖它。
fn cf_error_context(step: &str, err: *mut objc2_core_foundation::CFError) -> String {
    if err.is_null() {
        format!("{step}: failed with null CFError")
    } else {
        // SAFETY: 调用方保证 err 指向一个有效的 CFError
        let e = unsafe { &*err };
        format!("{step}: os_status={}", e.code())
    }
}

/// 用户在系统弹框点了取消（`errSecUserCanceled = -25293`）。仅取消走
/// 静默回退，其余失败一律当"包裹失效"（见设计文档 §3.4）。
const ERR_SEC_USER_CANCELED: i64 = -25293;
/// 条目不存在（`errSecItemNotFound`）：删除操作的幂等成功。
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

fn is_user_cancelled(context: &str) -> bool {
    context.contains(&ERR_SEC_USER_CANCELED.to_string())
}

/// AccessControl：私钥操作必须经生物识别（当前注册集）或系统密码回退
fn access_control() -> std::result::Result<CFRetained<SecAccessControl>, BiometricWrapError> {
    let mut err: *mut objc2_core_foundation::CFError = std::ptr::null_mut();
    // SAFETY: 框架常量静态（统一前提见 ecies_algorithm 文档）
    let protection: &CFType = unsafe { kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly };
    let flags = SecAccessControlCreateFlags::PrivateKeyUsage
        | SecAccessControlCreateFlags::BiometryCurrentSet;
    // SAFETY: 两个入参都是框架常量/位标志，out 错误指针由本函数持有
    let acl = unsafe { SecAccessControl::with_flags(None, protection, flags, &mut err) };
    acl.ok_or_else(|| BiometricWrapError::Platform(cf_error_context("access control create", err)))
}

/// 找已存在的包裹密钥；没有就 None
fn find_key() -> Option<CFRetained<SecKey>> {
    let tag = CFData::from_bytes(KEY_TAG);
    // SAFETY: 读框架常量静态构造查询字典（统一前提见 ecies_algorithm 文档）
    let query = unsafe {
        CFDictionary::<CFType, CFType>::from_slices(
            &[
                kSecClass.as_ref(),
                kSecAttrApplicationTag.as_ref(),
                kSecReturnRef.as_ref(),
            ],
            &[
                kSecClassKey.as_ref(),
                tag.as_ref(),
                CFBoolean::new(true).as_ref(),
            ],
        )
    };
    let mut found: *const CFType = std::ptr::null_mut();
    // SAFETY: query 是合法字典；found 由本函数持有并在 Ok 后转移所有权
    let status = unsafe { SecItemCopyMatching(query.as_opaque(), &mut found) };
    if status == 0 && !found.is_null() {
        // SAFETY: SecItemCopyMatching 成功时 found 是保留引用的 CFType
        // （kSecReturnRef → SecKeyRef），按 SecKey 转移所有权
        NonNull::new(found as *mut SecKey).map(|nn| unsafe { CFRetained::from_raw(nn) })
    } else {
        None
    }
}

/// 生成（或找回）Secure Enclave 包裹密钥
fn generate_or_find_key() -> std::result::Result<CFRetained<SecKey>, BiometricWrapError> {
    if let Some(key) = find_key() {
        return Ok(key);
    }
    let acl = access_control()?;
    let tag = CFData::from_bytes(KEY_TAG);
    let key_size = objc2_core_foundation::CFNumber::new_i32(256);
    // SAFETY: 读框架常量静态构造参数字典（统一前提见 ecies_algorithm 文档）
    let parameters = unsafe {
        CFDictionary::<CFType, CFType>::from_slices(
            &[
                kSecAttrKeyType.as_ref(),
                kSecAttrKeySizeInBits.as_ref(),
                kSecAttrTokenID.as_ref(),
                kSecAttrIsPermanent.as_ref(),
                kSecAttrAccessControl.as_ref(),
                kSecAttrApplicationTag.as_ref(),
            ],
            &[
                kSecAttrKeyTypeECSECPrimeRandom.as_ref(),
                key_size.as_ref(),
                kSecAttrTokenIDSecureEnclave.as_ref(),
                CFBoolean::new(true).as_ref(),
                acl.as_ref(),
                tag.as_ref(),
            ],
        )
    };
    let mut err: *mut objc2_core_foundation::CFError = std::ptr::null_mut();
    // SAFETY: parameters 合法；err 由本函数持有
    let key = unsafe { SecKey::new_random_key(parameters.as_opaque(), &mut err) };
    key.ok_or_else(|| {
        // ad-hoc 签名下预期可能 -34018：spike 就是为了抓这个码
        BiometricWrapError::Platform(cf_error_context("SecKeyCreateRandomKey (route B')", err))
    })
}

/// ECIES 包裹（走公钥，不弹框）
fn ecies_wrap(key: &SecKey, plaintext: &[u8]) -> std::result::Result<Vec<u8>, BiometricWrapError> {
    // SAFETY: key 是合法 SecKey；err 由本函数持有
    let public = unsafe { key.public_key() }
        .ok_or_else(|| BiometricWrapError::Platform("SecKeyCopyPublicKey returned None".into()))?;
    let data = CFData::from_bytes(plaintext);
    let mut err: *mut objc2_core_foundation::CFError = std::ptr::null_mut();
    // SAFETY: 公开的 ECIES 加密，无用户交互
    let ciphertext = unsafe { public.encrypted_data(ecies_algorithm(), &data, &mut err) };
    ciphertext
        .map(|d| d.to_vec())
        .ok_or_else(|| BiometricWrapError::Platform(cf_error_context("ECIES wrap", err)))
}

/// ECIES 解包（走私钥：SE 在此刻强制生物识别/系统密码）
fn ecies_unwrap(key: &SecKey, payload: &[u8]) -> std::result::Result<Vec<u8>, BiometricWrapError> {
    let ciphertext = CFData::from_bytes(payload);
    let mut err: *mut objc2_core_foundation::CFError = std::ptr::null_mut();
    // SAFETY: 私钥操作；Secure Enclave 在此刻强制用户认证（biometryCurrentSet）
    let plaintext = unsafe { key.decrypted_data(ecies_algorithm(), &ciphertext, &mut err) };
    let plaintext = match plaintext {
        Some(d) => d,
        None => {
            let detail = cf_error_context("ECIES unwrap", err);
            if is_user_cancelled(&detail) {
                return Err(BiometricWrapError::UserCancelled);
            }
            // 其余（含换指纹后密钥被 SE 永久作废）一律当包裹失效
            return Err(BiometricWrapError::Platform(detail));
        }
    };
    Ok(plaintext.to_vec())
}

/// spike 专用探针输出（`biometric_wrap_spike` 命令消费）：逐步骤的
/// OSStatus/结论，真机上跑完贴回设计文档 §5.2
pub struct SpikeStep {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// 跑 spike 全部探针（设计文档 §5.2 的探针 1/1b/2a/2b/3/4/5；"删一条指纹
/// 后解包"需要人在真机上操作生物注册，属手动对照：跑一次本函数、删一条
/// 指纹、再跑一次——第 2b 步必须失败才算 biometryCurrentSet 生效）。
/// 第 3 步的"重启后"维度同样靠连续两次运行本函数对比。
pub fn run_spike() -> Vec<SpikeStep> {
    let mut steps = Vec::new();

    // 1. B' 密钥生成（access control + 永久 SE）
    let key = match generate_or_find_key() {
        Ok(_) => {
            steps.push(SpikeStep {
                name: "1. SecKeyCreateRandomKey (SE, permanent, biometryCurrentSet)",
                ok: true,
                detail: "created or found".into(),
            });
            match find_key() {
                Some(key) => key,
                None => {
                    steps.push(SpikeStep {
                        name: "1b. find_key after create",
                        ok: false,
                        detail: "key not found right after creation".into(),
                    });
                    return steps;
                }
            }
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "1. SecKeyCreateRandomKey (SE, permanent, biometryCurrentSet)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };

    // 2. ECIES roundtrip（wrap 侧无提示，unwrap 侧会弹生物识别）
    let probe = b"persona-spike-probe";
    let ciphertext = match ecies_wrap(&key, probe) {
        Ok(c) => {
            steps.push(SpikeStep {
                name: "2a. SecKeyCreateEncryptedData (ECIES, public key)",
                ok: true,
                detail: format!("{} bytes", c.len()),
            });
            c
        }
        Err(e) => {
            steps.push(SpikeStep {
                name: "2a. SecKeyCreateEncryptedData (ECIES, public key)",
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    };
    match ecies_unwrap(&key, &ciphertext) {
        Ok(plain) => {
            let ok = plain == probe;
            steps.push(SpikeStep {
                name: "2b. SecKeyCreateDecryptedData (prompts biometry)",
                ok,
                detail: if ok {
                    "roundtrip ok".into()
                } else {
                    "content mismatch".into()
                },
            });
        }
        Err(e) => steps.push(SpikeStep {
            name: "2b. SecKeyCreateDecryptedData (prompts biometry)",
            ok: false,
            detail: e.to_string(),
        }),
    }

    // 3. 持久性：本次进程能找回既有密钥（find_key 命中 = keychain 引用存活；
    //    完整的"重启后"验证 = 结束本进程后再次运行 spike，看本步是否 still found）
    steps.push(SpikeStep {
        name: "3. find_key (persistence probe)",
        ok: find_key().is_some(),
        detail: "run this spike again after restarting the app to prove cross-restart persistence"
            .into(),
    });

    // 5. 对照组 A（设计文档 §5.2 第 5 项）：DP keychain + AccessControl
    //    在 ad-hoc 签名下预期 -34018——确认签名坑基线真实存在
    steps.push(access_control_probe());

    // 6. 删除路径（禁用 / 失效自愈都走它；幂等）
    let delete_status = match delete_se_key() {
        Ok(()) => String::new(),
        Err(e) => e.to_string(),
    };
    steps.push(SpikeStep {
        name: "5. SecItemDelete (wrap key, idempotent)",
        ok: delete_status.is_empty(),
        detail: if delete_status.is_empty() {
            "deleted".into()
        } else {
            delete_status
        },
    });

    steps
}

/// 对照组 A 探针：仅构造 AccessControl（不建 keychain 条目也足以观察
/// 签名门限——`SecAccessControlCreateWithFlags` 本身不吃 entitlement，
/// 真正的 -34018 出现在带 ACL 的 SecItemAdd/SecKeyCreateRandomKey；
/// 本步记录构造是否成功，主判断仍看第 1 步的真实 OSStatus）。
fn access_control_probe() -> SpikeStep {
    match access_control() {
        Ok(_) => SpikeStep {
            name: "4. access control create (baseline, no keychain write)",
            ok: true,
            detail: "SecAccessControl created; -34018 (if any) surfaces at key creation (step 1)"
                .into(),
        },
        Err(e) => SpikeStep {
            name: "4. access control create (baseline, no keychain write)",
            ok: false,
            detail: e.to_string(),
        },
    }
}

/// 删除 keychain 里的 SE 包裹密钥（幂等：不存在也算成功）
fn delete_se_key() -> std::result::Result<(), BiometricWrapError> {
    let tag = CFData::from_bytes(KEY_TAG);
    // SAFETY: 读框架常量静态构造查询字典（统一前提见 ecies_algorithm 文档）
    let query = unsafe {
        CFDictionary::<CFType, CFType>::from_slices(
            &[kSecClass.as_ref(), kSecAttrApplicationTag.as_ref()],
            &[kSecClassKey.as_ref(), tag.as_ref()],
        )
    };
    // SAFETY: query 合法
    let status = unsafe { SecItemDelete(query.as_opaque()) };
    if status == 0 || status == ERR_SEC_ITEM_NOT_FOUND {
        Ok(())
    } else {
        Err(BiometricWrapError::Platform(format!(
            "SecItemDelete os_status={status}"
        )))
    }
}

/// Secure Enclave 路线 B' 的硬件包裹器
pub struct SeKeyWrapper;

impl BiometricKeyWrapper for SeKeyWrapper {
    fn capability(&self) -> BiometricWrapCapability {
        BiometricWrapCapability::HardwareBound
    }

    fn is_available(&self) -> bool {
        // 硬件存在 + 生物注册在册才可用（复用门禁层的 LAContext 探测）
        super::macos::available()
    }

    fn platform(&self) -> WrapPlatform {
        WrapPlatform::MacSecureEnclave
    }

    fn enrollment_fingerprint(&self) -> std::result::Result<[u8; 32], BiometricWrapError> {
        // SE 密钥的 AccessControl 带 .biometryCurrentSet：注册集漂移由
        // 硬件强制失效（解包必失败）。core 的指纹比对是第二道防线，这里
        // 返回固定占位——不伪造注册集状态（Apple 不暴露，拿了也拿不准）。
        Ok([0u8; 32])
    }

    fn wrap_payload(
        &self,
        master_key: &[u8; 32],
        _prompt: &str,
    ) -> std::result::Result<Vec<u8>, BiometricWrapError> {
        let key = generate_or_find_key()?;
        ecies_wrap(&key, master_key)
    }

    fn unwrap_payload(
        &self,
        payload: &[u8],
        prompt: &str,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
        let _ = prompt; // SE 弹框文案由 AccessControl 的 prompt 机制管，Rust 侧仅审计
        let key = generate_or_find_key()?;
        let bytes = ecies_unwrap(&key, payload)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| BiometricWrapError::WrapInvalid)?;
        Ok(Zeroizing::new(arr))
    }

    fn delete_wrap_payload(&self, _payload: &[u8]) -> std::result::Result<(), BiometricWrapError> {
        delete_se_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真机/CI 探针入口：`cargo test --lib spike_probes_print_report
    /// -- --ignored --nocapture`。探针结果本身就是数据（GitHub runner 是
    /// VM，无 Secure Enclave / Touch ID，各步会如实失败并把 OSStatus 打进
    /// 日志——这正是 desktop-build macos job 跑它的目的：把真实输出回填
    /// 设计文档 §5.2），断言只保证"能出报告"，不对 ok 位做门禁——门禁
    /// 语义在 spike 输出的人工判读，不在测试。
    #[test]
    #[ignore = "需要真实 macOS 环境（Secure Enclave / Touch ID）；desktop-build macos job 按计划跑"]
    fn spike_probes_print_report() {
        let steps = run_spike();
        assert!(!steps.is_empty(), "spike 必须产出探针报告");
        for s in steps {
            println!(
                "SPIKE [{}] {} — {}",
                if s.ok { "PASS" } else { "FAIL" },
                s.name,
                s.detail
            );
        }
    }
}
